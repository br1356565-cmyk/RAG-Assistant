"""Human-in-the-loop API, routed from the chat function (all under /api/, all need sign-in).

  GET  reviews               what is waiting for a person in your teams: low-confidence or
                             disputed investigations, proposed team notes, fixes to approve
  POST reviews/investigation {investigation_id, decision: approved|rejected, note?, fix_override?}
  POST reviews/note          {note_id, decision: active|rejected}
  POST findings/dispute      {finding_id, note}                 any team member
  POST feedback              {session_id, job_id?, rating: 1|-1, comment?, answer?}
  GET  fixes                 recent fix requests in your teams
  POST fixes/request         {finding_id}                       any team member
  POST fixes/decide          {fix_request_id, decision: approved|rejected}

Who may decide is enforced by row-level security policies (leads and admins only), not by
this code; a refused write comes back as 403.
"""
from __future__ import annotations

import json
import logging
import re

import psycopg

from ..db import Scope
from ..tools.base import ToolError, parse_ref, ref

log = logging.getLogger(__name__)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DECIDERS = ("team_lead", "security_admin")


def _can_decide(scope: Scope) -> bool:
    return scope.role in DECIDERS


def reviews(deps, scope: Scope, body: dict):
    with deps.db.scoped(scope) as conn:
        latest = conn.execute(
            "select distinct on (i.fingerprint) i.id, i.fingerprint, i.team_id, i.explanation, i.confidence, "
            "i.created_at, review_state(i.id, i.needs_review) as state, f.title, f.resource, f.severity "
            "from investigations i join findings f on f.fingerprint = i.fingerprint "
            "where f.status = 'open' order by i.fingerprint, i.created_at desc, i.id desc").fetchall()
        notes = conn.execute(
            "select id, team_id, kind, text, fingerprint, expires_at, author, created_at from team_notes "
            "where status = 'proposed' order by created_at").fetchall()
        fixes = conn.execute(
            "select id, fingerprint, team_id, repo, manifest_path, diff, rationale, requested_by, created_at "
            "from fix_requests where status = 'awaiting_approval' order by created_at").fetchall()
    waiting = [r for r in latest if r["state"] in ("pending", "disputed")]
    return 200, {
        "can_decide": _can_decide(scope),
        "investigations": [{
            "investigation_id": r["id"], "finding": ref(r["fingerprint"]), "team": r["team_id"], "state": r["state"],
            "title": r["title"], "resource": r["resource"], "severity": r["severity"],
            "confidence": r["confidence"], "summary": (r["explanation"] or {}).get("summary"),
            "fix": ((r["explanation"] or {}).get("fix") or {}).get("action"),
            "impact": ((r["explanation"] or {}).get("impact") or {}).get("verdict")} for r in waiting],
        "notes": [{"note_id": str(n["id"]), "team": n["team_id"], "kind": n["kind"], "text": n["text"],
                   "finding": ref(n["fingerprint"]) if n["fingerprint"] else None,
                   "expires": n["expires_at"].isoformat() if n["expires_at"] else None,
                   "author": n["author"]} for n in notes],
        "fixes": [{"fix_request_id": str(x["id"]), "finding": ref(x["fingerprint"]), "team": x["team_id"],
                   "repo": x["repo"], "manifest": x["manifest_path"], "diff": x["diff"], "rationale": x["rationale"],
                   "requested_by": x["requested_by"]} for x in fixes],
    }


def decide_investigation(deps, scope: Scope, body: dict):
    decision = body.get("decision")
    if decision not in ("approved", "rejected"):
        return 400, {"error": "decision must be approved or rejected"}
    try:
        inv_id = int(body.get("investigation_id"))
    except (TypeError, ValueError):
        return 400, {"error": "investigation_id must be a number"}
    note = (str(body["note"])[:1000] if body.get("note") else None)
    override = (str(body["fix_override"])[:300] if body.get("fix_override") else None)
    try:
        with deps.db.scoped(scope) as conn:
            inv = conn.execute("select id, team_id, run_id, needs_review, review_state(id, needs_review) as state "
                               "from investigations where id = %s", (inv_id,)).fetchone()
            if not inv:
                return 404, {"error": "investigation not found"}
            conn.execute("insert into investigation_reviews (investigation_id, team_id, decision, reviewer, note, "
                         "fix_override) values (%s, %s, %s, %s, %s, %s)",
                         (inv_id, inv["team_id"], decision, scope.user_id, note, override))
            gate = None
            if inv["state"] == "pending" and inv["run_id"]:
                gate = conn.execute("update review_gates set pending = pending - 1 where run_id = %s and "
                                    "resolved_at is null returning pending, task_token", (inv["run_id"],)).fetchone()
                if gate and gate["pending"] <= 0:
                    conn.execute("update review_gates set resolved_at = now() where run_id = %s", (inv["run_id"],))
    except psycopg.errors.InsufficientPrivilege:
        return 403, {"error": "only a team lead or admin can approve or reject"}
    if gate and gate["pending"] <= 0 and deps.states is not None:
        try:
            deps.states.send_task_success(taskToken=gate["task_token"],
                                          output=json.dumps({"reviewed": True, "run_id": inv["run_id"]}))
        except Exception:  # noqa: BLE001 - the run will time out and report instead
            log.warning("could not release review gate for %s", inv["run_id"], exc_info=True)
    return 200, {"investigation_id": inv_id, "state": decision}


def decide_note(deps, scope: Scope, body: dict):
    decision = body.get("decision")
    note_id = str(body.get("note_id", ""))
    if decision not in ("active", "rejected") or not UUID_RE.match(note_id):
        return 400, {"error": "need note_id and decision active|rejected"}
    try:
        with deps.db.scoped(scope) as conn:
            row = conn.execute("update team_notes set status = %s, approver = %s, decided_at = now() "
                               "where id = %s and status = 'proposed' returning id",
                               (decision, scope.user_id, note_id)).fetchone()
    except psycopg.errors.InsufficientPrivilege:
        return 403, {"error": "only a team lead or admin can decide team notes"}
    if not row:
        return 404, {"error": "no proposed note with that id in your scope (or you can't decide it)"}
    return 200, {"note_id": note_id, "status": decision}


def dispute(deps, scope: Scope, body: dict):
    try:
        fp = parse_ref(str(body.get("finding_id", "")))
    except ToolError as exc:
        return 400, {"error": str(exc)}
    note = str(body.get("note") or "").strip()[:1000]
    if len(note) < 5:
        return 400, {"error": "say briefly what is wrong (at least 5 characters)"}
    with deps.db.scoped(scope) as conn:
        inv = conn.execute("select id, team_id from investigations where fingerprint = %s "
                           "order by created_at desc, id desc limit 1", (fp,)).fetchone()
        if not inv:
            return 404, {"error": "no investigation for that finding in your scope"}
        conn.execute("insert into investigation_reviews (investigation_id, team_id, decision, reviewer, note) "
                     "values (%s, %s, 'disputed', %s, %s)", (inv["id"], inv["team_id"], scope.user_id, note))
    return 200, {"finding": ref(fp), "state": "disputed",
                 "next_step": "Hidden from the brief; it is investigated again in the next weekly run."}


def feedback(deps, scope: Scope, body: dict):
    try:
        rating = int(body.get("rating"))
    except (TypeError, ValueError):
        rating = 0
    session_id = str(body.get("session_id") or "")[:64]
    job_id = str(body.get("job_id") or "")
    if rating not in (1, -1) or not session_id:
        return 400, {"error": "need session_id and rating 1 or -1"}
    with deps.db.scoped(scope) as conn:
        conn.execute("insert into answer_feedback (user_id, session_id, job_id, rating, comment, answer) "
                     "values (%s, %s, %s, %s, %s, %s)",
                     (scope.user_id, session_id, job_id if UUID_RE.match(job_id) else None, rating,
                      (str(body.get("comment") or "")[:1000] or None), (str(body.get("answer") or "")[:4000] or None)))
    log.info(json.dumps({"event": "feedback", "rating": rating, "user": scope.user_id}))
    return 200, {"ok": True}


def list_fixes(deps, scope: Scope, body: dict):
    with deps.db.scoped(scope) as conn:
        rows = conn.execute("select id, fingerprint, team_id, repo, status, manifest_path, diff, rationale, "
                            "requested_by, approver, pr_url, error, created_at from fix_requests "
                            "order by created_at desc limit 30").fetchall()
    return 200, {"can_decide": _can_decide(scope), "fixes": [{
        "fix_request_id": str(r["id"]), "finding": ref(r["fingerprint"]), "team": r["team_id"], "repo": r["repo"],
        "status": r["status"], "manifest": r["manifest_path"], "diff": r["diff"], "rationale": r["rationale"],
        "requested_by": r["requested_by"], "approver": r["approver"], "pr_url": r["pr_url"], "error": r["error"],
        "created_at": r["created_at"].isoformat()} for r in rows]}


def request_fix(deps, scope: Scope, body: dict):
    if deps.fix_client is None:
        return 503, {"error": "the fix agent is not configured here"}
    try:
        fp = parse_ref(str(body.get("finding_id", "")))
    except ToolError as exc:
        return 400, {"error": str(exc)}
    try:
        return 200, deps.fix_client.request_fix(scope, fp)
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": str(exc)[:300]}


def decide_fix(deps, scope: Scope, body: dict):
    decision = body.get("decision")
    fid = str(body.get("fix_request_id", ""))
    if decision not in ("approved", "rejected") or not UUID_RE.match(fid):
        return 400, {"error": "need fix_request_id and decision approved|rejected"}
    if deps.fix_client is None:
        return 503, {"error": "the fix agent is not configured here"}
    try:
        with deps.db.scoped(scope) as conn:
            row = conn.execute(
                "update fix_requests set status = %s, approver = %s, decided_at = now(), updated_at = now(), "
                "approved_sha256 = case when %s = 'approved' then encode(sha256(convert_to(new_content, 'UTF8')), 'hex') end "
                "where id = %s and status = 'awaiting_approval' returning id",
                (decision, scope.user_id, decision, fid)).fetchone()
    except psycopg.errors.InsufficientPrivilege:
        return 403, {"error": "only a team lead or admin of that team can approve or reject fixes"}
    if not row:
        return 404, {"error": "no fix waiting for approval with that id in your scope"}
    try:
        return 200, deps.fix_client.decide(scope, fid, decision)
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"recorded your decision, but the fix agent failed: {str(exc)[:200]}"}


ROUTES = {
    ("GET", "reviews"): reviews,
    ("POST", "reviews/investigation"): decide_investigation,
    ("POST", "reviews/note"): decide_note,
    ("POST", "findings/dispute"): dispute,
    ("POST", "feedback"): feedback,
    ("GET", "fixes"): list_fixes,
    ("POST", "fixes/request"): request_fix,
    ("POST", "fixes/decide"): decide_fix,
}

