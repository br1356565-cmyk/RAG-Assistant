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
import uuid

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
            "select id, fingerprint, team_id, repo, manifest_path, diff, rationale, requested_by, created_at, "
            "package, covers, major_upgrade from fix_requests where status = 'awaiting_approval' "
            "order by created_at").fetchall()
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
                   "requested_by": x["requested_by"], "package": x["package"],
                   "covers": [ref(c) for c in (x["covers"] or [x["fingerprint"]])],
                   "major_upgrade": x["major_upgrade"]} for x in fixes],
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


# ── Terraform drafter ─────────────────────────────────────────────────────
def _scope_json(scope: Scope) -> dict:
    return {"user_id": scope.user_id, "team_ids": list(scope.team_ids), "role": scope.role}


def _infra_ready(deps) -> bool:
    return deps.fix_client is not None and hasattr(deps.fix_client, "infra_start")


def _run_or_dispatch(deps, job: dict) -> tuple[int, dict]:
    if deps.dispatch is not None:
        deps.dispatch({"_infra_job": job})
        return 202, {"request_id": job["request_id"], "status": "drafting"}
    from .chat import run_infra_job
    return 200, run_infra_job(job, None, deps=deps)


def infra_request(deps, scope: Scope, body: dict):
    text = str(body.get("request") or "").strip()
    if not 10 <= len(text) <= 2000:
        return 400, {"error": "describe what you need in 10 to 2000 characters"}
    if not _infra_ready(deps):
        return 503, {"error": "the Terraform drafter is not configured here"}
    team = str(body.get("team") or (scope.team_ids[0] if len(scope.team_ids) == 1 else ""))
    if team not in scope.team_ids:
        return 400, {"error": "choose one of your teams" if scope.team_ids else "only team members can request infrastructure"}
    rid = str(uuid.uuid4())
    with deps.db.scoped(scope) as conn:
        conn.execute("insert into infra_requests (id, team_id, requested_by, request, thread_id) values (%s, %s, %s, %s, %s)",
                     (rid, team, scope.user_id, text, f"infra-{rid}"))
    log.info(json.dumps({"event": "infra_request", "team": team, "user": scope.user_id}))
    return _run_or_dispatch(deps, {"action": "start", "request_id": rid, "scope": _scope_json(scope)})


def infra_list(deps, scope: Scope, body: dict):
    with deps.db.scoped(scope) as conn:
        rows = conn.execute(
            "select id, team_id, requested_by, request, status, decision, pr_url, created_at, updated_at, "
            "jsonb_array_length(files) as n_files, "
            "(select count(*) from jsonb_array_elements(checks) c where (c->>'ok')::boolean is false) as warnings "
            "from infra_requests order by created_at desc limit 40").fetchall()
    return 200, {"can_decide": _can_decide(scope), "teams": list(scope.team_ids), "requests": [{
        "request_id": str(r["id"]), "team": r["team_id"], "requested_by": r["requested_by"], "request": r["request"],
        "status": r["status"], "decision": r["decision"], "pr_url": r["pr_url"], "files": r["n_files"],
        "warnings": r["warnings"], "created_at": r["created_at"].isoformat(),
        "updated_at": r["updated_at"].isoformat()} for r in rows]}


def infra_detail(deps, scope: Scope, body: dict):
    rid = str(body.get("id", ""))
    if not UUID_RE.match(rid):
        return 400, {"error": "invalid request id"}
    with deps.db.scoped(scope) as conn:
        r = conn.execute("select * from infra_requests where id = %s", (rid,)).fetchone()
    if not r:
        return 404, {"error": "request not found in your teams"}
    return 200, {"can_decide": _can_decide(scope), "is_requester": r["requested_by"] == scope.user_id, **{
        k: (r[k].isoformat() if hasattr(r[k], "isoformat") else r[k]) for k in (
            "team_id", "requested_by", "request", "status", "decision", "reasoning", "question", "answer", "files",
            "diff", "checks", "steps", "approver", "reject_reason", "pr_url", "error", "created_at", "updated_at")},
        "request_id": rid, "steps": [s["label"] for s in (r["steps"] or [])]}


def infra_answer(deps, scope: Scope, body: dict):
    rid, answer = str(body.get("request_id", "")), str(body.get("answer") or "").strip()
    if not UUID_RE.match(rid) or not 1 <= len(answer) <= 2000:
        return 400, {"error": "need request_id and an answer (up to 2000 characters)"}
    if not _infra_ready(deps):
        return 503, {"error": "the Terraform drafter is not configured here"}
    with deps.db.scoped(scope) as conn:
        r = conn.execute("select status, requested_by from infra_requests where id = %s", (rid,)).fetchone()
    if not r or r["status"] != "needs_input":
        return 409, {"error": "this request is not waiting for an answer"}
    if r["requested_by"] != scope.user_id and not _can_decide(scope):
        return 403, {"error": "only the requester or a lead can answer"}
    return _run_or_dispatch(deps, {"action": "answer", "request_id": rid, "answer": answer, "scope": _scope_json(scope)})


def infra_decide(deps, scope: Scope, body: dict):
    from fix_agent.infra_write import files_hash
    rid, decision = str(body.get("request_id", "")), body.get("decision")
    reason = str(body.get("reason") or "").strip()[:500]
    if not UUID_RE.match(rid) or decision not in ("approved", "rejected"):
        return 400, {"error": "need request_id and decision approved|rejected"}
    if decision == "rejected" and len(reason) < 5:
        return 400, {"error": "say why it is rejected: it becomes a proposed convention for future drafts"}
    if not _infra_ready(deps):
        return 503, {"error": "the Terraform drafter is not configured here"}
    try:
        with deps.db.scoped(scope) as conn:
            r = conn.execute("select team_id, files from infra_requests where id = %s and status = 'awaiting_approval'",
                             (rid,)).fetchone()
            if not r:
                return 404, {"error": "no request waiting for approval with that id in your teams"}
            if decision == "approved":
                # Bind the approval to exactly these files; the write tool re-checks the hash.
                row = conn.execute(
                    "update infra_requests set status = 'approved', approver = %s, decided_at = now(), updated_at = now(), "
                    "approved_sha256 = %s where id = %s and status = 'awaiting_approval' and files = %s::jsonb returning id",
                    (scope.user_id, files_hash(r["files"] or []), rid, json.dumps(r["files"] or []))).fetchone()
            else:
                row = conn.execute(
                    "update infra_requests set status = 'rejected', approver = %s, decided_at = now(), updated_at = now(), "
                    "reject_reason = %s where id = %s and status = 'awaiting_approval' returning id",
                    (scope.user_id, reason, rid)).fetchone()
                if row:   # the reason becomes a PROPOSED convention; a lead activates it in Conventions
                    conn.execute("insert into infra_conventions (team_id, text, source, author, request_id) "
                                 "values (%s, %s, 'rejection', %s, %s)", (r["team_id"], reason, scope.user_id, rid))
    except psycopg.errors.InsufficientPrivilege:
        return 403, {"error": "only a team lead or admin of that team can approve or reject"}
    if not row:
        return 409, {"error": "the draft changed while you were reviewing it; reload and review again"}
    try:
        out = deps.fix_client.infra_decide(scope, rid, decision)
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"recorded your decision, but the drafter failed: {str(exc)[:200]}"}
    return 200, out


def conventions(deps, scope: Scope, body: dict):
    with deps.db.scoped(scope) as conn:
        rows = conn.execute("select id, team_id, text, status, source, author, approver, created_at from infra_conventions "
                            "where status in ('active','proposed') order by status, created_at desc limit 100").fetchall()
    return 200, {"can_decide": _can_decide(scope), "conventions": [{
        "id": str(r["id"]), "team": r["team_id"] or "all teams", "text": r["text"], "status": r["status"],
        "source": r["source"], "author": r["author"], "approver": r["approver"],
        "created_at": r["created_at"].isoformat()} for r in rows]}


def convention_propose(deps, scope: Scope, body: dict):
    text = str(body.get("text") or "").strip()
    team = body.get("team") or (scope.team_ids[0] if len(scope.team_ids) == 1 else None)
    if not 5 <= len(text) <= 500:
        return 400, {"error": "a convention is 5 to 500 characters"}
    if team is not None and team not in scope.team_ids and not scope.is_admin:
        return 400, {"error": "choose one of your teams"}
    try:
        with deps.db.scoped(scope) as conn:
            cid = conn.execute("insert into infra_conventions (team_id, text, source, author) values (%s, %s, 'manual', %s) "
                               "returning id", (team, text, scope.user_id)).fetchone()["id"]
    except psycopg.errors.InsufficientPrivilege:
        return 403, {"error": "only admins can propose conventions for every team"}
    return 200, {"id": str(cid), "status": "proposed"}


def convention_decide(deps, scope: Scope, body: dict):
    cid, decision = str(body.get("id", "")), body.get("decision")
    if not UUID_RE.match(cid) or decision not in ("active", "rejected"):
        return 400, {"error": "need id and decision active|rejected"}
    try:
        with deps.db.scoped(scope) as conn:
            row = conn.execute("update infra_conventions set status = %s, approver = %s, decided_at = now() "
                               "where id = %s and status = 'proposed' returning id", (decision, scope.user_id, cid)).fetchone()
    except psycopg.errors.InsufficientPrivilege:
        return 403, {"error": "only a team lead or admin can decide conventions"}
    if not row:
        return 404, {"error": "no proposed convention with that id that you can decide"}
    return 200, {"id": cid, "status": decision}


ROUTES = {
    ("GET", "reviews"): reviews,
    ("POST", "reviews/investigation"): decide_investigation,
    ("POST", "reviews/note"): decide_note,
    ("POST", "findings/dispute"): dispute,
    ("POST", "feedback"): feedback,
    ("GET", "fixes"): list_fixes,
    ("POST", "fixes/request"): request_fix,
    ("POST", "fixes/decide"): decide_fix,
    ("POST", "infra/request"): infra_request,
    ("GET", "infra"): infra_list,
    ("GET", "infra/request"): infra_detail,
    ("POST", "infra/answer"): infra_answer,
    ("POST", "infra/decide"): infra_decide,
    ("GET", "conventions"): conventions,
    ("POST", "conventions/propose"): convention_propose,
    ("POST", "conventions/decide"): convention_decide,
}

