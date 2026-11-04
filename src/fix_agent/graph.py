"""The fix graph (LangGraph):

    load ──▶ edit ──▶ explain ──▶ await_approval ──approved──▶ open_pr ──▶ END
      │        │                       │ (interrupt: waits for a team lead)
      └────────┴──▶ fail               └──rejected──▶ record_rejection ──▶ END

The model is used for one thing only, the plain-English rationale. Reading the finding,
the version bump and the checks are deterministic code. State is checkpointed (Postgres in
production), so the graph pauses at `await_approval` for as long as the review takes and
resumes exactly there, in a different process if need be.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from audit_agent.db import Database, Scope

from .github_write import content_hash
from .manifest import ManifestError, bump, manifest_for

log = logging.getLogger(__name__)

WORKER = "worker:fix"


class FixState(TypedDict, total=False):
    fix_request_id: str
    fingerprint: str
    team_id: str
    repo: str
    package: str
    manifest_path: str
    target: str
    advisory: str
    summary: str
    new_content: str
    diff: str
    old_spec: str
    new_spec: str
    rationale: str
    decision: str
    approver: str
    pr_url: str
    error: str


@dataclass
class FixDeps:
    db: Database
    read_file: Callable[[Scope, str, str], dict]        # (scope, repo, path) -> {"content", "truncated"}
    open_pr: Callable[[Scope, str], dict]               # (scope, fix_request_id) -> {"pr_url"}
    llm: Any = None                                     # optional: writes the rationale
    model: str = ""


def worker_scope(team_id: str) -> Scope:
    return Scope(user_id=WORKER, team_ids=(team_id,), role="worker")


def build_graph(deps: FixDeps, checkpointer):
    def update(state: FixState, **cols) -> None:
        sets = ", ".join(f"{k} = %s" for k in cols)
        with deps.db.scoped(worker_scope(state["team_id"])) as conn:
            conn.execute(f"update fix_requests set {sets}, updated_at = now() where id = %s",
                         (*cols.values(), state["fix_request_id"]))

    def load(state: FixState) -> dict:
        scope = worker_scope(state["team_id"])
        with deps.db.scoped(scope) as conn:
            f = conn.execute("select * from findings where fingerprint = %s", (state["fingerprint"],)).fetchone()
        if not f:
            return {"error": "finding not found"}
        d = f["details"] or {}
        if f["source"] != "dependabot" or not d.get("first_patched") or not d.get("manifest"):
            return {"error": "only Dependabot findings with a fixed version can be drafted"}
        manifest = manifest_for(d["manifest"])
        try:
            file = deps.read_file(scope, f["resource"], manifest)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"could not read {manifest}: {exc}"}
        if file.get("truncated"):
            return {"error": f"{manifest} is too large to edit safely"}
        return {"repo": f["resource"], "package": d.get("package"), "manifest_path": manifest,
                "target": d["first_patched"], "advisory": d.get("advisory") or "", "summary": f["title"],
                "new_content": file["content"]}

    def edit(state: FixState) -> dict:
        try:
            e = bump(state["manifest_path"], state["new_content"], state["package"], state["target"])
        except ManifestError as exc:
            return {"error": str(exc)}
        return {"new_content": e.new, "diff": e.diff, "old_spec": e.old_spec, "new_spec": e.new_spec}

    def explain(state: FixState) -> dict:
        fallback = (f"Upgrades {state['package']} from {state['old_spec']} to {state['new_spec']} in "
                    f"{state['manifest_path']}, the first version that fixes {state['advisory'] or 'the advisory'} "
                    f"({state['summary']}).")
        if deps.llm is None:
            return {"rationale": fallback}
        try:
            resp = deps.llm.complete(model=deps.model, max_tokens=250, user=WORKER, tags=["mode:fix"], tools=[],
                                     tool_choice="auto", messages=[
                {"role": "system", "content": "Write a 2-3 sentence pull request description for a security "
                 "dependency upgrade. Plain words, no markdown headings, no claims beyond the facts given."},
                {"role": "user", "content": f"Package: {state['package']}\nChange: {state['old_spec']} -> "
                 f"{state['new_spec']}\nFile: {state['manifest_path']}\nAdvisory: {state['advisory']}\n"
                 f"Problem: {state['summary']}"}])
            text = (resp.text or "").strip()
            return {"rationale": text[:800] if text else fallback}
        except Exception:  # noqa: BLE001
            log.warning("rationale model call failed; using template", exc_info=True)
            return {"rationale": fallback}

    def publish(state: FixState) -> dict:
        # Its own node: LangGraph re-runs an interrupted node from the top on resume, so a write
        # placed before interrupt() would overwrite the lead's approval.
        update(state, status="awaiting_approval", manifest_path=state["manifest_path"], diff=state["diff"],
               new_content=state["new_content"], rationale=state["rationale"])
        return {}

    def await_approval(state: FixState) -> dict:
        decision = interrupt({"fix_request_id": state["fix_request_id"], "diff": state["diff"],
                              "content_sha256": content_hash(state["new_content"])})
        return {"decision": decision.get("decision", "rejected"), "approver": decision.get("approver", "")}

    def open_pr(state: FixState) -> dict:
        try:
            out = deps.open_pr(worker_scope(state["team_id"]), state["fix_request_id"])
            return {"pr_url": out.get("pr_url", "")}
        except Exception as exc:  # noqa: BLE001
            update(state, status="failed", error=str(exc)[:500])
            return {"error": str(exc)[:500]}

    def record_rejection(state: FixState) -> dict:
        return {}

    def fail(state: FixState) -> dict:
        update(state, status="failed", error=state["error"][:500])
        return {}

    g = StateGraph(FixState)
    for name, fn in [("load", load), ("edit", edit), ("explain", explain), ("publish", publish),
                     ("await_approval", await_approval),
                     ("open_pr", open_pr), ("record_rejection", record_rejection), ("fail", fail)]:
        g.add_node(name, fn)
    g.add_edge(START, "load")
    g.add_conditional_edges("load", lambda s: "fail" if s.get("error") else "edit")
    g.add_conditional_edges("edit", lambda s: "fail" if s.get("error") else "explain")
    g.add_edge("explain", "publish")
    g.add_edge("publish", "await_approval")
    g.add_conditional_edges("await_approval",
                            lambda s: "open_pr" if s.get("decision") == "approved" else "record_rejection")
    g.add_edge("open_pr", END)
    g.add_edge("record_rejection", END)
    g.add_edge("fail", END)
    return g.compile(checkpointer=checkpointer)
