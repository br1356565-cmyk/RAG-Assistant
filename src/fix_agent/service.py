"""Starts and resumes fix graphs. One graph thread per fix request (thread_id = its id)."""
from __future__ import annotations

import uuid

from langgraph.types import Command

from audit_agent.db import Scope

from .graph import FixDeps, build_graph


class FixError(Exception):
    pass


class FixService:
    def __init__(self, deps: FixDeps, checkpointer):
        self.deps = deps
        self.graph = build_graph(deps, checkpointer)

    def draft(self, scope: Scope, fingerprint: str) -> dict:
        """Create a fix request for a finding in the caller's scope and run until it waits for approval."""
        with self.deps.db.scoped(scope) as conn:
            f = conn.execute("select team_id, resource, details->>'package' as package from findings "
                             "where fingerprint = %s", (fingerprint,)).fetchone()
            if not f or not f["team_id"]:
                raise FixError("finding not found in your scope")
            # One live fix per package and repo: it covers every open finding for that package, so
            # ten axios advisories make one PR, not ten. Live = in progress, or a PR already open
            # (findings stay open until the PR merges and Dependabot closes the alerts).
            open_req = conn.execute(
                "select id, status, pr_url from fix_requests where status in "
                "('drafting','awaiting_approval','approved','opened') and repo = %s "
                "and (fingerprint = %s or %s = any(covers) or (package is not null and package = %s)) "
                "order by created_at desc limit 1",
                (f["resource"], fingerprint, fingerprint, f["package"])).fetchone()
            if open_req:
                note = (f"A fix PR is already open: {open_req['pr_url']}" if open_req["status"] == "opened"
                        else f"A fix for {f['package'] or 'this finding'} is already in progress; it covers this finding.")
                return {"fix_request_id": str(open_req["id"]), "status": open_req["status"],
                        "pr_url": open_req["pr_url"], "note": note}
            fid = str(uuid.uuid4())
            conn.execute("insert into fix_requests (id, fingerprint, team_id, repo, requested_by, thread_id, package) "
                         "values (%s, %s, %s, %s, %s, %s, %s)",
                         (fid, fingerprint, f["team_id"], f["resource"], scope.user_id, fid, f["package"]))
        state = self.graph.invoke({"fix_request_id": fid, "fingerprint": fingerprint, "team_id": f["team_id"]},
                                  {"configurable": {"thread_id": fid}})
        return self._summary(fid, state)

    def resume(self, fix_request_id: str, decision: str, approver: str) -> dict:
        """Continue a graph paused at await_approval. The approval itself was recorded by the
        API under the lead's scope; the write tool re-checks it before touching GitHub."""
        config = {"configurable": {"thread_id": fix_request_id}}
        snap = self.graph.get_state(config)
        if not snap.next or "await_approval" not in snap.next:
            raise FixError("this fix request is not waiting for approval")
        state = self.graph.invoke(Command(resume={"decision": decision, "approver": approver}), config)
        return self._summary(fix_request_id, state)

    @staticmethod
    def _summary(fid: str, state: dict) -> dict:
        if state.get("error"):
            return {"fix_request_id": fid, "status": "failed", "error": state["error"]}
        if state.get("pr_url"):
            return {"fix_request_id": fid, "status": "opened", "pr_url": state["pr_url"]}
        if state.get("decision") == "rejected":
            return {"fix_request_id": fid, "status": "rejected"}
        return {"fix_request_id": fid, "status": "awaiting_approval", "repo": state.get("repo"),
                "manifest": state.get("manifest_path"), "change": f"{state.get('old_spec')} -> {state.get('new_spec')}",
                "diff": state.get("diff"), "rationale": state.get("rationale"),
                "covers": len(state.get("covers") or []), "major_upgrade": bool(state.get("major_upgrade"))}
