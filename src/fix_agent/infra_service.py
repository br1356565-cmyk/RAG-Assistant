"""Starts, answers and resumes Terraform drafter graphs (thread_id = the request id).

The request row is created by the API under the requester's scope (so the page can poll it
at once); the graph then drafts in the background."""
from __future__ import annotations

from langgraph.types import Command

from audit_agent.db import Scope

from .infra_graph import InfraDeps, build_infra_graph


class InfraError(Exception):
    pass


class InfraService:
    def __init__(self, deps: InfraDeps, checkpointer):
        self.deps = deps
        self.graph = build_infra_graph(deps, checkpointer)

    def _row(self, scope: Scope, request_id: str) -> dict:
        with self.deps.db.scoped(scope) as conn:
            row = conn.execute("select id, team_id, request, status, requested_by from infra_requests where id = %s",
                               (request_id,)).fetchone()
        if not row:
            raise InfraError("infra request not found in your scope")
        return row

    def start(self, scope: Scope, request_id: str) -> dict:
        row = self._row(scope, request_id)
        if row["status"] != "drafting":
            raise InfraError(f"this request is {row['status']}, not waiting to be drafted")
        self.graph.invoke({"request_id": request_id, "team_id": row["team_id"], "request": row["request"],
                           "qa": [], "rounds": 0}, self._config(request_id))
        return self.summary(scope, request_id)

    def answer(self, scope: Scope, request_id: str, answer: str) -> dict:
        row = self._row(scope, request_id)
        if row["status"] != "needs_input":
            raise InfraError("this request is not waiting for an answer")
        if row["requested_by"] != scope.user_id and scope.role not in ("team_lead", "security_admin"):
            raise InfraError("only the requester (or a lead) can answer")
        if "wait_answer" not in (self.graph.get_state(self._config(request_id)).next or ()):
            raise InfraError("this request is not waiting for an answer")
        with self.deps.db.scoped(scope) as conn:
            conn.execute("update infra_requests set status = 'drafting', answer = %s, question = null, "
                         "steps = steps || '[{\"kind\": \"thinking\", \"label\": \"Got your answer; drafting again\"}]'::jsonb, "
                         "updated_at = now() where id = %s", (answer[:2000], request_id))
        self.graph.invoke(Command(resume={"answer": answer}), self._config(request_id))
        return self.summary(scope, request_id)

    def resume(self, scope: Scope, request_id: str, decision: str) -> dict:
        """The approval itself was recorded by the API under the lead's scope (approver and the
        hash of the approved files); the write tool re-checks it before touching GitHub."""
        if "await_approval" not in (self.graph.get_state(self._config(request_id)).next or ()):
            raise InfraError("this request is not waiting for approval")
        self.graph.invoke(Command(resume={"decision": decision, "approver": scope.user_id}), self._config(request_id))
        return self.summary(scope, request_id)

    def summary(self, scope: Scope, request_id: str) -> dict:
        with self.deps.db.scoped(scope) as conn:
            r = conn.execute("select status, decision, question, pr_url, error from infra_requests where id = %s",
                             (request_id,)).fetchone()
        return {"request_id": request_id, **{k: r[k] for k in ("status", "decision", "question", "pr_url", "error")}}

    @staticmethod
    def _config(request_id: str) -> dict:
        return {"configurable": {"thread_id": f"infra-{request_id}"}}
