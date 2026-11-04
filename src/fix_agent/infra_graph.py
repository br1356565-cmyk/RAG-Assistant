"""The Terraform drafter as a LangGraph graph.

    draft (ReAct: memory, infra repo, AWS) -> check (code) --need_input--> ask -> wait (interrupt) -> draft
                                                       \\--> publish -> await_approval (interrupt)
                                                                 -> open_pr | done
The model never writes outside teams/<team>/ (submit_draft enforces it), never applies
anything, and its files reach GitHub only after a lead approves exactly those files.
Every database write sits in its own node BEFORE an interrupt: LangGraph re-runs an
interrupted node from the top on resume.
"""
from __future__ import annotations

import difflib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from audit_agent.db import Database, Scope
from audit_agent.harness import Harness, HarnessConfig
from audit_agent.prompts import INFRA_SYSTEM
from audit_agent.tools import ToolContext

from . import infra_checks

log = logging.getLogger(__name__)
WORKER = "worker:infra"


class InfraState(TypedDict, total=False):
    request_id: str
    team_id: str
    request: str
    qa: list
    rounds: int
    draft: dict
    checks: list
    diff: str
    decision: str
    approver: str
    pr_url: str
    error: str


@dataclass
class InfraDeps:
    db: Database
    tools: Callable[[], list]                            # -> the infra-mode tools (in-process or via Gateway)
    llm_for: Callable[[tuple[str, ...]], Any]
    model: str
    read_infra: Callable[[Scope, str], str | None]       # current content of a path in the infra repo
    open_pr: Callable[[Scope, str], dict]                # (scope, request_id) -> {"pr_url"}
    repo: str = "demo-infra-terraform"
    github: Any = None                                   # for in-process repo tools
    aws: Any = None                                      # for in-process AWS tools
    max_questions: int = 2
    deadline_s: float = 150.0
    extra_config: dict = field(default_factory=dict)


def worker_scope(team_id: str) -> Scope:
    return Scope(user_id=WORKER, team_ids=(team_id,), role="worker")


def unified_diff(path: str, old: str | None, new: str) -> str:
    return "".join(difflib.unified_diff((old or "").splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{path}" if old is not None else "/dev/null", tofile=f"b/{path}"))


def build_infra_graph(deps: InfraDeps, checkpointer):
    def update(state: InfraState, **cols) -> None:
        sets = ", ".join(f"{k} = %s" for k in cols)
        with deps.db.scoped(worker_scope(state["team_id"])) as conn:
            conn.execute(f"update infra_requests set {sets}, updated_at = now() where id = %s",
                         (*cols.values(), state["request_id"]))

    def draft(state: InfraState) -> dict:
        scope = worker_scope(state["team_id"])

        def on_step(step: dict) -> None:
            try:
                with deps.db.scoped(scope) as conn:
                    conn.execute("update infra_requests set steps = steps || jsonb_build_array(%s::jsonb), "
                                 "updated_at = now() where id = %s",
                                 (json.dumps({"kind": step["kind"], "label": step["label"]}), state["request_id"]))
            except Exception:  # noqa: BLE001 - progress is best-effort
                log.warning("could not record a step", exc_info=True)

        convo = "\n".join(f"You asked: {x['q']}\nThe requester answered: {x['a']}" for x in state.get("qa") or [])
        messages = [
            {"role": "system", "content": INFRA_SYSTEM.format(team=state["team_id"], repo=deps.repo)},
            {"role": "user", "content": f"Request from the {state['team_id']} team:\n{state['request']}"
                                        + (f"\n\nEarlier questions:\n{convo}" if convo else "")},
        ]
        ctx = ToolContext(scope=scope, db=deps.db, github=deps.github, mode="infra", aws=deps.aws,
                          extra={"infra_repo": deps.repo, "request_id": state["request_id"], "team": state["team_id"]})
        cfg = HarnessConfig(mode="infra", model=deps.model, max_rounds=12, max_tokens_total=90_000,
                            max_output_tokens=4_000, deadline_s=deps.deadline_s)
        res = Harness(deps.llm_for((state["team_id"],)), deps.tools(), cfg).run(ctx, messages, on_step=on_step)
        if res.status != "submitted" or not isinstance(res.data, dict):
            return {"error": f"The drafter did not finish ({res.status}). Try a more specific request."}
        return {"draft": res.data, "decision": res.data["decision"]}

    def check(state: InfraState) -> dict:
        files = state["draft"].get("files") or []
        scope = worker_scope(state["team_id"])
        diffs = []
        for f in files:
            try:
                old = deps.read_infra(scope, f["path"])
            except Exception:  # noqa: BLE001 - a missing file is a new file
                old = None
            diffs.append(unified_diff(f["path"], old, f["content"]))
        return {"checks": infra_checks.run(files, state["team_id"]) if files else [], "diff": "".join(diffs)}

    def after_check(state: InfraState) -> str:
        if state.get("error"):
            return "fail"
        if state["decision"] == "need_input":
            return "ask" if state.get("rounds", 0) < deps.max_questions else "give_up"
        return "publish"

    def ask(state: InfraState) -> dict:
        update(state, status="needs_input", question=state["draft"]["question"], reasoning=state["draft"]["reasoning"])
        return {}

    def wait_answer(state: InfraState) -> dict:
        reply = interrupt({"request_id": state["request_id"], "question": state["draft"]["question"]})
        qa = list(state.get("qa") or []) + [{"q": state["draft"]["question"], "a": str(reply.get("answer", ""))[:2000]}]
        return {"qa": qa, "rounds": state.get("rounds", 0) + 1}

    def give_up(state: InfraState) -> dict:
        d = dict(state["draft"])
        d["reasoning"] = (f"Still missing information after {deps.max_questions} questions; last question: "
                          f"{d.get('question')}\n\n{d.get('reasoning', '')}")
        d.update(decision="refuse", files=[])
        return {"draft": d, "decision": "refuse", "checks": [], "diff": ""}

    def publish(state: InfraState) -> dict:
        d = state["draft"]
        update(state, status="awaiting_approval", decision=d["decision"], reasoning=d["reasoning"], question=None,
               files=json.dumps(d.get("files") or []), diff=state.get("diff") or "",
               checks=json.dumps(state.get("checks") or []))
        return {}

    def await_approval(state: InfraState) -> dict:
        reply = interrupt({"request_id": state["request_id"], "decision": state["decision"]})
        return {"approver": reply.get("approver", ""), "error": None,
                "pr_url": None, "decision": state["decision"],
                "draft": {**state["draft"], "approved": reply.get("decision") == "approved"}}

    def after_approval(state: InfraState) -> str:
        if not state["draft"].get("approved"):
            return "done"
        return "open_pr" if state["draft"].get("files") else "done"

    def open_pr(state: InfraState) -> dict:
        try:
            out = deps.open_pr(worker_scope(state["team_id"]), state["request_id"])
            return {"pr_url": out.get("pr_url", "")}
        except Exception as exc:  # noqa: BLE001
            update(state, status="failed", error=str(exc)[:500])
            return {"error": str(exc)[:500]}

    def done(state: InfraState) -> dict:
        return {}

    def fail(state: InfraState) -> dict:
        update(state, status="failed", error=(state.get("error") or "failed")[:500])
        return {}

    g = StateGraph(InfraState)
    for name, fn in [("draft", draft), ("check", check), ("ask", ask), ("wait_answer", wait_answer),
                     ("give_up", give_up), ("publish", publish), ("await_approval", await_approval),
                     ("open_pr", open_pr), ("done", done), ("fail", fail)]:
        g.add_node(name, fn)
    g.add_edge(START, "draft")
    g.add_conditional_edges("draft", lambda s: "fail" if s.get("error") else "check")
    g.add_conditional_edges("check", after_check)
    g.add_edge("ask", "wait_answer")
    g.add_edge("wait_answer", "draft")
    g.add_edge("give_up", "publish")
    g.add_edge("publish", "await_approval")
    g.add_conditional_edges("await_approval", after_approval)
    g.add_edge("open_pr", END)
    g.add_edge("done", END)
    g.add_edge("fail", END)
    return g.compile(checkpointer=checkpointer)
