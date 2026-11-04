"""Audit agent entry point on AgentCore Runtime (code deploy: entry_point ["agent_main.py"]).

Streams server-sent events: {"type": "step", "label": ...} while the agent works, then one
{"type": "answer", ...} (or {"type": "error", ...}).
"""
from __future__ import annotations

import logging
import queue
import threading

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from audit_agent.auth import AuthError, bearer_token, resolve_scope
from audit_agent.handlers.chat import MAX_QUESTION, answer
from audit_agent.handlers.deps import get_deps

logging.basicConfig(level=logging.INFO)
app = BedrockAgentCoreApp()


def run(payload: dict, headers: dict, session_id: str | None):
    deps = get_deps()
    try:
        claims = deps.verifier.verify(bearer_token(headers))
        scope = resolve_scope(claims, deps.db)
    except AuthError as exc:
        yield {"type": "error", "status": exc.status, "error": str(exc)}
        return
    question = str(payload.get("question", "")).strip()
    if not 1 <= len(question) <= MAX_QUESTION:
        yield {"type": "error", "status": 400, "error": f"question must be 1 to {MAX_QUESTION} characters"}
        return
    session = str(payload.get("session_id") or session_id or "")[:64]

    events: queue.Queue = queue.Queue()

    def work():
        try:
            body = answer(deps, scope, claims.get("name", "user"), question, session, 50.0,
                          on_step=lambda s: events.put({"type": "step", "label": s["label"], "kind": s["kind"]}))
            events.put({"type": "answer", **body})
        except Exception as exc:  # noqa: BLE001
            logging.exception("agent failed")
            events.put({"type": "error", "status": 500, "error": type(exc).__name__})
        finally:
            events.put(None)

    threading.Thread(target=work, daemon=True).start()
    while (event := events.get()) is not None:
        yield event


@app.entrypoint
def invoke(payload, context):
    headers = dict(getattr(context, "request_headers", None) or {})
    return run(payload or {}, headers, getattr(context, "session_id", None))


if __name__ == "__main__":
    app.run()
