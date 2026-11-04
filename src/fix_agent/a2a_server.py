"""A2A server for the fix agent (AgentCore Runtime, protocol A2A, port 9000).

Messages are one JSON text part:
  {"action": "draft",  "fingerprint": "<16 hex>",                         "scope_token": "..."}
  {"action": "decide", "fix_request_id": "<uuid>", "decision": "approved"|"rejected", "scope_token": "..."}
The scope token (signed by the audit agent's harness/API) carries who is asking; the fix
agent never trusts a user id in the message itself. Replies are one JSON text part.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re

from a2a.helpers.proto_helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor

from audit_agent.scope_token import ScopeTokenError, verify

from .infra_service import InfraError
from .service import FixError

log = logging.getLogger(__name__)
FP_RE = re.compile(r"^[0-9a-f]{16}$")
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")


def handle(service, key: bytes, text: str, infra=None) -> dict:
    try:
        msg = json.loads(text)
        scope, _ = verify(str(msg.get("scope_token", "")), key)
    except (json.JSONDecodeError, AttributeError):
        return {"error": "message must be a JSON object"}
    except ScopeTokenError as exc:
        return {"error": f"refused: {exc}"}
    try:
        if msg.get("action") == "draft" and FP_RE.match(str(msg.get("fingerprint", ""))):
            return service.draft(scope, msg["fingerprint"])
        if (msg.get("action") == "decide" and UUID_RE.match(str(msg.get("fix_request_id", "")))
                and msg.get("decision") in ("approved", "rejected")):
            return service.resume(msg["fix_request_id"], msg["decision"], scope.user_id)
        rid = str(msg.get("request_id", ""))
        if infra is not None and UUID_RE.match(rid):
            if msg.get("action") == "infra_start":
                return infra.start(scope, rid)
            if msg.get("action") == "infra_answer" and str(msg.get("answer", "")).strip():
                return infra.answer(scope, rid, str(msg["answer"]))
            if msg.get("action") == "infra_decide" and msg.get("decision") in ("approved", "rejected"):
                return infra.resume(scope, rid, msg["decision"])
        return {"error": "unknown or malformed action"}
    except (FixError, InfraError) as exc:
        return {"error": str(exc)}
    except Exception:  # noqa: BLE001
        log.exception("fix agent action failed")
        return {"error": "the fix agent failed; see its logs"}


class FixExecutor(AgentExecutor):
    def __init__(self, service, key: bytes, infra=None):
        self.service, self.key, self.infra = service, key, infra

    async def execute(self, context, event_queue) -> None:
        result = await asyncio.to_thread(handle, self.service, self.key, context.get_user_input(), self.infra)
        await event_queue.enqueue_event(new_text_message(
            json.dumps(result, default=str),
            context_id=getattr(context, "context_id", None), task_id=getattr(context, "task_id", None)))

    async def cancel(self, context, event_queue) -> None:
        raise NotImplementedError("fix requests are cancelled by rejecting them")


def context_builder():
    """The SDK's context builder, plus a default A2A protocol version.

    AgentCore Runtime forwards only allowlisted request headers to the agent, so the
    client's `A2A-Version: 1.0` header may not arrive; a request without it is treated as
    protocol 0.3 and refused by the 1.0 handler. Our only client speaks 1.0, so a missing
    version means 1.0. An explicit version header is left as sent."""
    from bedrock_agentcore.runtime.a2a import BedrockCallContextBuilder

    class DefaultVersionContextBuilder(BedrockCallContextBuilder):
        def build(self, request):
            ctx = super().build(request)
            headers = ctx.state.setdefault("headers", {})
            if not any(k.lower() == "a2a-version" for k in headers):
                headers["A2A-Version"] = "1.0"
            return ctx

    return DefaultVersionContextBuilder()
