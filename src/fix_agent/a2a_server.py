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

from .service import FixError

log = logging.getLogger(__name__)
FP_RE = re.compile(r"^[0-9a-f]{16}$")
UUID_RE = re.compile(r"^[0-9a-f-]{36}$")


def handle(service, key: bytes, text: str) -> dict:
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
        return {"error": "unknown or malformed action"}
    except FixError as exc:
        return {"error": str(exc)}
    except Exception:  # noqa: BLE001
        log.exception("fix agent action failed")
        return {"error": "the fix agent failed; see its logs"}


class FixExecutor(AgentExecutor):
    def __init__(self, service, key: bytes):
        self.service, self.key = service, key

    async def execute(self, context, event_queue) -> None:
        result = await asyncio.to_thread(handle, self.service, self.key, context.get_user_input())
        await event_queue.enqueue_event(new_text_message(
            json.dumps(result, default=str),
            context_id=getattr(context, "context_id", None), task_id=getattr(context, "task_id", None)))

    async def cancel(self, context, event_queue) -> None:
        raise NotImplementedError("fix requests are cancelled by rejecting them")
