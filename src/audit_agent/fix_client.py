"""How the audit agent reaches the fix agent.

A2AFixClient: AgentCore Runtime (A2A protocol), SigV4-signed JSON-RPC "SendMessage".
LocalFixClient: the same FixService in-process (local prototype and tests).
Both send a scope token, never a bare user id."""
from __future__ import annotations

import json
import uuid
from typing import Callable

import httpx

from .db import Scope
from .scope_token import sign


class FixAgentError(RuntimeError):
    pass


class LocalFixClient:
    def __init__(self, service, infra=None):
        self.service, self.infra = service, infra

    def request_fix(self, scope: Scope, fingerprint: str) -> dict:
        return self.service.draft(scope, fingerprint)

    def decide(self, scope: Scope, fix_request_id: str, decision: str) -> dict:
        return self.service.resume(fix_request_id, decision, scope.user_id)

    # Terraform drafter
    def infra_start(self, scope: Scope, request_id: str) -> dict:
        return self._infra().start(scope, request_id)

    def infra_answer(self, scope: Scope, request_id: str, answer: str) -> dict:
        return self._infra().answer(scope, request_id, answer)

    def infra_decide(self, scope: Scope, request_id: str, decision: str) -> dict:
        return self._infra().resume(scope, request_id, decision)

    def _infra(self):
        if self.infra is None:
            raise FixAgentError("the Terraform drafter is not configured here")
        return self.infra


class A2AFixClient:
    def __init__(self, url: str, key: bytes, signer: Callable | None = None, http: httpx.Client | None = None,
                 timeout_s: float = 50.0):
        self.url, self._key, self._sign = url, key, signer
        self._http = http or httpx.Client(timeout=timeout_s)

    def _send(self, scope: Scope, payload: dict, timeout_s: float | None = None) -> dict:
        text = json.dumps({**payload, "scope_token": sign(scope, self._key)})
        body = json.dumps({"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "SendMessage", "params": {
            "message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}}}).encode()
        headers = {"content-type": "application/json", "accept": "application/json", "a2a-version": "1.0",
                   "x-amzn-bedrock-agentcore-runtime-session-id": f"fix-{uuid.uuid4()}"}
        if self._sign:
            headers = self._sign("POST", self.url, headers, body)
        r = self._http.post(self.url, content=body, headers=headers,
                            **({"timeout": timeout_s} if timeout_s else {}))
        if r.status_code >= 400:
            raise FixAgentError(f"fix agent HTTP {r.status_code}: {r.text[:200]}")
        msg = r.json()
        if "error" in msg:
            raise FixAgentError(f"fix agent error: {msg['error'].get('message', msg['error'])}"[:300])
        text = _first_text(msg.get("result"))
        if text is None:
            raise FixAgentError("fix agent sent no reply")
        out = json.loads(text)
        if "error" in out:
            raise FixAgentError(out["error"])
        return out

    def request_fix(self, scope: Scope, fingerprint: str) -> dict:
        return self._send(scope, {"action": "draft", "fingerprint": fingerprint})

    def decide(self, scope: Scope, fix_request_id: str, decision: str) -> dict:
        return self._send(scope, {"action": "decide", "fix_request_id": fix_request_id, "decision": decision})

    # Terraform drafter: drafting runs a multi-tool agent, so allow minutes, not seconds.
    def infra_start(self, scope: Scope, request_id: str) -> dict:
        return self._send(scope, {"action": "infra_start", "request_id": request_id}, timeout_s=280)

    def infra_answer(self, scope: Scope, request_id: str, answer: str) -> dict:
        return self._send(scope, {"action": "infra_answer", "request_id": request_id, "answer": answer},
                          timeout_s=280)

    def infra_decide(self, scope: Scope, request_id: str, decision: str) -> dict:
        return self._send(scope, {"action": "infra_decide", "request_id": request_id, "decision": decision},
                          timeout_s=120)


def _first_text(node) -> str | None:
    """The reply is a Message, or a Task whose status message / artifacts hold the text."""
    if isinstance(node, dict):
        if isinstance(node.get("text"), str):
            return node["text"]
        for key in ("message", "msg", "status", "artifacts", "parts", "history", "task"):
            if key in node:
                found = _first_text(node[key])
                if found is not None:
                    return found
    if isinstance(node, list):
        for item in reversed(node) if node and isinstance(node[0], dict) and "role" in node[0] else node:
            found = _first_text(item)
            if found is not None:
                return found
    return None
