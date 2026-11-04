"""Calls the audit agent on AgentCore Runtime and reads its event stream.

The Runtime has an Entra JWT authorizer (AgentCore Identity), so the call carries the
user's own bearer token: AgentCore checks it before our code runs, and the agent verifies
it again to work out the user's teams (defence in depth)."""
from __future__ import annotations

import json
from typing import Iterator

import httpx


class RuntimeError_(RuntimeError):
    pass


class RuntimeClient:
    def __init__(self, url: str, http: httpx.Client | None = None, timeout_s: float = 55.0):
        self.url = url
        self._http = http or httpx.Client(timeout=timeout_s)

    def stream(self, bearer: str, payload: dict, session_id: str) -> Iterator[dict]:
        headers = {"authorization": f"Bearer {bearer}", "content-type": "application/json",
                   "accept": "text/event-stream",
                   # AgentCore needs >= 33 characters; our session ids are UUIDs (36).
                   "x-amzn-bedrock-agentcore-runtime-session-id": session_id.ljust(33, "0")}
        with self._http.stream("POST", self.url, content=json.dumps(payload).encode(), headers=headers) as r:
            if r.status_code >= 400:
                r.read()
                raise RuntimeError_(f"agent runtime HTTP {r.status_code}: {r.text[:300]}")
            for line in r.iter_lines():
                if line.startswith("data:"):
                    data = line[5:].strip()
                    if data:
                        event = json.loads(data)
                        # The SDK JSON-encodes yielded values; a yielded dict may arrive as a string.
                        yield json.loads(event) if isinstance(event, str) else event
