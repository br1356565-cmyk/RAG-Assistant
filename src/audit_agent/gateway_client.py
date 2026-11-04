"""Minimal MCP client for AgentCore Gateway (streamable HTTP, JSON-RPC), signed with SigV4.

The Gateway uses the AWS_IAM authorizer, so the caller's IAM role is the identity that
AgentCore Policy (Cedar) evaluates: the audit agent's role may call read tools only, the fix
agent's role may also call the write tool. Gateway tool names are "<target>___<tool>".

Every call carries a signed scope token (see scope_token.py) so the tool Lambda enforces the
user's scope; the model never sees or writes that token.
"""
from __future__ import annotations

import itertools
import json
import logging
from typing import Any, Callable

import httpx

from .db import Scope
from .scope_token import sign

log = logging.getLogger(__name__)

# MCP protocol version. AgentCore Gateway (MCP) supports 2025-03-26 by default; if a gateway
# refuses it, the client retries once with a version from the gateway's "supported" list.
PROTOCOL_VERSION = "2025-03-26"
SCOPE_ARG = "_scope"


class GatewayError(RuntimeError):
    pass


def sigv4_signer(region: str, service: str = "bedrock-agentcore") -> Callable[[str, str, dict, bytes], dict]:
    """Returns sign(method, url, headers, body) -> headers with SigV4 auth added."""
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    session = boto3.Session()

    def sign_request(method: str, url: str, headers: dict, body: bytes) -> dict:
        creds = session.get_credentials().get_frozen_credentials()
        req = AWSRequest(method=method, url=url, data=body, headers=headers)
        SigV4Auth(creds, service, region).add_auth(req)
        return dict(req.headers.items())
    return sign_request


class GatewayClient:
    """tools: local tool name -> gateway tool name, e.g. {"get_advisory": "github___get_advisory"}."""

    def __init__(self, url: str, tools: dict[str, str], signing_key: bytes,
                 signer: Callable | None = None, http: httpx.Client | None = None, timeout_s: float = 45.0):
        self.url = url
        self.tools = tools
        self.tool_names = set(tools)
        self._key = signing_key
        self._sign = signer
        self._http = http or httpx.Client(timeout=timeout_s)
        self._ids = itertools.count(1)
        self._session_id: str | None = None
        self._initialized = False
        self._version = PROTOCOL_VERSION

    def _post(self, payload: dict) -> dict | None:
        body = json.dumps(payload).encode()
        headers = {"content-type": "application/json", "accept": "application/json, text/event-stream",
                   "mcp-protocol-version": self._version}
        if self._session_id:
            headers["mcp-session-id"] = self._session_id
        if self._sign:
            headers = self._sign("POST", self.url, headers, body)
        r = self._http.post(self.url, content=body, headers=headers)
        if r.status_code >= 400:
            raise GatewayError(f"gateway HTTP {r.status_code}: {r.text[:300]}", _supported_versions(r))
        self._session_id = r.headers.get("mcp-session-id", self._session_id)
        if "id" not in payload:          # a notification: no response body expected
            return None
        return _parse_response(r)

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            reply = self._initialize()
        except GatewayError as exc:
            supported = exc.args[1] if len(exc.args) > 1 else []
            if not supported or self._version in supported:
                raise
            log.info("gateway refused MCP %s; retrying with %s", self._version, max(supported))
            self._version = max(supported)          # ISO dates: the newest sorts last
            reply = self._initialize()
        # The server may answer with a different version; later requests must use that one.
        self._version = ((reply or {}).get("result") or {}).get("protocolVersion") or self._version
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self._initialized = True

    def _initialize(self) -> dict | None:
        return self._post({"jsonrpc": "2.0", "id": next(self._ids), "method": "initialize", "params": {
            "protocolVersion": self._version, "capabilities": {},
            "clientInfo": {"name": "devops-audit-agent", "version": "2"}}})

    def call(self, local_name: str, arguments: dict, scope: Scope, **token_extra) -> dict:
        """-> the tool Lambda's JSON result: {"data", "finding_ids", "sources"} or {"error"}."""
        self._ensure_initialized()
        args = {**arguments, SCOPE_ARG: sign(scope, self._key, **token_extra)}
        msg = self._post({"jsonrpc": "2.0", "id": next(self._ids), "method": "tools/call",
                          "params": {"name": self.tools[local_name], "arguments": args}})
        if msg is None or "error" in msg:
            err = (msg or {}).get("error", {})
            raise GatewayError(f"tool call failed: {err.get('message', 'no response')}"[:300])
        result = msg.get("result", {})
        text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        if result.get("isError"):
            # Policy denials arrive here, e.g. "No policy applies to the request (denied by default)."
            return {"error": text[:500] or "tool call was refused"}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"data": text}


def _supported_versions(r: httpx.Response) -> list[str]:
    """The versions a gateway lists when it refuses ours: error.data.supported."""
    try:
        data = (r.json().get("error") or {}).get("data") or {}
        return [str(v) for v in data.get("supported") or []]
    except Exception:  # noqa: BLE001 - not JSON
        return []


def _parse_response(r: httpx.Response) -> dict:
    ctype = r.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        last = None
        for line in r.text.splitlines():
            if line.startswith("data:"):
                try:
                    last = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        if last is None:
            raise GatewayError("empty event stream from gateway")
        return last
    return r.json()
