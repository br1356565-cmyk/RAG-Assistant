"""Signed scope tokens for remote tools.

Tools behind AgentCore Gateway run in their own Lambda. They must enforce the same scope
(user, teams, role) as in-process tools, and must not trust anything the model wrote. The
harness signs a short-lived token for every remote call and adds it to the arguments AFTER
the model has chosen the call; the model never sees it. The tool verifies the signature and
expiry and rebuilds the Scope from it.

Format: base64url(json payload) + "." + base64url(HMAC-SHA256(payload, key)).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from .db import Scope

DEFAULT_TTL_S = 300


class ScopeTokenError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(scope: Scope, key: bytes, ttl_s: int = DEFAULT_TTL_S, now: float | None = None, **extra) -> str:
    if len(key) < 32:
        raise ValueError("scope signing key must be at least 32 bytes")
    payload = {"u": scope.user_id, "t": list(scope.team_ids), "r": scope.role,
               "exp": int((now or time.time()) + ttl_s), **extra}
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    mac = hmac.new(key, body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(mac)}"


def verify(token: str, key: bytes, now: float | None = None) -> tuple[Scope, dict]:
    """-> (scope, full payload). Raises ScopeTokenError on any problem."""
    try:
        body, mac = token.split(".")
        expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(mac)):
            raise ScopeTokenError("bad signature")
        payload = json.loads(_unb64(body))
    except ScopeTokenError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ScopeTokenError("malformed scope token") from exc
    if payload.get("exp", 0) < (now or time.time()):
        raise ScopeTokenError("scope token expired")
    try:
        scope = Scope(user_id=str(payload["u"]), team_ids=tuple(payload["t"]), role=str(payload["r"]))
    except (KeyError, ValueError) as exc:
        raise ScopeTokenError("invalid scope in token") from exc
    return scope, payload
