"""Entra ID token verification and mapping a user to teams and a role.

App roles (defined on the Entra app registration):
  security.admin -> sees every team, admin-only findings and unowned repos
  team.lead      -> own teams; can later approve notes in the UI
  (none)         -> team member
Team membership comes from the token's `groups` claim. In the company tenant, configure it
as "groups assigned to the application" so it never overflows (assigning groups to an app
needs Entra ID P1). A free demo tenant uses "Security groups"; overage (200+ groups) is
rejected with a clear 403 either way.
"""
from __future__ import annotations

from dataclasses import dataclass

import jwt

from .db import Database, Scope


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401):
        super().__init__(message)
        self.status = status


class EntraVerifier:
    def __init__(self, tenant_id: str, audience: str, jwks_client: jwt.PyJWKClient | None = None):
        self.audience = audience
        self.issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        self.jwks = jwks_client or jwt.PyJWKClient(
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys", cache_keys=True
        )

    def verify(self, token: str) -> dict:
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token, key, algorithms=["RS256"], audience=self.audience, issuer=self.issuer,
                options={"require": ["exp", "iat", "oid"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc}") from exc


def bearer_token(headers: dict) -> str:
    """Read the user's token.

    Behind CloudFront with origin access control, CloudFront signs the request to the
    Lambda function URL and overwrites `Authorization`, so the web app sends the user's
    token in `x-user-authorization` instead. `authorization` is the fallback for direct calls.
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    raw = h.get("x-user-authorization") or h.get("authorization") or ""
    if not raw.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    return raw[7:].strip()


def resolve_scope(claims: dict, db: Database) -> Scope:
    if "_claim_names" in claims and "groups" in claims.get("_claim_names", {}):
        raise AuthError(
            "group overage: configure the app registration to emit only groups assigned to the application",
            status=403,
        )
    roles = set(claims.get("roles") or [])
    groups = list(claims.get("groups") or [])
    user_id = claims["oid"]

    with db.scoped(Scope(user_id=user_id, team_ids=(), role="none")) as conn:
        rows = conn.execute(
            "select id, name from teams where entra_group_id = any(%s) order by id", (groups,)
        ).fetchall()
    team_ids = tuple(r["id"] for r in rows)
    names = {r["id"]: r["name"] for r in rows}

    if "security.admin" in roles:
        role = "security_admin"
    elif not team_ids:
        raise AuthError("you are not in any team that uses the audit agent", status=403)
    elif "team.lead" in roles:
        role = "team_lead"
    else:
        role = "team_member"
    return Scope(user_id=user_id, team_ids=team_ids, role=role, team_names=names)
