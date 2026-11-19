"""Entra ID token verification and mapping a user to teams and a role.

App roles (defined on the Entra app registration):
  security.admin -> sees every team, admin-only findings and unowned repos
  team.lead      -> own teams; can later approve notes in the UI
  (none)         -> team member
Team membership is managed in the dashboard (team_members, by the token's e-mail/UPN), so
adding someone to a team needs no Entra change and no deploy. The token's `groups` claim
still counts for teams that have an entra_group_id (the legacy mapping). A user is a team
lead if they have the Entra team.lead role, or are a lead in every team they belong to
(a lead of one team who is a plain member of another gets member rights, never more).
Group overage (200+ groups) is rejected with a clear 403.
"""
from __future__ import annotations


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
    from .teams import email_from_claims, memberships

    if "_claim_names" in claims and "groups" in claims.get("_claim_names", {}):
        raise AuthError(
            "group overage: configure the app registration to emit only groups assigned to the application",
            status=403,
        )
    roles = set(claims.get("roles") or [])
    groups = list(claims.get("groups") or [])
    user_id = claims["oid"]

    with db.scoped(Scope(user_id=user_id, team_ids=(), role="none")) as conn:
        m = memberships(conn, email_from_claims(claims), groups)
    team_ids = m.team_ids

    if "security.admin" in roles:
        role = "security_admin"
    elif not team_ids:
        raise AuthError("you are not in any team that uses the audit agent; ask a security admin to add you",
                        status=403)
    elif "team.lead" in roles or (m.lead_of and m.lead_of == frozenset(team_ids)):
        role = "team_lead"
    else:
        role = "team_member"
    return Scope(user_id=user_id, team_ids=team_ids, role=role, team_names=m.names)
