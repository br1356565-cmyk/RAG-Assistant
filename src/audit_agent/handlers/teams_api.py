"""Team management API (dashboard), routed from the chat function under /api/teams.

  GET  teams                 teams you can see: members, repos/URLs, rules, settings, counts;
                             admins also get the unowned repos
  POST teams/create          {name, id?}                                   admins
  POST teams/update          {team_id, name?, archived?, entra_group_id?}  admins
  POST teams/member          {team_id, email, role?: member|lead, remove?} admins; leads (members only)
  POST teams/asset           {team_id, kind: repo|url, value, remove?}     admins (moves findings now)
  POST teams/assign          {repos: [..], team_id}                        admins (bulk, unowned queue)
  POST teams/rule            {team_id, kind: topic|name_prefix|name_contains, value, remove?}  admins
  POST teams/settings        {team_id, email_digest?, slack_webhook?, jira_enabled?, jira_project?,
                              jira_issue_type?, jira_assignee?, sla_days?}  admins; the team's leads

Row-level security decides who may write; a refused write is a 403.
"""
from __future__ import annotations

import psycopg

from .. import teams as T
from ..db import Scope

MAX_BULK = 200


def _run(deps, scope: Scope, fn, *args, **kw):
    try:
        with deps.db.scoped(scope) as conn:
            out = fn(conn, scope, *args, **kw)
        return 200, {"ok": True, **(out if isinstance(out, dict) else {})}
    except T.TeamError as exc:
        return 400, {"error": str(exc)}
    except (PermissionError, psycopg.errors.InsufficientPrivilege):
        return 403, {"error": "you can't make that change (admins manage teams; leads manage their own team's "
                              "members and notifications)"}
    except psycopg.errors.CheckViolation as exc:
        return 400, {"error": f"invalid value: {exc.diag.constraint_name or 'check failed'}"}


def _admin_only(scope: Scope):
    if not scope.is_admin:
        return 403, {"error": "only security admins can do that"}
    return None


def _flag(body: dict, key: str) -> bool:
    v = body.get(key, False)
    return v is True or str(v).lower() in ("1", "true", "yes")


def list_teams(deps, scope: Scope, body: dict):
    with deps.db.scoped(scope) as conn:
        return 200, T.overview(conn, scope)


def create(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, lambda c, s: {"team_id": T.create_team(c, s, body.get("name"), body.get("id") or None)})


def update(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    archived = None if "archived" not in body else _flag(body, "archived")
    return _run(deps, scope, T.update_team, str(body.get("team_id", "")), body.get("name"), archived,
                body.get("entra_group_id"))


def member(deps, scope: Scope, body: dict):
    return _run(deps, scope, T.set_member, str(body.get("team_id", "")), body.get("email"),
                str(body.get("role") or "member"), _flag(body, "remove"))


def asset(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, T.set_asset, str(body.get("team_id", "")), str(body.get("kind", "")),
                body.get("value"), _flag(body, "remove"))


def assign(deps, scope: Scope, body: dict):
    """Bulk-assign repos (the unowned queue) in one transaction."""
    if (denied := _admin_only(scope)):
        return denied
    repos = body.get("repos")
    if not isinstance(repos, list) or not 1 <= len(repos) <= MAX_BULK:
        return 400, {"error": f"repos must be a list of 1 to {MAX_BULK} names"}

    def go(conn, s):
        moved = sum(T.set_asset(conn, s, str(body.get("team_id", "")), "repo", r)["findings_moved"] for r in repos)
        return {"assigned": len(repos), "findings_moved": moved}
    return _run(deps, scope, go)


def rule(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, T.set_rule, str(body.get("team_id", "")), str(body.get("kind", "")),
                body.get("value"), _flag(body, "remove"))


def settings(deps, scope: Scope, body: dict):
    return _run(deps, scope, T.set_settings, str(body.get("team_id", "")), body)


ROUTES = {
    ("GET", "teams"): list_teams,
    ("POST", "teams/create"): create,
    ("POST", "teams/update"): update,
    ("POST", "teams/member"): member,
    ("POST", "teams/asset"): asset,
    ("POST", "teams/assign"): assign,
    ("POST", "teams/rule"): rule,
    ("POST", "teams/settings"): settings,
}
