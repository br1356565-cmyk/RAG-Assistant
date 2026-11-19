"""Team management API (dashboard), routed from the chat function under /api/teams.
Built for hundreds of repos: a light team list, one team's detail on demand, and a
paginated, filterable repo inventory with bulk actions.

  GET  teams                   team list with counts (+ repos_total / unowned for admins)
  GET  teams/detail            ?team_id   members, URLs, rules, settings, recent activity
  GET  teams/repos             ?q&team(=id|unowned)&source(=dashboard|rule|config|unowned)
                               &has_findings&sort(=repo|team|open|high)&page&size
  GET  teams/repos/export      every visible repo with owner and counts (for CSV)
  GET  teams/rule-preview      ?kind&value   which repos a rule would match / change
  GET  teams/activity          ?team_id?     who changed what
  POST teams/create            {name, id?}                                   admins
  POST teams/update            {team_id, name?, archived?, entra_group_id?}  admins
  POST teams/member            {team_id, email, role?, remove?}              admins; leads (members)
  POST teams/members           {team_id, emails: "a@x, b@y ...", role?}      admins; leads (members)
  POST teams/asset             {team_id, kind: repo|url, value, remove?}     admins (moves findings now)
  POST teams/assign            {team_id, repos: [..]} | {team_id, filter: {q, team, source, has_findings}}  admins
  POST teams/unpin             {repos: [..]} | {filter: {...}}               admins
  POST teams/rule              {team_id, kind, value, remove?, apply_now?}   admins
  POST teams/import            {text: "repo,team" lines}                     admins
  POST teams/settings          {team_id, email_digest?, slack_webhook?, jira_*?, sla_days?}  admins; leads

Row-level security decides who may write; a refused write is a 403.
"""
from __future__ import annotations

import psycopg

from .. import teams as T
from ..db import Scope


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


def _read(deps, scope: Scope, fn, *args, **kw):
    try:
        with deps.db.scoped(scope) as conn:
            return 200, fn(conn, scope, *args, **kw)
    except T.TeamError as exc:
        return 400, {"error": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": f"bad parameter: {exc}"}


def _admin_only(scope: Scope):
    if not scope.is_admin:
        return 403, {"error": "only security admins can do that"}
    return None


def _flag(body: dict, key: str) -> bool:
    v = body.get(key, False)
    return v is True or str(v).lower() in ("1", "true", "yes")


def _filter(body: dict) -> dict:
    return {"q": str(body.get("q") or ""), "team": str(body.get("team") or ""),
            "source": str(body.get("source") or ""), "has_findings": _flag(body, "has_findings")}


def _targets(conn, scope, body: dict) -> list[str]:
    if isinstance(body.get("filter"), dict):
        return T.matching_repos(conn, scope, **_filter(body["filter"]))
    repos = body.get("repos")
    if not isinstance(repos, list):
        raise T.TeamError("send repos: [...] or filter: {...}")
    return repos


# ── reads ──────────────────────────────────────────────────────────────────
def list_teams(deps, scope: Scope, body: dict):
    return _read(deps, scope, T.summary)


def team_detail(deps, scope: Scope, body: dict):
    return _read(deps, scope, T.detail, str(body.get("team_id", "")))


def repos(deps, scope: Scope, body: dict):
    return _read(deps, scope, T.list_repos, **_filter(body), page=int(body.get("page") or 1),
                 size=int(body.get("size") or 50), sort=str(body.get("sort") or "repo"))


def repos_export(deps, scope: Scope, body: dict):
    return _read(deps, scope, lambda c, s: {"repos": T.export_repos(c, s)})


def rule_preview(deps, scope: Scope, body: dict):
    def go(conn, s):
        out = T.rule_matches(conn, str(body.get("kind", "")), body.get("value"))
        out.pop("_changeable", None)
        return out
    return _read(deps, scope, go)


def activity(deps, scope: Scope, body: dict):
    team = str(body.get("team_id") or "") or None
    if team is None and not scope.is_admin:
        return 403, {"error": "pick a team"}
    return _read(deps, scope, lambda c, s: {"activity": T.activity(c, s, team, limit=100)})


# ── writes ─────────────────────────────────────────────────────────────────
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


def members(deps, scope: Scope, body: dict):
    return _run(deps, scope, lambda c, s: T.add_members(c, s, str(body.get("team_id", "")), body.get("emails"),
                                                       str(body.get("role") or "member")))


def asset(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, T.set_asset, str(body.get("team_id", "")), str(body.get("kind", "")),
                body.get("value"), _flag(body, "remove"))


def assign(deps, scope: Scope, body: dict):
    """Bulk-assign: a list of repos, or every repo matching a filter ("select all N matching")."""
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, lambda c, s: T.bulk_assign(c, s, str(body.get("team_id", "")), _targets(c, s, body)))


def unpin(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, lambda c, s: T.bulk_unpin(c, s, _targets(c, s, body)))


def rule(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    if _flag(body, "apply_now") and not _flag(body, "remove"):
        return _run(deps, scope, T.apply_rule_now, str(body.get("team_id", "")), str(body.get("kind", "")),
                    body.get("value"))
    return _run(deps, scope, T.set_rule, str(body.get("team_id", "")), str(body.get("kind", "")),
                body.get("value"), _flag(body, "remove"))


def import_csv(deps, scope: Scope, body: dict):
    if (denied := _admin_only(scope)):
        return denied
    return _run(deps, scope, lambda c, s: T.import_ownership(c, s, body.get("text")))


def settings(deps, scope: Scope, body: dict):
    return _run(deps, scope, T.set_settings, str(body.get("team_id", "")), body)


ROUTES = {
    ("GET", "teams"): list_teams,
    ("GET", "teams/detail"): team_detail,
    ("GET", "teams/repos"): repos,
    ("GET", "teams/repos/export"): repos_export,
    ("GET", "teams/rule-preview"): rule_preview,
    ("GET", "teams/activity"): activity,
    ("POST", "teams/create"): create,
    ("POST", "teams/update"): update,
    ("POST", "teams/member"): member,
    ("POST", "teams/members"): members,
    ("POST", "teams/asset"): asset,
    ("POST", "teams/assign"): assign,
    ("POST", "teams/unpin"): unpin,
    ("POST", "teams/rule"): rule,
    ("POST", "teams/import"): import_csv,
    ("POST", "teams/settings"): settings,
}
