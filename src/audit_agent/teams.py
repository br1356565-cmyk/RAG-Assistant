"""Dashboard-managed teams: membership, owned repos/URLs, ownership rules, delivery settings.

The database is the source of truth. ownership.yml and Entra groups still seed teams and
memberships (source = 'config'), but anything an admin changes in the dashboard wins and
takes effect immediately:

  * whose repo is this:  team_assets (explicit)  >  team_rules  >  ownership.yml
  * who is in a team:    team_members by e-mail  +  legacy Entra group mapping
  * moving a repo/URL re-teams its findings at once (no wait for the weekly run)

Authorization is row-level security (schema.sql); this module validates input and keeps
the writes together.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

TEAM_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
RULE_RE = re.compile(r"^[a-z0-9._-]{1,100}$")
JIRA_PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,19}$")
SLACK_RE = re.compile(r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+$")
RULE_KINDS = ("topic", "name_prefix", "name_contains")
ASSET_KINDS = ("repo", "url")
MEMBER_ROLES = ("member", "lead")
SLA_SEVERITIES = ("critical", "high")
# Findings whose resource is a repo name (not an AWS account, user or URL).
NON_REPO_SOURCES = ("guardduty", "security_hub", "securityhub", "dast", "vpn_inactive")


class TeamError(ValueError):
    """Bad input; the API answers 400 with the message."""


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if s and not s[0].isalpha():
        s = "t_" + s
    return s[:40]


def norm_email(raw: str) -> str:
    e = str(raw or "").strip().lower()
    if not EMAIL_RE.fullmatch(e) or len(e) > 254:
        raise TeamError(f"not an e-mail address: {raw!r}")
    return e


def norm_url(raw: str) -> str:
    u = str(raw or "").strip()
    parts = urlsplit(u)
    if parts.scheme not in ("http", "https") or not parts.netloc or " " in u or len(u) > 300:
        raise TeamError(f"not an http(s) URL: {raw!r}")
    host = parts.hostname or ""
    if host in ("localhost",) or host.startswith(("127.", "10.", "192.168.", "169.254.")) or host.endswith(".internal"):
        raise TeamError("private or internal addresses can't be DAST targets")
    return f"{parts.scheme}://{parts.netloc.lower()}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


def email_from_claims(claims: dict) -> str | None:
    """The sign-in e-mail: `email`, else the UPN in `preferred_username` / `upn`."""
    for k in ("email", "preferred_username", "upn"):
        v = str(claims.get(k) or "").strip().lower()
        if EMAIL_RE.fullmatch(v):
            return v
    return None


# ── Sign-in ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Membership:
    team_ids: tuple[str, ...]
    names: dict[str, str]
    lead_of: frozenset[str]


def memberships(conn, email: str | None, groups: list[str]) -> Membership:
    rows: dict[str, tuple[str, str]] = {}
    if email:
        for r in conn.execute("select team_id, team_name, role from memberships_for(%s)", (email,)).fetchall():
            rows[r["team_id"]] = (r["team_name"], r["role"])
    if groups:
        for r in conn.execute("select id, name from teams where entra_group_id = any(%s) and archived_at is null",
                              (groups,)).fetchall():
            rows.setdefault(r["id"], (r["name"], "member"))
    ids = tuple(sorted(rows))
    return Membership(ids, {t: rows[t][0] for t in ids}, frozenset(t for t in ids if rows[t][1] == "lead"))


# ── Ownership precedence (used by ingest) ──────────────────────────────────
def load_overrides(conn) -> tuple[dict[str, str], list[dict]]:
    assets = {r["value"]: r["team_id"] for r in conn.execute(
        "select a.value, a.team_id from team_assets a join teams t on t.id = a.team_id "
        "where a.kind = 'repo' and t.archived_at is null").fetchall()}
    rules = [dict(r) for r in conn.execute(
        "select r.team_id, r.kind, r.value from team_rules r join teams t on t.id = r.team_id "
        "where t.archived_at is null order by r.id").fetchall()]
    return assets, rules


def apply_overrides(repo: str, topics: set[str], yaml_owner: dict, assets: dict[str, str],
                    rules: list[dict]) -> dict:
    """-> {"team_id", "source", "confidence"}: dashboard assignment, dashboard rule, else YAML."""
    if repo in assets:
        return {"team_id": assets[repo], "source": "dashboard", "confidence": "confirmed"}
    n = repo.lower()
    for r in rules:
        v = r["value"]
        hit = (r["kind"] == "topic" and v in topics) or (r["kind"] == "name_prefix" and n.startswith(v)) \
            or (r["kind"] == "name_contains" and v in n)
        if hit:
            return {"team_id": r["team_id"], "source": f"dashboard rule: {r['kind']} {v}", "confidence": "likely"}
    return {k: yaml_owner.get(k) for k in ("team_id", "source", "confidence")}


def dast_targets(conn) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "select a.value as url, a.team_id from team_assets a join teams t on t.id = a.team_id "
        "where a.kind = 'url' and t.archived_at is null order by a.value").fetchall()]


# ── Dashboard reads ────────────────────────────────────────────────────────
def overview(conn, scope) -> dict:
    """Teams the caller can see with members, assets, rules and settings (webhook masked)."""
    teams = conn.execute(
        "select id, name, source, archived_at, entra_group_id from teams "
        + ("" if scope.is_admin else "where id = any(%s) ") + "order by archived_at nulls first, name",
        () if scope.is_admin else (list(scope.team_ids),)).fetchall()
    ids = [t["id"] for t in teams]
    by = lambda sql: _group(conn.execute(sql, (ids,)).fetchall())  # noqa: E731
    members = by("select team_id, email, role, added_by, added_at from team_members where team_id = any(%s) "
                 "order by role desc, email")
    assets = by("select team_id, kind, value, added_by, added_at from team_assets where team_id = any(%s) "
                "order by kind, value")
    rules = by("select team_id, id, kind, value from team_rules where team_id = any(%s) order by id")
    settings = {r["team_id"]: r for r in conn.execute(
        "select * from team_settings where team_id = any(%s)", (ids,)).fetchall()}
    repos = by("select team_id, repo, source from repo_owners where team_id = any(%s) order by repo")
    counts = {r["team_id"]: r for r in conn.execute(
        "select team_id, count(*) filter (where severity in ('critical','high')) as high, count(*) as open "
        "from findings where status = 'open' and team_id = any(%s) group by team_id", (ids,)).fetchall()}
    tickets = {r["team_id"]: r["n"] for r in conn.execute(
        "select team_id, count(*) n from jira_tickets where status = 'open' and team_id = any(%s) group by 1",
        (ids,)).fetchall()}
    out = []
    for t in teams:
        tid = t["id"]
        s = settings.get(tid) or {}
        out.append({
            "id": tid, "name": t["name"], "source": t["source"], "archived": t["archived_at"] is not None,
            "entra_group_id": t["entra_group_id"],
            "can_manage": scope.is_admin or (tid in scope.team_ids and scope.role == "team_lead"),
            "members": [{"email": m["email"], "role": m["role"], "added_by": m["added_by"]} for m in members.get(tid, [])],
            "assets": [{"kind": a["kind"], "value": a["value"]} for a in assets.get(tid, [])],
            "rules": [{"id": r["id"], "kind": r["kind"], "value": r["value"]} for r in rules.get(tid, [])],
            "repos": [{"repo": r["repo"], "source": r["source"]} for r in repos.get(tid, [])],
            "open": (counts.get(tid) or {}).get("open", 0), "open_high": (counts.get(tid) or {}).get("high", 0),
            "jira_open": tickets.get(tid, 0),
            "settings": {
                "email_digest": s.get("email_digest", True),
                "slack": bool(s.get("slack_webhook")),
                "slack_hint": _mask(s.get("slack_webhook")),
                "jira_enabled": s.get("jira_enabled", False), "jira_project": s.get("jira_project"),
                "jira_issue_type": s.get("jira_issue_type", "Bug"), "jira_assignee": s.get("jira_assignee"),
                "sla_days": s.get("sla_days") or {"critical": 7, "high": 30},
            },
        })
    unowned = []
    if scope.is_admin:
        unowned = [r["repo"] for r in conn.execute(
            "select repo from repo_owners where team_id is null order by repo limit 500").fetchall()]
    return {"is_admin": scope.is_admin, "teams": out, "unowned_repos": unowned}


def _group(rows) -> dict[str, list]:
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r["team_id"], []).append(r)
    return out


def _mask(url: str | None) -> str | None:
    return None if not url else url[:34] + "…" + url[-4:]


# ── Dashboard writes ───────────────────────────────────────────────────────
def _log(conn, scope, team_id, action, detail) -> None:
    conn.execute("insert into team_changes (team_id, actor, action, detail) values (%s,%s,%s,%s)",
                 (team_id, scope.user_id, action, json.dumps(detail)))


def _team_exists(conn, team_id: str) -> None:
    if not conn.execute("select 1 from teams where id = %s", (team_id,)).fetchone():
        raise TeamError(f"unknown team {team_id!r}")


def create_team(conn, scope, name: str, team_id: str | None = None) -> str:
    name = str(name or "").strip()
    if not 2 <= len(name) <= 80:
        raise TeamError("team name must be 2 to 80 characters")
    tid = team_id or slug(name)
    if not TEAM_ID_RE.fullmatch(tid or ""):
        raise TeamError("team id must be lowercase letters, digits and _ (2-40), starting with a letter")
    if conn.execute("select 1 from teams where id = %s", (tid,)).fetchone():
        raise TeamError(f"a team with id {tid!r} already exists")
    conn.execute("insert into teams (id, name, source, created_by) values (%s, %s, 'dashboard', %s)",
                 (tid, name, scope.user_id))
    conn.execute("insert into team_settings (team_id, updated_by) values (%s, %s)", (tid, scope.user_id))
    _log(conn, scope, tid, "create_team", {"name": name})
    return tid


def update_team(conn, scope, team_id: str, name: str | None = None, archived: bool | None = None,
                entra_group_id: str | None = None) -> None:
    _team_exists(conn, team_id)
    sets, params = ["source = 'dashboard'"], []
    if name is not None:
        name = str(name).strip()
        if not 2 <= len(name) <= 80:
            raise TeamError("team name must be 2 to 80 characters")
        sets.append("name = %s"); params.append(name)
    if archived is not None:
        sets.append("archived_at = " + ("now()" if archived else "null"))
    if entra_group_id is not None:
        sets.append("entra_group_id = %s"); params.append(str(entra_group_id).strip() or None)
    cur = conn.execute(f"update teams set {', '.join(sets)} where id = %s", (*params, team_id))
    if cur.rowcount == 0:
        raise PermissionError("only security admins can change teams")
    _log(conn, scope, team_id, "update_team", {"name": name, "archived": archived})


def set_member(conn, scope, team_id: str, email: str, role: str = "member", remove: bool = False) -> None:
    _team_exists(conn, team_id)
    email = norm_email(email)
    if role not in MEMBER_ROLES:
        raise TeamError("role must be member or lead")
    if remove:
        cur = conn.execute("delete from team_members where team_id = %s and email = %s", (team_id, email))
        if cur.rowcount == 0 and not conn.execute(
                "select 1 from team_members where team_id = %s and email = %s", (team_id, email)).fetchone():
            raise TeamError(f"{email} is not in this team")
        if cur.rowcount == 0:
            raise PermissionError("leads can remove members; only admins remove leads")
    else:
        conn.execute(
            "insert into team_members (team_id, email, role, added_by) values (%s, %s, %s, %s) "
            "on conflict (team_id, email) do update set role = excluded.role",
            (team_id, email, role, scope.user_id))
    _log(conn, scope, team_id, "remove_member" if remove else "set_member", {"email": email, "role": role})


def set_asset(conn, scope, team_id: str, kind: str, value: str, remove: bool = False) -> dict:
    """Assign (or unassign) a repo or URL. Its open findings move with it right away."""
    if kind not in ASSET_KINDS:
        raise TeamError("kind must be repo or url")
    value = norm_url(value) if kind == "url" else str(value or "").strip()
    if kind == "repo" and not REPO_RE.fullmatch(value):
        raise TeamError(f"not a repository name: {value!r}")
    _team_exists(conn, team_id)
    if remove:
        conn.execute("delete from team_assets where kind = %s and value = %s and team_id = %s", (kind, value, team_id))
        new_team = None
    else:
        conn.execute(
            "insert into team_assets (kind, value, team_id, added_by) values (%s, %s, %s, %s) "
            "on conflict (kind, value) do update set team_id = excluded.team_id, added_by = excluded.added_by, "
            "added_at = now()", (kind, value, team_id, scope.user_id))
        new_team = team_id
    moved = 0
    if kind == "repo":
        if new_team:
            conn.execute(
                "insert into repo_owners (repo, team_id, source, confidence, approved_by, updated_at) "
                "values (%s, %s, 'dashboard', 'confirmed', %s, now()) on conflict (repo) do update set "
                "team_id = excluded.team_id, source = excluded.source, confidence = excluded.confidence, "
                "approved_by = excluded.approved_by, updated_at = now()", (value, new_team, scope.user_id))
            moved = conn.execute(
                "update findings set team_id = %s where resource = %s and status <> 'fixed' "
                "and not (source = any(%s)) and team_id is distinct from %s",
                (new_team, value, list(NON_REPO_SOURCES), new_team)).rowcount
        # Unassigning keeps the current owner until the next run recomputes it from the rules.
    elif new_team:
        moved = conn.execute(
            "update findings set team_id = %s where source = 'dast' and resource = %s and status <> 'fixed' "
            "and team_id is distinct from %s", (new_team, value, new_team)).rowcount
    _log(conn, scope, team_id, "remove_asset" if remove else "set_asset", {"kind": kind, "value": value, "moved": moved})
    return {"kind": kind, "value": value, "team_id": new_team, "findings_moved": moved}


def set_rule(conn, scope, team_id: str, kind: str, value: str, remove: bool = False) -> None:
    if kind not in RULE_KINDS:
        raise TeamError(f"rule kind must be one of {', '.join(RULE_KINDS)}")
    value = str(value or "").strip().lower()
    if not RULE_RE.fullmatch(value):
        raise TeamError("rule value must be lowercase letters, digits, . _ or - (1-100)")
    _team_exists(conn, team_id)
    if remove:
        conn.execute("delete from team_rules where team_id = %s and kind = %s and value = %s", (team_id, kind, value))
    else:
        conn.execute("insert into team_rules (team_id, kind, value, added_by) values (%s,%s,%s,%s) "
                     "on conflict (kind, value) do update set team_id = excluded.team_id",
                     (team_id, kind, value, scope.user_id))
    _log(conn, scope, team_id, "remove_rule" if remove else "set_rule", {"kind": kind, "value": value})


def set_settings(conn, scope, team_id: str, body: dict) -> None:
    _team_exists(conn, team_id)
    cur = dict(conn.execute("select * from team_settings where team_id = %s", (team_id,)).fetchone() or {})
    new = {
        "email_digest": bool(body.get("email_digest", cur.get("email_digest", True))),
        "jira_enabled": bool(body.get("jira_enabled", cur.get("jira_enabled", False))),
        "jira_project": cur.get("jira_project"), "jira_issue_type": cur.get("jira_issue_type") or "Bug",
        "jira_assignee": cur.get("jira_assignee"), "slack_webhook": cur.get("slack_webhook"),
        "sla_days": cur.get("sla_days") or {"critical": 7, "high": 30},
    }
    if "slack_webhook" in body:          # "" clears it; omitted keeps it (the UI never sees the value)
        hook = str(body["slack_webhook"] or "").strip()
        if hook and not SLACK_RE.fullmatch(hook):
            raise TeamError("Slack webhook must be an https://hooks.slack.com/services/... URL")
        new["slack_webhook"] = hook or None
    if "jira_project" in body:
        p = str(body["jira_project"] or "").strip().upper()
        if p and not JIRA_PROJECT_RE.fullmatch(p):
            raise TeamError("Jira project key looks like OPS or PLAT_SEC")
        new["jira_project"] = p or None
    if "jira_issue_type" in body:
        it = str(body["jira_issue_type"] or "Bug").strip()
        if not 1 <= len(it) <= 40:
            raise TeamError("Jira issue type is 1 to 40 characters")
        new["jira_issue_type"] = it
    if "jira_assignee" in body:
        a = str(body["jira_assignee"] or "").strip()
        new["jira_assignee"] = norm_email(a) if a else None
    if "sla_days" in body:
        sla = body["sla_days"] or {}
        if not isinstance(sla, dict) or set(sla) - set(SLA_SEVERITIES):
            raise TeamError("sla_days is {\"critical\": days, \"high\": days}")
        clean = {}
        for k, v in sla.items():
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 365:
                raise TeamError("SLA days must be whole numbers from 1 to 365")
            clean[k] = v
        new["sla_days"] = {**new["sla_days"], **clean}
    if new["jira_enabled"] and not new["jira_project"]:
        raise TeamError("set a Jira project key before turning Jira on")
    cols = list(new)
    conn.execute(
        f"insert into team_settings (team_id, {', '.join(cols)}, updated_by, updated_at) values "
        f"(%s, {', '.join(['%s'] * len(cols))}, %s, now()) on conflict (team_id) do update set "
        + ", ".join(f"{c} = excluded.{c}" for c in cols) + ", updated_by = excluded.updated_by, updated_at = now()",
        (team_id, *[json.dumps(new[c]) if c == "sla_days" else new[c] for c in cols], scope.user_id))
    _log(conn, scope, team_id, "settings", {k: (bool(v) if k == "slack_webhook" else v) for k, v in new.items()})
