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
# Built for hundreds of repos and dozens of teams: a light team list, one team's detail on
# demand, and a paginated, filterable repo inventory instead of everything in one payload.
REPO_SOURCES = {
    "dashboard": "o.source = 'dashboard'",
    "rule": "o.source like 'dashboard rule:%%'",
    "config": "o.team_id is not null and o.source not like 'dashboard%%'",
    "unowned": "o.team_id is null",
}
REPO_SORTS = {"repo": "o.repo", "team": "t.name nulls first, o.repo", "open": "open desc, o.repo",
              "high": "high desc, open desc, o.repo"}
MAX_PAGE = 200
MAX_BULK = 2000
FINDING_COUNTS = ("(select resource, count(*) as open, count(*) filter (where severity in ('critical','high')) as high "
                  "from findings where status = 'open' and data_class = 'team' group by resource)")


def summary(conn, scope) -> dict:
    """Every team the caller can see, with counts only."""
    teams = conn.execute(
        "select t.id, t.name, t.source, t.archived_at is not null as archived, "
        " (select count(*) from team_members m where m.team_id = t.id) as members, "
        " (select count(*) from team_members m where m.team_id = t.id and m.role = 'lead') as leads, "
        " (select count(*) from repo_owners o where o.team_id = t.id) as repos, "
        " (select count(*) from team_assets a where a.team_id = t.id and a.kind = 'url') as urls, "
        " (select count(*) from team_rules r where r.team_id = t.id) as rules, "
        " (select count(*) from findings f where f.team_id = t.id and f.status = 'open' and f.data_class = 'team') as open, "
        " (select count(*) from findings f where f.team_id = t.id and f.status = 'open' and f.data_class = 'team' "
        "   and f.severity in ('critical','high')) as high, "
        " (select count(*) from jira_tickets j where j.team_id = t.id and j.status = 'open') as jira_open "
        "from teams t " + ("" if scope.is_admin else "where t.id = any(%s) ")
        + "order by t.archived_at is not null, t.name",
        () if scope.is_admin else (list(scope.team_ids),)).fetchall()
    out = {"is_admin": scope.is_admin, "teams": [dict(t, can_manage=_can_manage(scope, t["id"])) for t in teams]}
    if scope.is_admin:
        out["repos_total"] = conn.execute("select count(*) n from repo_owners").fetchone()["n"]
        out["unowned"] = conn.execute("select count(*) n from repo_owners where team_id is null").fetchone()["n"]
    return out


def _can_manage(scope, team_id: str) -> bool:
    return scope.is_admin or (team_id in scope.team_ids and scope.role == "team_lead")


def detail(conn, scope, team_id: str) -> dict:
    if not scope.is_admin and team_id not in scope.team_ids:
        raise TeamError("no such team in your scope")
    t = conn.execute("select id, name, source, archived_at, entra_group_id from teams where id = %s", (team_id,)).fetchone()
    if not t:
        raise TeamError("no such team in your scope")
    s = conn.execute("select * from team_settings where team_id = %s", (team_id,)).fetchone() or {}
    return {
        "id": t["id"], "name": t["name"], "source": t["source"], "archived": t["archived_at"] is not None,
        "entra_group_id": t["entra_group_id"], "can_manage": _can_manage(scope, team_id), "is_admin": scope.is_admin,
        "members": [dict(r) for r in conn.execute(
            "select email, role, added_by, added_at from team_members where team_id = %s order by role = 'lead' desc, email",
            (team_id,)).fetchall()],
        "urls": [dict(r) for r in conn.execute(
            "select a.value as url, a.added_by, a.added_at, "
            " (select count(*) from findings f where f.source = 'dast' and f.resource = a.value and f.status = 'open') as open "
            "from team_assets a where a.team_id = %s and a.kind = 'url' order by a.value", (team_id,)).fetchall()],
        "rules": [dict(r) for r in conn.execute(
            "select id, kind, value, added_by, added_at from team_rules where team_id = %s order by id", (team_id,)).fetchall()],
        "pinned_repos": conn.execute("select count(*) n from team_assets where team_id = %s and kind = 'repo'",
                                     (team_id,)).fetchone()["n"],
        "settings": {
            "email_digest": s.get("email_digest", True), "slack": bool(s.get("slack_webhook")),
            "slack_hint": _mask(s.get("slack_webhook")), "jira_enabled": s.get("jira_enabled", False),
            "jira_project": s.get("jira_project"), "jira_issue_type": s.get("jira_issue_type", "Bug"),
            "jira_assignee": s.get("jira_assignee"), "sla_days": s.get("sla_days") or {"critical": 7, "high": 30},
        },
        "activity": activity(conn, scope, team_id, limit=25),
    }


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _repo_filter(scope, q: str = "", team: str = "", source: str = "", has_findings: bool = False):
    where, params = [], []
    if not scope.is_admin:
        where.append("o.team_id = any(%s)"); params.append(list(scope.team_ids))
    q = str(q or "").strip()[:100]
    if q:
        where.append("(o.repo ilike %s or %s = any(o.topics))"); params += [_like(q), q.lower()]
    if team == "unowned":
        where.append("o.team_id is null")
    elif team:
        where.append("o.team_id = %s"); params.append(team)
    if source:
        if source not in REPO_SOURCES:
            raise TeamError(f"source must be one of {', '.join(REPO_SOURCES)}")
        where.append(REPO_SOURCES[source])
    if has_findings:
        where.append("coalesce(f.open, 0) > 0")
    base = (f"from repo_owners o left join teams t on t.id = o.team_id left join {FINDING_COUNTS} f "
            f"on f.resource = o.repo " + ("where " + " and ".join(where) if where else ""))
    return base, params


def list_repos(conn, scope, q: str = "", team: str = "", source: str = "", has_findings: bool = False,
               page: int = 1, size: int = 50, sort: str = "repo") -> dict:
    size = max(1, min(int(size or 50), MAX_PAGE))
    page = max(1, int(page or 1))
    if sort not in REPO_SORTS:
        raise TeamError(f"sort must be one of {', '.join(REPO_SORTS)}")
    base, params = _repo_filter(scope, q, team, source, has_findings)
    total = conn.execute(f"select count(*) as n {base}", params).fetchone()["n"]
    rows = conn.execute(
        f"select o.repo, o.team_id, t.name as team_name, o.source, o.topics, o.updated_at, "
        f"coalesce(f.open, 0) as open, coalesce(f.high, 0) as high, "
        f"exists (select 1 from team_assets a where a.kind = 'repo' and a.value = o.repo) as pinned "
        f"{base} order by {REPO_SORTS[sort]} limit %s offset %s", (*params, size, (page - 1) * size)).fetchall()
    return {"total": total, "page": page, "size": size, "pages": max(1, -(-total // size)),
            "repos": [dict(r, updated_at=r["updated_at"].isoformat() if r["updated_at"] else None) for r in rows]}


def matching_repos(conn, scope, q: str = "", team: str = "", source: str = "", has_findings: bool = False) -> list[str]:
    """Every repo a filter matches (for "select all N matching"), capped at MAX_BULK."""
    base, params = _repo_filter(scope, q, team, source, has_findings)
    rows = conn.execute(f"select o.repo {base} order by o.repo limit %s", (*params, MAX_BULK + 1)).fetchall()
    if len(rows) > MAX_BULK:
        raise TeamError(f"that filter matches more than {MAX_BULK} repos; narrow it down")
    return [r["repo"] for r in rows]


def export_repos(conn, scope) -> list[dict]:
    base, params = _repo_filter(scope)
    return [dict(r) for r in conn.execute(
        f"select o.repo, coalesce(o.team_id, '') as team, o.source, coalesce(f.open, 0) as open, "
        f"coalesce(f.high, 0) as high {base} order by o.repo", params).fetchall()]


def rule_matches(conn, kind: str, value: str, limit: int = 200) -> dict:
    """Which repos a rule would match, and how many would actually change owner (explicitly
    assigned repos and repos already matched by an earlier dashboard rule keep their owner)."""
    if kind not in RULE_KINDS:
        raise TeamError(f"rule kind must be one of {', '.join(RULE_KINDS)}")
    value = str(value or "").strip().lower()
    if not RULE_RE.fullmatch(value):
        raise TeamError("rule value must be lowercase letters, digits, . _ or - (1-100)")
    cond = {"topic": "%s = any(o.topics)", "name_prefix": "lower(o.repo) like %s",
            "name_contains": "lower(o.repo) like %s"}[kind]
    arg = value if kind == "topic" else (_like(value)[1:] if kind == "name_prefix" else _like(value))
    rows = conn.execute(
        f"select o.repo, o.team_id, o.source, "
        f"exists (select 1 from team_assets a where a.kind = 'repo' and a.value = o.repo) as pinned "
        f"from repo_owners o where {cond} order by o.repo", (arg,)).fetchall()
    changeable = [r for r in rows if not r["pinned"] and not str(r["source"]).startswith("dashboard")]
    return {"kind": kind, "value": value, "count": len(rows), "would_change": len(changeable),
            "repos": [dict(r) for r in rows[:limit]], "_changeable": [r["repo"] for r in changeable]}


def activity(conn, scope, team_id: str | None = None, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        "select team_id, actor, action, detail, at from team_changes "
        + ("where team_id = %s " if team_id else "") + "order by at desc limit %s",
        ((team_id, limit) if team_id else (limit,))).fetchall()
    return [dict(r, at=r["at"].isoformat()) for r in rows]


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


# ── Bulk operations (hundreds of repos at a time) ──────────────────────────
def _reteam_repo(conn, scope, repo: str, team_id: str, source: str, confidence: str) -> int:
    conn.execute(
        "insert into repo_owners (repo, team_id, source, confidence, approved_by, updated_at) "
        "values (%s, %s, %s, %s, %s, now()) on conflict (repo) do update set team_id = excluded.team_id, "
        "source = excluded.source, confidence = excluded.confidence, approved_by = excluded.approved_by, "
        "updated_at = now()", (repo, team_id, source, confidence, scope.user_id))
    return conn.execute(
        "update findings set team_id = %s where resource = %s and status <> 'fixed' and not (source = any(%s)) "
        "and team_id is distinct from %s", (team_id, repo, list(NON_REPO_SOURCES), team_id)).rowcount


def bulk_assign(conn, scope, team_id: str, repos: list[str]) -> dict:
    """Pin every repo in `repos` to `team_id`; their open findings move now."""
    _team_exists(conn, team_id)
    clean = sorted({str(r).strip() for r in repos if str(r).strip()})
    if not 1 <= len(clean) <= MAX_BULK:
        raise TeamError(f"pick 1 to {MAX_BULK} repos")
    bad = [r for r in clean if not REPO_RE.fullmatch(r)]
    if bad:
        raise TeamError(f"not repository names: {', '.join(bad[:5])}")
    moved = 0
    for r in clean:
        conn.execute("insert into team_assets (kind, value, team_id, added_by) values ('repo', %s, %s, %s) "
                     "on conflict (kind, value) do update set team_id = excluded.team_id, added_by = excluded.added_by, "
                     "added_at = now()", (r, team_id, scope.user_id))
        moved += _reteam_repo(conn, scope, r, team_id, "dashboard", "confirmed")
    _log(conn, scope, team_id, "bulk_assign", {"repos": len(clean), "sample": clean[:20], "moved": moved})
    return {"assigned": len(clean), "findings_moved": moved}


def bulk_unpin(conn, scope, repos: list[str]) -> dict:
    """Remove explicit assignments. Owners are recomputed from rules / ownership.yml on the next run."""
    clean = sorted({str(r).strip() for r in repos if str(r).strip()})
    if not 1 <= len(clean) <= MAX_BULK:
        raise TeamError(f"pick 1 to {MAX_BULK} repos")
    gone = conn.execute("delete from team_assets where kind = 'repo' and value = any(%s) returning team_id, value",
                        (clean,)).fetchall()
    conn.execute("update repo_owners set source = 'dashboard (unpinned; recomputed next run)', confidence = 'likely' "
                 "where repo = any(%s) and source = 'dashboard'", (clean,))
    for team, rows in _group([{"team_id": g["team_id"], "v": g["value"]} for g in gone]).items():
        _log(conn, scope, team, "bulk_unpin", {"repos": len(rows), "sample": [x["v"] for x in rows][:20]})
    return {"unpinned": len(gone)}


def apply_rule_now(conn, scope, team_id: str, kind: str, value: str) -> dict:
    """Save a rule and apply it at once to the repos it would change (see rule_matches)."""
    set_rule(conn, scope, team_id, kind, value)
    m = rule_matches(conn, kind, value)
    moved = 0
    for repo in m["_changeable"]:
        moved += _reteam_repo(conn, scope, repo, team_id, f"dashboard rule: {kind} {m['value']}", "likely")
    _log(conn, scope, team_id, "apply_rule", {"kind": kind, "value": m["value"], "repos": len(m["_changeable"]),
                                              "moved": moved})
    return {"matched": m["count"], "changed": len(m["_changeable"]), "findings_moved": moved}


def import_ownership(conn, scope, text: str) -> dict:
    """CSV/TSV "repo,team" lines (header optional). Valid rows are applied, bad ones reported;
    nothing is applied if more than half the rows are bad (probably the wrong file)."""
    lines = [ln for ln in str(text or "").splitlines() if ln.strip()]
    if not lines:
        raise TeamError("paste or upload lines of: repo,team")
    if len(lines) > MAX_BULK + 1:
        raise TeamError(f"at most {MAX_BULK} rows per import")
    teams = {r["id"]: r["archived_at"] for r in conn.execute("select id, archived_at from teams").fetchall()}
    names = {r["name"].lower(): r["id"] for r in conn.execute("select id, name from teams").fetchall()}
    known = {r["repo"] for r in conn.execute("select repo from repo_owners").fetchall()}
    by_team: dict[str, list[str]] = {}
    errors, unknown = [], []
    for i, ln in enumerate(lines, 1):
        cells = [c.strip().strip('"') for c in re.split(r"[,\t;]", ln)]
        if i == 1 and cells[0].lower() in ("repo", "repository", "name"):
            continue
        if len(cells) < 2 or not cells[0] or not cells[1]:
            errors.append({"line": i, "error": "expected: repo,team"}); continue
        repo, team = cells[0], cells[1]
        team = team if team in teams else names.get(team.lower(), team)
        if not REPO_RE.fullmatch(repo):
            errors.append({"line": i, "error": f"bad repo name {repo!r}"}); continue
        if team not in teams:
            errors.append({"line": i, "error": f"unknown team {cells[1]!r}"}); continue
        if teams[team] is not None:
            errors.append({"line": i, "error": f"team {team} is archived"}); continue
        if repo not in known:
            unknown.append(repo)
        by_team.setdefault(team, []).append(repo)
    good = sum(len(v) for v in by_team.values())
    if errors and len(errors) > good:
        return {"applied": 0, "errors": errors[:100], "unknown_repos": unknown[:50],
                "message": "more rows were invalid than valid; nothing applied"}
    moved = sum(bulk_assign(conn, scope, t, rs)["findings_moved"] for t, rs in by_team.items())
    return {"applied": good, "findings_moved": moved, "errors": errors[:100], "unknown_repos": unknown[:50]}


def add_members(conn, scope, team_id: str, text: str, role: str = "member") -> dict:
    """Paste many e-mails (comma, space or newline separated)."""
    _team_exists(conn, team_id)
    raw = [x for x in re.split(r"[,;\s]+", str(text or "")) if x]
    if not 1 <= len(raw) <= 500:
        raise TeamError("paste 1 to 500 e-mail addresses")
    ok, invalid = [], []
    for x in raw:
        try:
            ok.append(norm_email(x))
        except TeamError:
            invalid.append(x[:80])
    for e in sorted(set(ok)):
        set_member(conn, scope, team_id, e, role)
    return {"added": len(set(ok)), "invalid": invalid[:50]}
