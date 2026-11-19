"""Optional Jira integration: one ticket per team + source + resource + rule (high and
critical only), closed automatically when the weekly scan no longer finds it, with a
follow-up comment to the team's leads when it stays open past the team's SLA.

Turned on per team in the dashboard (team_settings.jira_enabled + project key). Credentials
are one Jira Cloud API token in Secrets Manager: {"base_url", "email", "api_token"}.
Creation is capped per run (JIRA_MAX_CREATE) so the first run on a large org doesn't
flood a project; the rest are created on the following runs.
"""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx

log = logging.getLogger(__name__)

FOLLOWUP_EVERY = timedelta(days=7)
MAX_ITEMS_IN_TICKET = 20


class JiraError(RuntimeError):
    pass


class JiraClient:
    def __init__(self, base_url: str, email: str, api_token: str, http: httpx.Client | None = None):
        if not base_url.startswith("https://"):
            raise JiraError("Jira base_url must be https://<site>.atlassian.net")
        self.base = base_url.rstrip("/")
        auth = base64.b64encode(f"{email}:{api_token}".encode()).decode()
        self.http = http or httpx.Client(timeout=20)
        self.headers = {"Authorization": f"Basic {auth}", "Accept": "application/json",
                        "Content-Type": "application/json"}
        self._users: dict[str, str | None] = {}

    def _call(self, method: str, path: str, body: dict | None = None, params: dict | None = None):
        r = self.http.request(method, self.base + path, headers=self.headers, json=body, params=params)
        if r.status_code >= 400:
            raise JiraError(f"{method} {path}: HTTP {r.status_code} {r.text[:200]}")
        return r.json() if r.content else {}

    def account_id(self, email: str | None) -> str | None:
        if not email:
            return None
        if email not in self._users:
            try:
                found = self._call("GET", "/rest/api/3/user/search", params={"query": email})
                self._users[email] = next((u["accountId"] for u in found or [] if u.get("accountId")), None)
            except JiraError:
                self._users[email] = None
        return self._users[email]

    def create(self, project: str, issue_type: str, summary: str, description: dict, labels: list[str],
               assignee: str | None = None, priority: str | None = None) -> str:
        fields = {"project": {"key": project}, "issuetype": {"name": issue_type}, "summary": summary[:250],
                  "description": description, "labels": labels}
        if assignee:
            fields["assignee"] = {"accountId": assignee}
        if priority:
            fields["priority"] = {"name": priority}
        try:
            return self._call("POST", "/rest/api/3/issue", {"fields": fields})["key"]
        except JiraError:
            if not priority:
                raise
            fields.pop("priority")                     # projects without that priority scheme
            return self._call("POST", "/rest/api/3/issue", {"fields": fields})["key"]

    def comment(self, key: str, body: dict) -> None:
        self._call("POST", f"/rest/api/3/issue/{key}/comment", {"body": body})

    def close(self, key: str) -> bool:
        ts = self._call("GET", f"/rest/api/3/issue/{key}/transitions").get("transitions") or []
        done = next((t for t in ts if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == "done"), None)
        if not done:
            return False
        self._call("POST", f"/rest/api/3/issue/{key}/transitions", {"transition": {"id": done["id"]}})
        return True


# ── Atlassian document format helpers ──────────────────────────────────────
def _text(t: str) -> dict:
    return {"type": "text", "text": t}


def _para(*parts) -> dict:
    return {"type": "paragraph", "content": [p if isinstance(p, dict) else _text(str(p)) for p in parts]}


def _doc(*blocks) -> dict:
    return {"type": "doc", "version": 1, "content": list(blocks)}


def _mention(account_id: str) -> dict:
    return {"type": "mention", "attrs": {"id": account_id}}


def _link(text: str, url: str) -> dict:
    return {"type": "text", "text": text, "marks": [{"type": "link", "attrs": {"href": url}}]}


def description(group: dict, items: list[dict], dashboard_url: str) -> dict:
    bullets = {"type": "bulletList", "content": [
        {"type": "listItem", "content": [_para(f"{i['title']}" + (f" ({i['where']})" if i.get("where") else ""))]}
        for i in items[:MAX_ITEMS_IN_TICKET]]}
    blocks = [
        _para(f"The weekly DevOps audit scan found {len(items)} {group['severity']} issue(s) for rule "
              f"{group['rule']} in {group['resource']} (source: {group['source']})."),
        bullets,
        _para("This ticket closes itself when the scan no longer finds the issue."),
    ]
    if len(items) > MAX_ITEMS_IN_TICKET:
        blocks.insert(2, _para(f"…and {len(items) - MAX_ITEMS_IN_TICKET} more."))
    if dashboard_url:
        blocks.append(_para(_link("Open in the DevOps audit dashboard", f"{dashboard_url}#findings")))
    return _doc(*blocks)


def group_key(team: str, source: str, resource: str, rule: str) -> str:
    return f"{team}|{source}|{resource}|{rule}"[:500]


def summary_line(g: dict) -> str:
    rule = g["rule"].rsplit(".", 1)[-1]
    return f"[{g['severity'].upper()}] {rule} in {g['resource']} ({g['source']})"


def _where(details: dict) -> str:
    if details.get("path"):
        return f"{details['path']}:{details.get('line', '')}"
    if details.get("manifest"):
        return str(details["manifest"])
    if details.get("uris"):
        return str(details["uris"][0])
    return ""


def sync(conn, client: JiraClient, *, dashboard_url: str = "", now: datetime | None = None,
         max_create: int = 50) -> dict:
    """Create, update, close and follow up. Runs as the ingest login (all teams)."""
    now = now or datetime.now(timezone.utc)
    out = {"created": 0, "closed": 0, "followups": 0, "deferred": 0, "errors": []}
    settings = {r["team_id"]: r for r in conn.execute(
        "select s.* from team_settings s join teams t on t.id = s.team_id "
        "where s.jira_enabled and s.jira_project is not null and t.archived_at is null").fetchall()}
    if not settings:
        return out
    rows = conn.execute(
        "select fingerprint, team_id, source, resource, rule, severity, title, details from findings "
        "where status = 'open' and data_class = 'team' and severity in ('critical','high') "
        "and team_id = any(%s) order by team_id, source, resource, rule", (list(settings),)).fetchall()
    groups: dict[str, dict] = {}
    for r in rows:
        k = group_key(r["team_id"], r["source"], r["resource"], r["rule"])
        g = groups.setdefault(k, {"team_id": r["team_id"], "source": r["source"], "resource": r["resource"],
                                  "rule": r["rule"], "severity": "high", "items": []})
        if r["severity"] == "critical":
            g["severity"] = "critical"
        details = r["details"] if isinstance(r["details"], dict) else json.loads(r["details"] or "{}")
        g["items"].append({"fp": r["fingerprint"], "title": r["title"], "where": _where(details)})
    tickets = {r["group_key"]: r for r in conn.execute("select * from jira_tickets").fetchall()}

    # 1. Create tickets for new groups; refresh the fingerprint list of existing ones.
    for k, g in groups.items():
        fps = sorted(i["fp"] for i in g["items"])
        t = tickets.get(k)
        if t and t["status"] == "open":
            if list(t["fingerprints"]) != fps or t["severity"] != g["severity"]:
                conn.execute("update jira_tickets set fingerprints = %s, severity = %s where group_key = %s",
                             (fps, g["severity"], k))
            continue
        if out["created"] >= max_create:
            out["deferred"] += 1
            continue
        s = settings[g["team_id"]]
        try:
            key = client.create(s["jira_project"], s["jira_issue_type"] or "Bug", summary_line(g),
                                description(g, g["items"], dashboard_url), ["devops-audit", f"source-{g['source']}"],
                                assignee=client.account_id(s["jira_assignee"]),
                                priority="Highest" if g["severity"] == "critical" else "High")
        except (JiraError, httpx.HTTPError) as exc:
            out["errors"].append(f"create {k}: {str(exc)[:160]}")
            continue
        conn.execute(
            "insert into jira_tickets (group_key, team_id, source, resource, rule, severity, issue_key, status, "
            "fingerprints, created_at) values (%s,%s,%s,%s,%s,%s,%s,'open',%s,%s) on conflict (group_key) do update "
            "set issue_key = excluded.issue_key, status = 'open', fingerprints = excluded.fingerprints, "
            "severity = excluded.severity, created_at = excluded.created_at, closed_at = null, "
            "last_followup_at = null, followups = 0",
            (k, g["team_id"], g["source"], g["resource"], g["rule"], g["severity"], key, fps, now))
        out["created"] += 1

    # 2. Close tickets whose findings are all gone (fixed or suppressed).
    for k, t in tickets.items():
        if t["status"] != "open" or k in groups:
            continue
        try:
            client.comment(t["issue_key"], _doc(_para(
                f"Closed automatically: the DevOps audit scan on {now.date().isoformat()} no longer finds this issue.")))
            closed = client.close(t["issue_key"])
        except (JiraError, httpx.HTTPError) as exc:
            out["errors"].append(f"close {t['issue_key']}: {str(exc)[:160]}")
            continue
        conn.execute("update jira_tickets set status = 'closed', closed_at = %s where group_key = %s", (now, k))
        out["closed"] += 1
        if not closed:
            out["errors"].append(f"{t['issue_key']}: no 'done' transition; marked closed here, close it in Jira")

    # 3. Follow up on tickets past the team's SLA, at most once a week each.
    leads = {}
    for r in conn.execute("select team_id, email from team_members where role = 'lead' and team_id = any(%s)",
                          (list(settings),)).fetchall():
        leads.setdefault(r["team_id"], []).append(r["email"])
    for t in conn.execute("select * from jira_tickets where status = 'open'").fetchall():
        s = settings.get(t["team_id"])
        if not s:
            continue
        sla = s["sla_days"] if isinstance(s["sla_days"], dict) else json.loads(s["sla_days"] or "{}")
        days = int(sla.get(t["severity"]) or (7 if t["severity"] == "critical" else 30))
        age = (now - t["created_at"]).days
        if age < days or (t["last_followup_at"] and now - t["last_followup_at"] < FOLLOWUP_EVERY):
            continue
        people = [a for a in (client.account_id(e) for e in [s["jira_assignee"], *leads.get(t["team_id"], [])]) if a]
        parts: list = [_text("Reminder: ")] + [p for a in dict.fromkeys(people) for p in (_mention(a), _text(" "))]
        parts.append(_text(f"this {t['severity']} issue has been open {age} days; the team's SLA is {days} days."))
        try:
            client.comment(t["issue_key"], _doc(_para(*parts)))
        except (JiraError, httpx.HTTPError) as exc:
            out["errors"].append(f"follow-up {t['issue_key']}: {str(exc)[:160]}")
            continue
        conn.execute("update jira_tickets set last_followup_at = %s, followups = followups + 1 where group_key = %s",
                     (now, t["group_key"]))
        out["followups"] += 1
    out["errors"] = out["errors"][:30]
    return out
