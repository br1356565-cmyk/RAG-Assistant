"""Weekly per-team digest: what is open, what changed, what is overdue, sent to the team's
members by e-mail (Amazon SES) and to the team's Slack channel (incoming webhook).

Recipients come from the dashboard (team_members), so who gets which report is changed
there, not in code. Everything model- or scanner-written is escaped in the HTML.
"""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

SEVS = ("critical", "high", "medium", "low")
SEV_RANK = "array_position(array['critical','high','medium','low','info'], f.severity)"
TOP = 15


def build(conn, team: dict, now: datetime, sla: dict) -> dict:
    tid = team["id"]
    counts = {r["severity"]: r["n"] for r in conn.execute(
        "select severity, count(*) n from findings where team_id = %s and status = 'open' and data_class = 'team' "
        "group by 1", (tid,)).fetchall()}
    week_ago = now - timedelta(days=7)
    events = {r["event"]: r["n"] for r in conn.execute(
        "select event, count(*) n from finding_events where team_id = %s and at >= %s group by 1",
        (tid, week_ago)).fetchall()}
    top = conn.execute(
        f"select f.fingerprint, f.source, f.resource, f.title, f.severity, f.first_seen, j.issue_key "
        f"from findings f left join jira_tickets j on j.status = 'open' and f.fingerprint = any(j.fingerprints) "
        f"where f.team_id = %s and f.status = 'open' and f.data_class = 'team' and f.severity in ('critical','high') "
        f"order by {SEV_RANK}, f.first_seen limit %s", (tid, TOP)).fetchall()
    overdue = 0
    for sev in ("critical", "high"):
        days = int((sla or {}).get(sev) or (7 if sev == "critical" else 30))
        overdue += conn.execute(
            "select count(*) n from findings where team_id = %s and status = 'open' and data_class = 'team' "
            "and severity = %s and first_seen < %s", (tid, sev, now - timedelta(days=days))).fetchone()["n"]
    by_source = {r["source"]: r["n"] for r in conn.execute(
        "select source, count(*) n from findings where team_id = %s and status = 'open' and data_class = 'team' "
        "group by 1 order by 2 desc", (tid,)).fetchall()}
    return {
        "team_id": tid, "team": team["name"], "open": {s: counts.get(s, 0) for s in SEVS},
        "total_open": sum(counts.values()), "new": events.get("opened", 0) + events.get("reopened", 0),
        "fixed": events.get("fixed", 0), "overdue": overdue, "by_source": by_source, "sla": sla,
        "top": [{"id": f"F-{r['fingerprint']}", "source": r["source"], "resource": r["resource"], "title": r["title"],
                 "severity": r["severity"], "age_days": max(0, (now - r["first_seen"]).days), "jira": r["issue_key"]}
                for r in top],
    }


def worth_sending(d: dict) -> bool:
    return d["total_open"] > 0 or d["new"] > 0 or d["fixed"] > 0


def render_email(d: dict, dashboard_url: str) -> tuple[str, str, str]:
    o = d["open"]
    subject = (f"[DevOps audit] {d['team']}: {o['critical']} critical, {o['high']} high open"
               + (f", {d['overdue']} overdue" if d["overdue"] else ""))
    lines = [f"Weekly security & DevOps report for {d['team']}", "",
             f"Open: {o['critical']} critical, {o['high']} high, {o['medium']} medium, {o['low']} low",
             f"This week: {d['new']} new, {d['fixed']} fixed" + (f", {d['overdue']} past SLA" if d["overdue"] else ""),
             ""]
    if d["top"]:
        lines.append("Fix first:")
        for t in d["top"]:
            lines.append(f"- [{t['severity'].upper()}] {t['title']} ({t['resource']}, {t['source']}, "
                         f"{t['age_days']} days)" + (f" Jira {t['jira']}" if t["jira"] else ""))
        lines.append("")
    if dashboard_url:
        lines.append(f"Open the dashboard: {dashboard_url}#findings")
    lines += ["", "You get this because you are in this team in the DevOps audit dashboard. "
                  "A team lead or admin can change who receives it."]
    text = "\n".join(lines)

    e = html.escape
    rows = "".join(
        f"<tr><td style='padding:4px 8px'><b style='color:{_color(t['severity'])}'>{e(t['severity'].upper())}</b></td>"
        f"<td style='padding:4px 8px'>{e(t['title'])}<br><small>{e(t['resource'])} · {e(t['source'])} · "
        f"{t['age_days']} days{(' · Jira ' + e(t['jira'])) if t['jira'] else ''}</small></td></tr>"
        for t in d["top"])
    link = (f"<p><a href='{e(dashboard_url)}#findings'>Open the dashboard</a></p>" if dashboard_url else "")
    body = (
        f"<div style='font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:680px'>"
        f"<h2 style='margin:0 0 8px'>{e(d['team'])}: weekly security &amp; DevOps report</h2>"
        f"<p><b>Open:</b> {o['critical']} critical · {o['high']} high · {o['medium']} medium · {o['low']} low<br>"
        f"<b>This week:</b> {d['new']} new · {d['fixed']} fixed"
        + (f" · <b style='color:#b42318'>{d['overdue']} past SLA</b>" if d["overdue"] else "") + "</p>"
        + (f"<h3>Fix first</h3><table style='border-collapse:collapse'>{rows}</table>" if rows else "")
        + link
        + "<p style='color:#667085;font-size:12px'>You get this because you are in this team in the DevOps audit "
          "dashboard. A team lead or admin can change who receives it.</p></div>")
    return subject, text, body


def render_slack(d: dict, dashboard_url: str) -> dict:
    o = d["open"]
    head = (f"*{d['team']}*: {o['critical']} critical, {o['high']} high open · {d['new']} new, {d['fixed']} fixed "
            "this week" + (f" · :rotating_light: {d['overdue']} past SLA" if d["overdue"] else ""))
    items = [f"• `{t['severity'].upper()}` {t['title']} ({t['resource']}, {t['age_days']}d)"
             + (f" {t['jira']}" if t["jira"] else "") for t in d["top"][:8]]
    text = "\n".join([head, *items] + ([f"<{dashboard_url}#findings|Open the dashboard>"] if dashboard_url else []))
    return {"text": text}


def _color(sev: str) -> str:
    return {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708"}.get(sev, "#475467")


def deliver(conn, *, ses, http, sender: str | None, dashboard_url: str = "",
            now: datetime | None = None) -> dict:
    """Send every active team's digest. Never raises for one team's failure."""
    now = now or datetime.now(timezone.utc)
    teams = conn.execute(
        "select t.id, t.name, coalesce(s.email_digest, true) as email_digest, s.slack_webhook, s.sla_days "
        "from teams t left join team_settings s on s.team_id = t.id where t.archived_at is null order by t.id").fetchall()
    summary = {"teams": 0, "emails": 0, "slack": 0, "skipped": 0, "errors": []}
    for t in teams:
        sla = t["sla_days"] if isinstance(t["sla_days"], dict) else json.loads(t["sla_days"] or "{}")
        d = build(conn, t, now, sla)
        if not worth_sending(d):
            summary["skipped"] += 1
            continue
        summary["teams"] += 1
        if t["email_digest"] and ses is not None and sender:
            subject, text, body = render_email(d, dashboard_url)
            for r in conn.execute("select email from team_members where team_id = %s order by email", (t["id"],)).fetchall():
                try:
                    ses.send_email(FromEmailAddress=sender, Destination={"ToAddresses": [r["email"]]},
                                   Content={"Simple": {"Subject": {"Data": subject[:200]},
                                                       "Body": {"Text": {"Data": text}, "Html": {"Data": body}}}})
                    summary["emails"] += 1
                except Exception as exc:  # noqa: BLE001 - SES sandbox / unverified address / throttling
                    summary["errors"].append(f"email {t['id']}/{r['email']}: {type(exc).__name__}: {str(exc)[:120]}")
        if t["slack_webhook"] and http is not None:
            try:
                resp = http.post(t["slack_webhook"], json=render_slack(d, dashboard_url), timeout=10)
                if resp.status_code == 200:
                    summary["slack"] += 1
                else:
                    summary["errors"].append(f"slack {t['id']}: HTTP {resp.status_code}")
            except Exception as exc:  # noqa: BLE001
                summary["errors"].append(f"slack {t['id']}: {type(exc).__name__}")
    summary["errors"] = summary["errors"][:30]
    return summary
