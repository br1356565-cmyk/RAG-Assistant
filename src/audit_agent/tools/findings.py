"""Read-only tools over the findings store. Row-level security does the team filtering;
these queries add a team filter only to narrow, never to grant."""
from __future__ import annotations

import json
from datetime import date
from typing import Literal

from pydantic import Field

from .base import Args, ToolContext, ToolError, ToolResult, parse_ref, ref, tool

Severity = Literal["critical", "high", "medium", "low", "info"]
SEV_ORDER = "array_position(array['critical','high','medium','low','info'], severity)"
MAX_DETAIL_CHARS = 3000


class TeamArg(Args):
    team: str | None = Field(
        None,
        description="Team id. Only needed by users in several teams or security admins "
        "(admins may also use 'unowned' in search_findings).",
    )


@tool(
    "get_team_overview",
    "Open findings by severity and source for your team(s), this week's opened and fixed counts, "
    "and when the data was last refreshed. Start here for broad questions.",
    TeamArg, {"chat"},
)
def get_team_overview(ctx: ToolContext, a: TeamArg) -> ToolResult:
    teams = ctx.teams_for(a.team)
    with ctx.db.scoped(ctx.scope) as conn:
        sev = conn.execute(
            "select team_id, severity, count(*) n from findings "
            "where status = 'open' and team_id = any(%s) group by 1, 2",
            (list(teams),),
        ).fetchall()
        src = conn.execute(
            "select team_id, source, count(*) n from findings "
            "where status = 'open' and team_id = any(%s) group by 1, 2 order by n desc",
            (list(teams),),
        ).fetchall()
        week = conn.execute(
            "select distinct on (team_id) team_id, week, counts from weekly_aggregates "
            "where team_id = any(%s) order by team_id, week desc",
            (list(teams),),
        ).fetchall()
        run = conn.execute(
            "select finished_at from runs where status in ('succeeded', 'partial') "
            "order by finished_at desc limit 1"
        ).fetchone()
    out: dict = {"as_of": run["finished_at"].isoformat() if run else None, "teams": {}}
    for t in teams:
        out["teams"][t] = {
            "name": ctx.scope.team_names.get(t, t),
            "open_by_severity": {r["severity"]: r["n"] for r in sev if r["team_id"] == t},
            "open_by_source": {r["source"]: r["n"] for r in src if r["team_id"] == t},
        }
        w = next((r for r in week if r["team_id"] == t), None)
        if w:
            out["teams"][t]["this_week"] = {"week": w["week"].isoformat(), **{
                k: w["counts"].get(k) for k in ("opened", "fixed") if k in w["counts"]}}
    return ToolResult(out)


class SearchArgs(TeamArg):
    source: str | None = Field(None, description="e.g. dependabot, guardduty, security_hub, readme, branch_divergence")
    severity: list[Severity] | None = None
    status: Literal["open", "fixed", "suppressed", "any"] = "open"
    repo: str | None = Field(None, description="Exact repo or resource name")
    text: str | None = Field(None, max_length=100, description="Words to match in title or rule, e.g. a package name or GHSA id")
    opened_since: date | None = None
    limit: int = Field(10, ge=1, le=25)


@tool(
    "search_findings",
    "Find findings by source, severity, status, repo, text or date. Returns the total match count and "
    "the top results ordered by severity then age. Cite results as [F-<id>].",
    SearchArgs, {"chat"},
)
def search_findings(ctx: ToolContext, a: SearchArgs) -> ToolResult:
    team_sql, team_params = ctx.team_filter(a.team)
    where, params = [team_sql], list(team_params)
    if a.status != "any":
        where.append("status = %s"); params.append(a.status)
    if a.source:
        where.append("source = %s"); params.append(a.source)
    if a.severity:
        where.append("severity = any(%s)"); params.append(list(a.severity))
    if a.repo:
        where.append("resource = %s"); params.append(a.repo)
    if a.text:
        where.append("(title ilike %s or rule ilike %s)"); params += [f"%{a.text}%"] * 2
    if a.opened_since:
        where.append("first_seen >= %s"); params.append(a.opened_since)
    clause = " and ".join(where)
    with ctx.db.scoped(ctx.scope) as conn:
        total = conn.execute(f"select count(*) n from findings where {clause}", params).fetchone()["n"]
        rows = conn.execute(
            f"select fingerprint, team_id, source, resource, title, severity, status, first_seen "
            f"from findings where {clause} order by {SEV_ORDER}, first_seen limit %s",
            params + [a.limit],
        ).fetchall()
    items = [{
        "id": ref(r["fingerprint"]), "team": r["team_id"], "source": r["source"], "resource": r["resource"],
        "title": r["title"], "severity": r["severity"], "status": r["status"],
        "open_days": (ctx.now - r["first_seen"]).days,
    } for r in rows]
    return ToolResult({"total": total, "returned": len(items), "findings": items},
                      finding_ids={r["fingerprint"] for r in rows})


class FindingArg(Args):
    id: str = Field(description="Finding id, e.g. F-0123456789abcdef")


def load_finding(ctx: ToolContext, fingerprint: str) -> dict:
    """Shared by tools and the investigation handler. Same error whether the finding is
    missing or belongs to another team, so existence never leaks across teams."""
    with ctx.db.scoped(ctx.scope) as conn:
        f = conn.execute("select * from findings where fingerprint = %s", (fingerprint,)).fetchone()
        if not f:
            raise ToolError(f"No finding {ref(fingerprint)} in your scope.")
        events = conn.execute(
            "select event, at from finding_events where fingerprint = %s order by at desc limit 10", (fingerprint,)
        ).fetchall()
        inv = conn.execute(
            "select explanation, created_at, prompt_version from investigations "
            "where fingerprint = %s order by created_at desc limit 1", (fingerprint,)
        ).fetchone()
        notes = conn.execute(
            "select kind, text, expires_at from team_notes where fingerprint = %s and status = 'active' "
            "and (expires_at is null or expires_at >= current_date)", (fingerprint,)
        ).fetchall()
    return {"finding": f, "events": events, "investigation": inv, "notes": notes}


@tool(
    "get_finding",
    "Full detail for one finding: source fields, history, the latest investigation (explanation, "
    "evidence, fix) and any active team notes such as an accepted risk.",
    FindingArg, {"chat", "investigate"},
)
def get_finding(ctx: ToolContext, a: FindingArg) -> ToolResult:
    fp = parse_ref(a.id)
    d = load_finding(ctx, fp)
    f = d["finding"]
    details = f["details"]
    if len(json.dumps(details, default=str)) > MAX_DETAIL_CHARS:
        details = {"note": "details truncated", **{k: details[k] for k in list(details)[:15]}}
    out = {
        "id": ref(fp), "team": f["team_id"], "source": f["source"], "resource": f["resource"],
        "rule": f["rule"], "title": f["title"], "severity": f["severity"], "status": f["status"],
        "first_seen": f["first_seen"].date().isoformat(), "last_seen": f["last_seen"].date().isoformat(),
        "open_days": (ctx.now - f["first_seen"]).days, "details": details,
        "history": [{"event": e["event"], "at": e["at"].date().isoformat()} for e in d["events"]],
        "active_notes": [{"kind": n["kind"], "text": n["text"],
                          "expires": n["expires_at"].isoformat() if n["expires_at"] else None} for n in d["notes"]],
    }
    if d["investigation"]:
        out["latest_investigation"] = {
            **d["investigation"]["explanation"],
            "investigated_on": d["investigation"]["created_at"].date().isoformat(),
        }
    return ToolResult(out, finding_ids={fp}, sources={f"finding:{ref(fp)}"})


class TrendArgs(TeamArg):
    weeks: int = Field(8, ge=1, le=26)


@tool(
    "get_trend",
    "Weekly open, opened and fixed counts for your team(s), newest first.",
    TrendArgs, {"chat"},
)
def get_trend(ctx: ToolContext, a: TrendArgs) -> ToolResult:
    teams = ctx.teams_for(a.team)
    with ctx.db.scoped(ctx.scope) as conn:
        rows = conn.execute(
            "select team_id, week, counts from weekly_aggregates where team_id = any(%s) "
            "order by week desc, team_id limit %s",
            (list(teams), a.weeks * len(teams)),
        ).fetchall()
    return ToolResult({"weeks": [{"team": r["team_id"], "week": r["week"].isoformat(), **r["counts"]} for r in rows]})
