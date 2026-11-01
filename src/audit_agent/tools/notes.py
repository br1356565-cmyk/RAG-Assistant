"""Team knowledge (long-term memory). The agent reads active notes and may only PROPOSE new
ones; a team lead approves in the UI. The database policy enforces the 'proposed only' rule."""
from __future__ import annotations

from datetime import date, timedelta
from typing import Literal

from pydantic import Field

from .base import Args, ToolContext, ToolError, ToolResult, parse_ref, tool
from .findings import TeamArg

MAX_ACCEPTED_RISK_DAYS = 180


class ListNotesArgs(TeamArg):
    kind: Literal["accepted_risk", "false_positive", "context"] | None = None


@tool(
    "list_team_notes",
    "Active team notes: accepted risks (with expiry), false positives and team context such as how "
    "the team deploys. Check these before recommending action on a finding.",
    ListNotesArgs, {"chat", "investigate"},
)
def list_team_notes(ctx: ToolContext, a: ListNotesArgs) -> ToolResult:
    teams = ctx.teams_for(a.team)
    where, params = ["team_id = any(%s)", "status = 'active'",
                     "(expires_at is null or expires_at >= current_date)"], [list(teams)]
    if a.kind:
        where.append("kind = %s"); params.append(a.kind)
    with ctx.db.scoped(ctx.scope) as conn:
        rows = conn.execute(
            f"select team_id, kind, fingerprint, text, expires_at from team_notes "
            f"where {' and '.join(where)} order by created_at desc limit 30", params
        ).fetchall()
        pending = conn.execute(
            "select count(*) n from team_notes where team_id = any(%s) and status = 'proposed'", (list(teams),)
        ).fetchone()["n"]
    notes = [{
        "team": r["team_id"], "kind": r["kind"], "text": r["text"],
        "finding": f"F-{r['fingerprint']}" if r["fingerprint"] else None,
        "expires": r["expires_at"].isoformat() if r["expires_at"] else None,
    } for r in rows]
    return ToolResult({"notes": notes, "pending_proposals": pending},
                      finding_ids={r["fingerprint"] for r in rows if r["fingerprint"]})


class ProposeArgs(TeamArg):
    kind: Literal["accepted_risk", "false_positive", "context"]
    text: str = Field(min_length=10, max_length=500, description="The note, in the user's words")
    finding_id: str | None = Field(None, description="Finding the note is about, if any")
    expires_at: date | None = Field(None, description=f"Required for accepted_risk; at most {MAX_ACCEPTED_RISK_DAYS} days ahead")


@tool(
    "propose_team_note",
    "Propose a team note when the user states a decision (e.g. 'we accept this risk until March'). "
    "It is saved as a proposal; it takes effect only after a team lead approves it. Only call this "
    "when the user explicitly asked to record something.",
    ProposeArgs, {"chat"},
)
def propose_team_note(ctx: ToolContext, a: ProposeArgs) -> ToolResult:
    fp = parse_ref(a.finding_id) if a.finding_id else None
    if a.kind == "accepted_risk":
        if not a.expires_at:
            raise ToolError("An accepted risk needs expires_at.")
        if not (ctx.now.date() < a.expires_at <= ctx.now.date() + timedelta(days=MAX_ACCEPTED_RISK_DAYS)):
            raise ToolError(f"expires_at must be in the next {MAX_ACCEPTED_RISK_DAYS} days.")
    with ctx.db.scoped(ctx.scope) as conn:
        if fp:
            row = conn.execute("select team_id from findings where fingerprint = %s", (fp,)).fetchone()
            if not row:
                raise ToolError(f"No finding F-{fp} in your scope.")
            team = row["team_id"]
        else:
            teams = ctx.teams_for(a.team)
            if len(teams) != 1:
                raise ToolError("You are in several teams; pass `team`.")
            team = teams[0]
        new = conn.execute(
            "insert into team_notes (team_id, kind, fingerprint, text, author, expires_at) "
            "values (%s, %s, %s, %s, %s, %s) returning id",
            (team, a.kind, fp, a.text, f"agent:{ctx.scope.user_id}", a.expires_at),
        ).fetchone()
    return ToolResult({"proposal_id": str(new["id"]), "status": "proposed", "team": team,
                       "note": "Saved as a proposal. A team lead must approve it before it takes effect."},
                      finding_ids={fp} if fp else set())
