"""The investigation's structured output. Calling this tool successfully ends the run.

Every source the model cites must be something this run actually retrieved, so an
explanation cannot reference evidence that was never looked at.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from .base import Args, ToolContext, ToolError, ToolResult, tool


class Impact(Args):
    verdict: Literal["confirmed", "likely", "unlikely", "unknown"] = Field(
        description="Does this affect the team's running code? 'unlikely' needs evidence, e.g. dev-only dependency."
    )
    reasoning: str = Field(max_length=400)


class Fix(Args):
    action: str = Field(max_length=300, description="What to do, specifically, in this repo")
    target_version: str | None = Field(None, max_length=50)
    breaking_changes: Literal["none_listed", "listed", "unknown"] = "unknown"


class Source(Args):
    kind: Literal["finding", "advisory", "file", "code"]
    ref: str = Field(max_length=200, description="As retrieved: F-<id>, GHSA id, <repo>/<path>, or <repo>:<query>")


class Investigation(Args):
    summary: str = Field(max_length=400, description="What the problem is, in plain words, for this team")
    impact: Impact
    fix: Fix
    sources: list[Source] = Field(min_length=1, max_length=8)
    confidence: Literal["high", "medium", "low"]


@tool(
    "submit_investigation",
    "Submit the finished investigation. Call exactly once, when you have the evidence. Every source "
    "must be something you retrieved in this run.",
    Investigation, {"investigate"}, terminal=True,
)
def submit_investigation(ctx: ToolContext, a: Investigation) -> ToolResult:
    unknown = [s.ref for s in a.sources if f"{s.kind}:{s.ref}" not in ctx.retrieved_sources]
    if unknown:
        seen = sorted(ctx.retrieved_sources) or ["nothing yet"]
        raise ToolError(f"These sources were not retrieved in this run: {unknown}. Retrieved: {seen}")
    return ToolResult(a.model_dump(mode="json"))
