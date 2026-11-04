"""request_fix: hand a finding to the fix agent (over A2A), which drafts a change and waits
for a team lead's approval before anything reaches GitHub."""
from __future__ import annotations

from pydantic import Field

from .base import Args, ToolContext, ToolError, ToolResult, parse_ref, ref, tool
from .findings import load_finding


class FixArgs(Args):
    finding_id: str = Field(description="Finding to fix, e.g. F-0123456789abcdef")


@tool(
    "request_fix",
    "Ask the fix agent to draft a dependency upgrade for a Dependabot finding. It prepares the change "
    "and a team lead must approve it before a pull request is opened. Only call this when the user asks "
    "for a fix to be drafted.",
    FixArgs, {"chat"},
)
def request_fix(ctx: ToolContext, a: FixArgs) -> ToolResult:
    if ctx.fix_client is None:
        raise ToolError("The fix agent is not configured in this environment.")
    fp = parse_ref(a.finding_id)
    f = load_finding(ctx, fp)["finding"]          # scope check: same error if not yours
    d = f["details"] or {}
    if f["source"] != "dependabot" or not d.get("first_patched") or not d.get("manifest"):
        raise ToolError("Only Dependabot findings with a published fixed version can be drafted automatically.")
    if f["status"] != "open":
        raise ToolError(f"{ref(fp)} is {f['status']}, not open.")
    result = ctx.fix_client.request_fix(ctx.scope, fp)
    return ToolResult({"finding": ref(fp), **result,
                       "next_step": "A team lead reviews the diff under 'Pending fixes' and approves or rejects it."},
                      finding_ids={fp}, sources={f"finding:{ref(fp)}"})
