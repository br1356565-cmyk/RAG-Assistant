"""Public advisory data from the GitHub Advisory Database. Not team data, so no scope check."""
from __future__ import annotations

from pydantic import Field

from .base import Args, ToolContext, ToolError, ToolResult, tool


class AdvisoryArgs(Args):
    ghsa_id: str = Field(pattern=r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$", description="e.g. GHSA-xxxx-xxxx-xxxx")


@tool(
    "get_advisory",
    "Details of a security advisory: summary, severity, CVSS and EPSS where published, affected "
    "version ranges, first patched versions and reference links.",
    AdvisoryArgs, {"chat", "investigate"}, untrusted=True,
)
def get_advisory(ctx: ToolContext, a: AdvisoryArgs) -> ToolResult:
    if ctx.github is None:
        raise ToolError("Advisory lookups are not available right now.")
    adv = ctx.github.advisory(a.ghsa_id)
    if not adv:
        raise ToolError(f"Advisory {a.ghsa_id} not found.")
    out = {
        "ghsa_id": adv.get("ghsa_id"),
        "cve_id": adv.get("cve_id"),
        "summary": adv.get("summary"),
        "description": (adv.get("description") or "")[:1500],
        "severity": adv.get("severity"),
        "cvss_score": (adv.get("cvss") or {}).get("score"),
        "epss": adv.get("epss"),
        "published_at": adv.get("published_at"),
        "updated_at": adv.get("updated_at"),
        "vulnerabilities": [{
            "ecosystem": (v.get("package") or {}).get("ecosystem"),
            "package": (v.get("package") or {}).get("name"),
            "vulnerable_range": v.get("vulnerable_version_range"),
            "first_patched": v.get("first_patched_version"),
        } for v in (adv.get("vulnerabilities") or [])[:10]],
        "references": (adv.get("references") or [])[:5],
    }
    return ToolResult(out, sources={f"advisory:{a.ghsa_id}"})
