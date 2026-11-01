"""Open Dependabot alerts across the org, one record per alert, with the detail the agent
needs to explain it (package, manifest, runtime vs development scope, fix version).

For an organization this uses the org-level endpoint (a few paged calls). For a personal
account the client reads each repo's alerts instead; repos it could not read make the
output incomplete, so their existing findings are not closed as fixed.
The GitHub App needs the "Dependabot alerts: read" permission.
"""
from __future__ import annotations

from .base import CollectorOutput, FindingRecord

SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low"}


def collect(github) -> CollectorOutput:
    out = CollectorOutput("dependabot", complete=True)
    for a in github.org_dependabot_alerts(state="open"):
        repo = (a.get("repository") or {}).get("name")
        if not repo:
            continue
        dep = a.get("dependency") or {}
        pkg = dep.get("package") or {}
        adv = a.get("security_advisory") or {}
        vuln = a.get("security_vulnerability") or {}
        sev = SEVERITY.get(str(vuln.get("severity") or adv.get("severity") or "low").lower(), "low")
        ghsa = adv.get("ghsa_id") or f"alert-{a.get('number')}"
        out.findings.append(FindingRecord(
            source="dependabot", resource=repo, rule=ghsa,
            location=f"{dep.get('manifest_path', '')}#{pkg.get('name', '')}",
            title=f"{pkg.get('name', 'dependency')}: {adv.get('summary') or ghsa}",
            severity=sev,
            details={
                "package": pkg.get("name"), "ecosystem": pkg.get("ecosystem"),
                "manifest": dep.get("manifest_path"), "scope": dep.get("scope"),
                "vulnerable_range": vuln.get("vulnerable_version_range"),
                "first_patched": (vuln.get("first_patched_version") or {}).get("identifier"),
                "advisory": adv.get("ghsa_id"), "cve": adv.get("cve_id"),
                "_alert_number": a.get("number"), "_url": a.get("html_url"),
                "_created_at": a.get("created_at"),  # when GitHub opened it; used as first_seen
            },
        ))
    skipped = getattr(github, "skipped_repos", None) or []
    unreadable = getattr(github, "unreadable_repos", None) or []
    if skipped:
        out.warnings.append(f"Dependabot alerts are disabled in {len(skipped)} repo(s): {', '.join(skipped[:10])}")
    if unreadable:
        out.complete = False
        out.warnings.append(f"could not read Dependabot alerts in {len(unreadable)} repo(s): {', '.join(unreadable[:10])}")
    return out
