"""Active Security Hub findings (failed controls and product findings) across regions.

Team: the `team` tag on the finding's first resource when it names a known team, otherwise
the ownership file's aws_findings_team. Products in `skip_products` are left out, so the
GuardDuty findings Security Hub also aggregates aren't counted twice when the guardduty
collector runs. A region that fails marks the output incomplete (ingest then doesn't mark
that region's findings fixed).
"""
from __future__ import annotations

import logging

from .base import CollectorOutput, FindingRecord

log = logging.getLogger(__name__)

SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFORMATIONAL": "info"}
FILTERS = {
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}, {"Value": "NOTIFIED", "Comparison": "EQUALS"}],
    # Passed controls are reported as findings too; keep only the ones that need action.
    "ComplianceStatus": [{"Value": "PASSED", "Comparison": "NOT_EQUALS"}],
}


def collect(session, regions: list[str], default_team: str, known_teams: set[str],
            skip_products: set[str] | None = None) -> CollectorOutput:
    out = CollectorOutput("securityhub", complete=True)
    skip = {p.lower() for p in (skip_products or set())}
    for region in regions:
        try:
            sh = session.client("securityhub", region_name=region)
            for page in sh.get_paginator("get_findings").paginate(Filters=FILTERS, PaginationConfig={"PageSize": 100}):
                for f in page["Findings"]:
                    if (f.get("ProductName") or "").lower() in skip:
                        continue
                    out.findings.append(_record(f, region, default_team, known_teams))
        except Exception as exc:  # one bad region must not wipe the others' findings
            log.exception("securityhub region %s failed", region)
            out.complete = False
            out.warnings.append(f"{region}: {type(exc).__name__}: {exc}"[:300])
    return out


def _record(f: dict, region: str, default_team: str, known_teams: set[str]) -> FindingRecord:
    res = (f.get("Resources") or [{}])[0]
    tags = res.get("Tags") or {}
    team = tags.get("team") if tags.get("team") in known_teams else default_team
    comp = f.get("Compliance") or {}
    control = comp.get("SecurityControlId")
    rid = res.get("Id") or "unknown"
    short = rid.split(":", 5)[-1].split("/")[-1] if rid.startswith("arn:") else rid
    remediation = ((f.get("Remediation") or {}).get("Recommendation") or {})
    return FindingRecord(
        source="securityhub", resource=f"{f.get('AwsAccountId')}/{short}",
        rule=control or f.get("GeneratorId") or (f.get("Types") or ["unknown"])[0],
        location=rid, title=f.get("Title", "Security Hub finding"),
        severity=SEVERITY.get(((f.get("Severity") or {}).get("Label") or "").upper(), "medium"),
        team_hint=team,
        details={
            "region": region, "account": f.get("AwsAccountId"), "product": f.get("ProductName"),
            "control": control, "resource_type": res.get("Type"), "resource_arn": rid,
            "description": (f.get("Description") or "")[:800],
            "remediation": (remediation.get("Text") or "")[:400], "remediation_url": remediation.get("Url"),
            "_updated_at": f.get("UpdatedAt"), "_created_at": f.get("CreatedAt"),
        },
    )
