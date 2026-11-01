"""Active (non-archived) GuardDuty findings across regions.

Run in, or with a role into, the account that administers GuardDuty. If any region fails,
the output is marked incomplete so ingest doesn't mark that region's findings fixed.
"""
from __future__ import annotations

import logging

from .base import CollectorOutput, FindingRecord

log = logging.getLogger(__name__)

DEFAULT_REGIONS = ["us-east-1", "us-west-2", "ap-southeast-2", "ca-central-1", "eu-south-1", "eu-north-1", "eu-west-2"]


def severity(score: float) -> str:
    # GuardDuty: 9.0-10.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 1.0-3.9 low
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def collect(session, regions: list[str], team: str) -> CollectorOutput:
    out = CollectorOutput("guardduty", complete=True)
    for region in regions:
        try:
            gd = session.client("guardduty", region_name=region)
            for det in gd.get_paginator("list_detectors").paginate():
                for detector_id in det["DetectorIds"]:
                    ids: list[str] = []
                    for page in gd.get_paginator("list_findings").paginate(
                        DetectorId=detector_id,
                        FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
                    ):
                        ids += page["FindingIds"]
                    for i in range(0, len(ids), 50):
                        for f in gd.get_findings(DetectorId=detector_id, FindingIds=ids[i:i + 50])["Findings"]:
                            out.findings.append(_record(f, region, team))
        except Exception as exc:  # one bad region must not wipe the others' findings
            log.exception("guardduty region %s failed", region)
            out.complete = False
            out.warnings.append(f"{region}: {type(exc).__name__}: {exc}"[:300])
    return out


def _record(f: dict, region: str, team: str) -> FindingRecord:
    res = f.get("Resource") or {}
    inst = res.get("InstanceDetails") or {}
    svc = f.get("Service") or {}
    target = inst.get("InstanceId") or res.get("ResourceType") or "unknown"
    return FindingRecord(
        source="guardduty", resource=f"{f.get('AccountId')}/{target}", rule=f.get("Type", "unknown"),
        location=f.get("Id", ""), title=f.get("Title", f.get("Type", "GuardDuty finding")),
        severity=severity(float(f.get("Severity") or 0)), team_hint=team,
        details={
            "region": region, "account": f.get("AccountId"), "type": f.get("Type"),
            "description": (f.get("Description") or "")[:800], "resource_type": res.get("ResourceType"),
            "instance_id": inst.get("InstanceId"), "confidence": f.get("Confidence"),
            "_count": svc.get("Count"), "_last_seen": svc.get("EventLastSeen"), "_updated_at": f.get("UpdatedAt"),
            "_created_at": f.get("CreatedAt"),
        },
    )
