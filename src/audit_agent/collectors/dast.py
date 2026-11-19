"""ZAP baseline reports (from the weekly DAST task) -> findings, one per ZAP rule per URL.

The team is the URL's owner in the dashboard (team_assets kind=url); ingest looks it up, the
report's team_id is only a fallback. Evidence values are not kept (they are page content an
attacker may control); the URIs and parameter names are, so the team can reproduce it.
"""
from __future__ import annotations

import hashlib
import json

from .base import CollectorOutput, FindingRecord

RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def to_findings(url: str, team_id: str | None, report: dict, include_info: bool = False) -> list[FindingRecord]:
    out = []
    for site in report.get("site") or []:
        for a in site.get("alerts") or []:
            sev = RISK.get(str(a.get("riskcode")), "low")
            if sev == "info" and not include_info:
                continue
            plugin = str(a.get("pluginid") or a.get("alertRef") or "zap")
            inst = a.get("instances") or []
            out.append(FindingRecord(
                source="dast", resource=url, rule=f"zap-{plugin}",
                title=f"{a.get('name') or a.get('alert') or 'ZAP alert'} on {url}"[:300],
                severity=sev, team_hint=team_id,
                details={
                    "alert": a.get("name") or a.get("alert"), "risk": a.get("riskdesc"),
                    "confidence": a.get("confidence"), "cwe": a.get("cweid"), "wasc": a.get("wascid"),
                    "solution": _text(a.get("solution"))[:800], "description": _text(a.get("desc"))[:800],
                    "references": _text(a.get("reference"))[:400], "count": len(inst) or a.get("count"),
                    "uris": sorted({str(i.get("uri", ""))[:300] for i in inst if i.get("uri")})[:5],
                    "params": sorted({str(i.get("param", ""))[:60] for i in inst if i.get("param")})[:10],
                    "scanner": "zap-baseline",
                }))
    return out


def _text(html: object) -> str:
    """ZAP fields are HTML paragraphs; keep plain text."""
    s = str(html or "")
    for tag in ("<p>", "</p>", "<br>", "<br/>"):
        s = s.replace(tag, "\n")
    return "\n".join(line.strip() for line in s.splitlines() if line.strip())


def collect(s3, bucket: str, run_id: str) -> CollectorOutput:
    prefix = f"runs/{run_id}/dast-raw/"
    try:
        manifest = json.loads(s3.get_object(Bucket=bucket, Key=prefix + "_manifest.json")["Body"].read())
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"no DAST scan output for run {run_id}: {type(exc).__name__}") from exc
    scanned = list(manifest.get("scanned") or [])
    out = CollectorOutput("dast", complete=True, scope_resources=scanned)
    for url in scanned:
        key = f"{prefix}{hashlib.sha256(url.encode()).hexdigest()[:16]}.json"
        raw = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
        out.findings += to_findings(url, raw.get("team_id"), raw.get("report") or {})
    if manifest.get("failed"):
        out.warnings.append(f"dast: could not scan {len(manifest['failed'])} URL(s): "
                            f"{', '.join(sorted(manifest['failed'])[:5])}")
    return out
