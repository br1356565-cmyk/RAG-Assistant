"""Semgrep results (from the weekly SAST scan task) -> findings, one per rule per code location.

Identity: repo + rule + path + hash of the matched lines, so a finding keeps its id when
unrelated edits move it to another line, and closes when the code is fixed. Only repos the
scan actually covered can have findings closed (scope_resources), so a clone failure never
reports a fix.
"""
from __future__ import annotations

import json

from .base import CollectorOutput, FindingRecord

SEVERITY = {"CRITICAL": "critical", "ERROR": "high", "HIGH": "high", "WARNING": "medium", "MEDIUM": "medium",
            "INFO": "low", "LOW": "low"}
MAX_PER_REPO = 300          # a repo with thousands of hits is one problem, not thousands of tickets


def severity(r: dict) -> str:
    sev = SEVERITY.get(str(r.get("severity") or "").upper(), "low")
    # High-confidence, high-impact security rules (injection, hard-coded secrets) are critical.
    if sev == "high" and str(r.get("confidence") or "").upper() == "HIGH" and str(r.get("impact") or "").upper() == "HIGH":
        return "critical"
    return sev


def short_rule(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1] if check_id else "semgrep"


def to_findings(repo: str, results: list[dict]) -> tuple[list[FindingRecord], int]:
    out = []
    ranked = sorted(results, key=lambda r: ["critical", "high", "medium", "low"].index(severity(r)))
    for r in ranked[:MAX_PER_REPO]:
        check = str(r.get("check_id") or "semgrep")
        path = str(r.get("path") or "")
        out.append(FindingRecord(
            source="sast", resource=repo, rule=check,
            location=f"{path}#{r.get('snippet_sha') or r.get('line')}",
            title=f"{short_rule(check)} in {path}:{r.get('line')}",
            severity=severity(r),
            details={
                "path": path, "line": r.get("line"), "end_line": r.get("end_line"), "message": r.get("message"),
                "cwe": r.get("cwe"), "owasp": r.get("owasp"), "confidence": r.get("confidence"),
                "category": r.get("category"), "references": r.get("references"), "scanner": "semgrep",
            }))
    return out, max(0, len(results) - MAX_PER_REPO)


def collect(s3, bucket: str, run_id: str) -> CollectorOutput:
    prefix = f"runs/{run_id}/sast-raw/"
    try:
        manifest = json.loads(s3.get_object(Bucket=bucket, Key=prefix + "_manifest.json")["Body"].read())
    except Exception as exc:  # noqa: BLE001 - no manifest = the scan did not finish; record a failure
        raise RuntimeError(f"no SAST scan output for run {run_id}: {type(exc).__name__}") from exc
    out = CollectorOutput("sast", complete=True, scope_resources=list(manifest.get("scanned") or []))
    for repo in out.scope_resources:
        raw = json.loads(s3.get_object(Bucket=bucket, Key=f"{prefix}{repo}.json")["Body"].read())
        found, dropped = to_findings(repo, raw.get("results") or [])
        out.findings += found
        if dropped:
            out.warnings.append(f"sast: {repo} has {dropped} more results than the {MAX_PER_REPO} kept")
    failed = manifest.get("failed") or {}
    if failed:
        out.warnings.append(f"sast: could not scan {len(failed)} repo(s): {', '.join(sorted(failed)[:10])}")
    return out
