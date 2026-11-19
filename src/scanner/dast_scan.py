"""DAST: OWASP ZAP *baseline* (passive) scan of every URL a team registered in the dashboard.

Runs as a weekly Fargate task in the official ZAP image (ghcr.io/zaproxy/zaproxy:stable);
Terraform passes this file in an environment variable. The baseline scan spiders for a
minute and reports what passive rules see (security headers, cookie flags, information
leaks, mixed content). It sends no attack payloads, so it is safe against production;
active scanning is deliberately not offered here.

Input:  s3://DATA_BUCKET/config/dast_targets.json   [{"url", "team_id"}]   (written by Prepare)
Output: runs/<RUN_ID>/dast-raw/<sha>.json            {"url", "team_id", "report": <ZAP JSON>}
        runs/<RUN_ID>/dast-raw/_manifest.json        {"scanned": [urls], "failed": {url: error}}

Env: RUN_ID, DATA_BUCKET, AWS_REGION, ZAP_SPIDER_MINUTES (1), DAST_MAX_TARGETS (50),
     DAST_TARGET_TIMEOUT_S (600)
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

WRK = pathlib.Path("/zap/wrk")


def log(event: str, **kw) -> None:
    print(json.dumps({"event": event, **kw}), flush=True)


def scan(url: str, minutes: int, timeout_s: int) -> dict:
    out = WRK / f"{hashlib.sha256(url.encode()).hexdigest()[:16]}.json"
    out.unlink(missing_ok=True)
    # -I: warnings don't fail the script; -J: JSON report, written relative to /zap/wrk
    proc = subprocess.run(["zap-baseline.py", "-t", url, "-m", str(minutes), "-I", "-J", out.name],
                          cwd=str(WRK), timeout=timeout_s, capture_output=True, text=True)
    if not out.exists():
        raise RuntimeError(f"ZAP produced no report (exit {proc.returncode}): {proc.stdout[-300:]}")
    return json.loads(out.read_text())


def main() -> int:
    import boto3

    run_id, bucket = os.environ["RUN_ID"], os.environ["DATA_BUCKET"]
    s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    minutes = int(os.environ.get("ZAP_SPIDER_MINUTES", "1"))
    limit = int(os.environ.get("DAST_MAX_TARGETS", "50"))
    timeout_s = int(os.environ.get("DAST_TARGET_TIMEOUT_S", "600"))
    try:
        targets = json.loads(s3.get_object(Bucket=bucket, Key="config/dast_targets.json")["Body"].read())
    except s3.exceptions.NoSuchKey:
        targets = []
    targets = [t for t in targets if str(t.get("url", "")).startswith(("http://", "https://"))][:limit]
    WRK.mkdir(parents=True, exist_ok=True)
    prefix = f"runs/{run_id}/dast-raw"
    scanned, failed = [], {}
    log("dast_start", run_id=run_id, targets=len(targets))
    for t in targets:
        url, started = t["url"], time.time()
        try:
            report = scan(url, minutes, timeout_s)
        except (subprocess.SubprocessError, RuntimeError, OSError, ValueError) as exc:
            failed[url] = str(exc)[:300]
            log("dast_target_failed", url=url, error=failed[url])
            continue
        key = f"{prefix}/{hashlib.sha256(url.encode()).hexdigest()[:16]}.json"
        s3.put_object(Bucket=bucket, Key=key, ContentType="application/json",
                      Body=json.dumps({"url": url, "team_id": t.get("team_id"), "report": report}).encode())
        scanned.append(url)
        log("dast_target", url=url, seconds=round(time.time() - started))
    s3.put_object(Bucket=bucket, Key=f"{prefix}/_manifest.json", ContentType="application/json",
                  Body=json.dumps({"run_id": run_id, "scanned": scanned, "failed": failed,
                                   "targets": [t["url"] for t in targets]}).encode())
    log("dast_done", scanned=len(scanned), failed=len(failed))
    return 0 if scanned or not targets else 1


if __name__ == "__main__":
    sys.exit(main())
