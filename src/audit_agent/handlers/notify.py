"""Run summary to Slack: one message per weekly run, including failures. Replaces the
GitHub Actions alert steps that could never fire."""
from __future__ import annotations

import json
import logging
import os
from collections import Counter

import httpx

from ..config import load_secret

log = logging.getLogger()
log.setLevel(logging.INFO)


def format_message(event: dict) -> str:
    run_id = event.get("run_id", "?")
    if event.get("error"):
        err = event["error"]
        cause = err.get("Cause") if isinstance(err, dict) else str(err)
        return f":x: DevOps audit run `{run_id}` failed before finishing.\n```{str(cause)[:1500]}```"
    ing = event.get("ingest") or {}
    cols = ing.get("collectors") or []
    ok = [c["collector"] for c in cols if c.get("status") == "succeeded"]
    bad = [f"{c['collector']} ({(c.get('error') or 'failed')[:120]})" for c in cols if c.get("status") != "succeeded"]
    inv = Counter((i or {}).get("status", "failed") for i in (event.get("investigations") or []))
    icon = ":white_check_mark:" if not bad else ":warning:"
    lines = [
        f"{icon} DevOps audit run `{run_id}`: {ing.get('status', 'unknown')}",
        f"Collectors OK: {', '.join(ok) or 'none'}",
    ]
    if bad:
        lines.append(f"Collectors failed: {'; '.join(bad)}")
    lines.append(f"Findings: {ing.get('opened', 0)} new, {ing.get('fixed', 0)} fixed, {ing.get('reopened', 0)} reopened")
    if inv:
        lines.append("Investigations: " + ", ".join(f"{n} {s}" for s, n in sorted(inv.items())))
    for w in (ing.get("warnings") or [])[:5]:
        lines.append(f"• {w}")
    return "\n".join(lines)


def handler(event: dict, context) -> dict:
    text = format_message(event)
    log.info(json.dumps({"event": "notify", "text": text}))
    secret = os.environ.get("SLACK_WEBHOOK_SECRET")
    if not secret:
        return {"sent": False, "reason": "no webhook configured"}
    try:
        url = load_secret(secret, os.environ.get("AWS_REGION", "us-east-1")).strip()
    except Exception as exc:  # secret created by Terraform but no value set yet
        log.warning("slack webhook secret unreadable: %s", type(exc).__name__)
        return {"sent": False, "reason": "webhook secret not set yet"}
    if not url.startswith("https://"):
        return {"sent": False, "reason": "webhook secret not set yet"}
    try:
        r = httpx.post(url, json={"text": text}, timeout=10)
    except httpx.HTTPError as exc:  # never fail the run because Slack is down
        log.warning("slack post failed: %s", exc)
        return {"sent": False, "reason": "slack unreachable"}
    return {"sent": r.status_code == 200, "status": r.status_code}
