"""Deliver Lambda (in the VPC, ingest login): after the weekly run's review step,
  1. Jira sync for teams that turned it on (create / close / SLA follow-ups), then
  2. each team's digest by e-mail (SES) to its members and to its Slack channel.
Never fails the run: problems are returned (and shown in the run's Slack summary).

Event: {"run_id", "dashboard_url"}   (the link comes from Step Functions; DASHBOARD_URL env is a fallback)
Env: DB_*, DIGEST_SENDER (verified SES identity), JIRA_SECRET (optional), JIRA_MAX_CREATE (default 50)
"""
from __future__ import annotations

import json
import logging
import os

import httpx

from .. import digest, jira
from ..config import Settings, load_secret
from ..db import Database

log = logging.getLogger()
log.setLevel(logging.INFO)

_db: Database | None = None


def _jira_client():
    secret = os.environ.get("JIRA_SECRET")
    if not secret:
        return None
    try:
        cfg = json.loads(load_secret(secret, os.environ.get("AWS_REGION", "us-east-1")))
        return jira.JiraClient(cfg["base_url"], cfg["email"], cfg["api_token"])
    except Exception as exc:  # noqa: BLE001 - secret created by Terraform, value not set yet
        log.warning("jira secret unusable: %s", type(exc).__name__)
        return None


def run(conn, *, ses, http, jira_client, sender: str | None, dashboard_url: str, max_create: int) -> dict:
    out: dict = {}
    if jira_client is not None:
        try:
            with conn.transaction():
                out["jira"] = jira.sync(conn, jira_client, dashboard_url=dashboard_url, max_create=max_create)
        except Exception as exc:  # noqa: BLE001
            log.exception("jira sync failed")
            out["jira"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    else:
        out["jira"] = {"skipped": "no Jira credentials configured"}
    try:
        out["digest"] = digest.deliver(conn, ses=ses, http=http, sender=sender, dashboard_url=dashboard_url)
    except Exception as exc:  # noqa: BLE001
        log.exception("digest failed")
        out["digest"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    return out


def handler(event: dict, context) -> dict:
    global _db
    import boto3

    _db = _db or Database(Settings.from_env())
    sender = os.environ.get("DIGEST_SENDER") or None
    out = run(_db.conn, ses=boto3.client("sesv2") if sender else None, http=httpx.Client(),
              jira_client=_jira_client(), sender=sender,
              dashboard_url=str(event.get("dashboard_url") or os.environ.get("DASHBOARD_URL", "")),
              max_create=int(os.environ.get("JIRA_MAX_CREATE", "50")))
    log.info(json.dumps({"event": "deliver", "run_id": event.get("run_id"), **out}, default=str))
    return out
