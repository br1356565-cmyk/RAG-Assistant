"""Step Functions waits here (lambda:invoke.waitForTaskToken) until a team lead has
reviewed every low-confidence investigation from this run, or the wait times out.

Runs as the ingest database user (it counts across all teams).
Input: {"run_id": "<execution name>", "task_token": "<$$.Task.Token>"}
Nothing to review -> the task is completed at once. Otherwise the token is stored in
review_gates; the review API completes it when the last pending item is decided."""
from __future__ import annotations

import json
import logging
import os

from ..config import Settings, load_secret
from ..db import Database

log = logging.getLogger()
log.setLevel(logging.INFO)

_db: Database | None = None


def handler(event: dict, context, db: Database | None = None, states=None) -> dict:
    global _db
    import boto3

    db = db or _db or (_db := Database(Settings.from_env()))
    states = states or boto3.client("stepfunctions")
    run_id, token = str(event["run_id"]), str(event["task_token"])
    with db.conn.transaction():
        pending = db.conn.execute(
            "select count(*) n from investigations i where i.run_id = %s and i.needs_review "
            "and review_state(i.id, i.needs_review) = 'pending'", (run_id,)).fetchone()["n"]
        if pending:
            db.conn.execute("insert into review_gates (run_id, task_token, pending) values (%s, %s, %s) "
                            "on conflict (run_id) do update set task_token = excluded.task_token, "
                            "pending = excluded.pending, resolved_at = null", (run_id, token, pending))
    if not pending:
        states.send_task_success(taskToken=token, output=json.dumps({"reviewed": True, "pending": 0}))
        return {"pending": 0}
    _tell_reviewers(run_id, pending)
    log.info(json.dumps({"event": "review_gate", "run_id": run_id, "pending": pending}))
    return {"pending": pending}


def _tell_reviewers(run_id: str, pending: int) -> None:
    secret = os.environ.get("SLACK_WEBHOOK_SECRET")
    if not secret:
        return
    try:
        import httpx
        url = load_secret(secret, os.environ.get("AWS_REGION", "us-east-1")).strip()
        if url.startswith("https://"):
            httpx.post(url, timeout=10, json={"text": (
                f":mag: DevOps audit run `{run_id}`: {pending} low-confidence investigation(s) need a team lead's "
                f"review before they appear in the brief. Open the assistant → Review.")})
    except Exception:  # noqa: BLE001 - never block the run on Slack
        log.warning("could not notify reviewers", exc_info=True)
