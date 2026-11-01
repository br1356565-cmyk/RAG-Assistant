"""Ingest Lambda (in the VPC, connects as the audit_ingest login).

Input:  {"run_id": "...", "results": [<collector handler outputs or failure records>]}
Output: the ingest summary, including "investigate": [{"fingerprint", "team_id"}] for the Map state.
"""
from __future__ import annotations

import json
import logging
import os

from ..config import Settings
from ..db import Database
from ..ingest import ingest

log = logging.getLogger()
log.setLevel(logging.INFO)

_db: Database | None = None
_s3 = None


def handler(event: dict, context) -> dict:
    global _db, _s3
    import boto3

    _db = _db or Database(Settings.from_env())
    _s3 = _s3 or boto3.client("s3")
    bucket = os.environ["DATA_BUCKET"]

    def load(key: str) -> dict:
        return json.loads(_s3.get_object(Bucket=bucket, Key=key)["Body"].read())

    summary = ingest(_db.conn, str(event["run_id"]), list(event.get("results") or []), load,
                     max_investigations=int(os.environ.get("MAX_INVESTIGATIONS", "100")))
    log.info(json.dumps({"event": "ingest", **{k: v for k, v in summary.items() if k != "investigate"},
                         "investigate_count": len(summary["investigate"])}))
    return summary
