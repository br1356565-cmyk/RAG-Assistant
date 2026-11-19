"""Prepare Lambda: the first step of the weekly run (in the VPC, ingest login).

Exports what the scan tasks need from the dashboard, so a URL a team registered on Monday is
scanned in that week's run:
  s3://DATA_BUCKET/config/dast_targets.json   [{"url", "team_id"}]
Output: {"dast_targets": n}
"""
from __future__ import annotations

import json
import logging
import os

from ..config import Settings
from ..db import Database
from ..teams import dast_targets

log = logging.getLogger()
log.setLevel(logging.INFO)

_db: Database | None = None
_s3 = None


def export(conn, s3, bucket: str) -> dict:
    targets = dast_targets(conn)
    s3.put_object(Bucket=bucket, Key="config/dast_targets.json", Body=json.dumps(targets).encode(),
                  ContentType="application/json")
    return {"dast_targets": len(targets)}


def handler(event: dict, context) -> dict:
    global _db, _s3
    import boto3

    _db = _db or Database(Settings.from_env())
    _s3 = _s3 or boto3.client("s3")
    with _db.conn.transaction():
        out = export(_db.conn, _s3, os.environ["DATA_BUCKET"])
    log.info(json.dumps({"event": "prepare", **out}))
    return out
