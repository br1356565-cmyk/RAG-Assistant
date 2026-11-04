"""Schema migration Lambda. Terraform invokes it on every apply where the schema changed.

Connects as the RDS master user (credentials from the RDS-managed secret), applies the
idempotent schema, and creates the IAM-authenticated login users.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import pathlib
import time

import psycopg
from psycopg import sql
from psycopg.rows import dict_row


log = logging.getLogger()
log.setLevel(logging.INFO)

SCHEMA = pathlib.Path(__file__).resolve().parents[1] / "sql" / "schema.sql"
LOGIN_USERS = {"audit_app_login": "audit_app", "audit_ingest_login": "audit_ingest"}


def schema_text() -> str:
    return SCHEMA.read_text()


def apply(conn: psycopg.Connection, use_iam: bool = True) -> str:
    text = schema_text()
    with conn.transaction():
        conn.execute(text)
        for user, role in LOGIN_USERS.items():
            exists = conn.execute("select 1 from pg_roles where rolname = %s", (user,)).fetchone()
            if not exists:
                conn.execute(sql.SQL("create role {} login").format(sql.Identifier(user)))
            conn.execute(sql.SQL("grant {} to {}").format(sql.Identifier(role), sql.Identifier(user)))
            if use_iam:
                conn.execute(sql.SQL("grant rds_iam to {}").format(sql.Identifier(user)))
    return hashlib.sha256(text.encode()).hexdigest()


def _master_secret(region: str, deadline: float, client=None, sleep=time.sleep) -> dict:
    """Secrets Manager is reached through the NAT. On a first apply in a fresh VPC the NAT
    instance may still be booting, so retry with short timeouts instead of hanging."""
    if client is None:
        import boto3
        from botocore.config import Config

        client = boto3.client("secretsmanager", region_name=region, config=Config(
            connect_timeout=5, read_timeout=10, retries={"max_attempts": 1}))
    while True:
        try:
            return json.loads(client.get_secret_value(SecretId=os.environ["DB_MASTER_SECRET_ARN"])["SecretString"])
        except Exception as exc:  # noqa: BLE001 - connection errors until the NAT is up
            if time.monotonic() > deadline:
                raise
            log.info(json.dumps({"event": "migrate_wait", "reason": type(exc).__name__}))
            sleep(5)


def handler(event: dict, context) -> dict:
    region = os.environ.get("AWS_REGION", "us-east-1")
    budget = (context.get_remaining_time_in_millis() / 1000 - 25) if context else 60
    master = _master_secret(region, time.monotonic() + max(budget, 5))
    with psycopg.connect(host=os.environ["DB_HOST"], port=int(os.environ.get("DB_PORT", "5432")),
                         dbname=os.environ.get("DB_NAME", "audit"), user=master["username"],
                         password=master["password"], sslmode="require", connect_timeout=10,
                         autocommit=True) as conn:
        digest = apply(conn)
        conn.row_factory = dict_row
        from fix_agent.checkpoints import setup as setup_checkpoints
        setup_checkpoints(conn)               # LangGraph tables for paused fix graphs
    log.info(json.dumps({"event": "migrate", "schema_sha256": digest}))
    return {"status": "ok", "schema_sha256": digest}
