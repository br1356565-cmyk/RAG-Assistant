"""LangGraph checkpoint tables for paused fix graphs. Created by the migrate step (as the
database owner) and granted to the app role the fix agent connects as."""
from __future__ import annotations

import psycopg
from psycopg.rows import dict_row

TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes", "checkpoint_migrations")


def setup(dsn_or_conn) -> None:
    from langgraph.checkpoint.postgres import PostgresSaver

    conn = dsn_or_conn if isinstance(dsn_or_conn, psycopg.Connection) else \
        psycopg.connect(dsn_or_conn, autocommit=True, row_factory=dict_row)
    PostgresSaver(conn).setup()
    for t in TABLES:
        conn.execute(f"grant select, insert, update, delete on {t} to audit_app")
