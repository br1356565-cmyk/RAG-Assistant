"""Postgres access where every query runs inside a request scope.

Scope values are set with set_config(..., is_local => true): they exist only for the
current transaction, so a reused Lambda connection can never carry one user's scope
into the next request. Row-level security policies in db/schema.sql read them.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

from .config import Settings

log = logging.getLogger(__name__)

ROLES = ("team_member", "team_lead", "security_admin", "worker", "none")


@dataclass(frozen=True)
class Scope:
    """Who is asking, derived from a verified token (or the batch job's input). Never from the model."""

    user_id: str
    team_ids: tuple[str, ...]
    role: str = "team_member"
    team_names: dict[str, str] = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}")
        for t in self.team_ids:
            if "," in t:
                raise ValueError("team ids may not contain commas")

    @property
    def is_admin(self) -> bool:
        return self.role == "security_admin"


class Database:
    """One lazily opened connection per Lambda container, reopened if it breaks."""

    def __init__(self, settings: Settings | None = None, dsn: str | None = None):
        self._settings = settings
        self._dsn = dsn or (settings.db_dsn if settings else None)
        self._conn: psycopg.Connection | None = None

    def _connect(self) -> psycopg.Connection:
        if self._dsn:
            return psycopg.connect(self._dsn, autocommit=True, row_factory=dict_row)
        s = self._settings
        if not s or not s.db_host:
            raise RuntimeError("Set DB_DSN, or DB_HOST for RDS IAM authentication")
        import boto3

        token = boto3.client("rds", region_name=s.aws_region).generate_db_auth_token(
            DBHostname=s.db_host, Port=s.db_port, DBUsername=s.db_user, Region=s.aws_region
        )
        return psycopg.connect(
            host=s.db_host, port=s.db_port, dbname=s.db_name, user=s.db_user,
            password=token, sslmode="require", autocommit=True, row_factory=dict_row,
            connect_timeout=5,
        )

    @property
    def conn(self) -> psycopg.Connection:
        if self._conn is None or self._conn.closed or self._conn.broken:
            self._conn = self._connect()
        return self._conn

    @contextmanager
    def scoped(self, scope: Scope) -> Iterator[psycopg.Connection]:
        """A transaction whose RLS scope is `scope`. Rolls back on any exception."""
        conn = self.conn
        try:
            with conn.transaction():
                conn.execute(
                    "select set_config('app.team_ids', %s, true),"
                    "       set_config('app.role', %s, true),"
                    "       set_config('app.user_id', %s, true)",
                    (",".join(scope.team_ids), scope.role, scope.user_id),
                )
                yield conn
        except psycopg.OperationalError:
            log.warning("database connection failed; will reconnect on next use")
            self._conn = None
            raise

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
