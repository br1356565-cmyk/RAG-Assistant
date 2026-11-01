"""Create the schema and login roles in the local Postgres (same migration code as AWS,
minus RDS IAM). Safe to run repeatedly.

    python local/bootstrap.py
"""
from __future__ import annotations

import common  # noqa: F401  (sets sys.path)
import psycopg

from common import env, guard_local, load_env


def main() -> None:
    guard_local()
    load_env()
    from audit_agent.handlers import migrate

    with psycopg.connect(env("AUDIT_DB_ADMIN_DSN"), autocommit=True) as conn:
        digest = migrate.apply(conn, use_iam=False)
    print(f"Schema applied ({digest[:12]}). Login roles audit_app_login and audit_ingest_login ready.")


if __name__ == "__main__":
    main()
