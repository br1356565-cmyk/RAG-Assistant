"""Team isolation is enforced by the database. These tests query WITHOUT any team filter
to prove the policies, not the application code, keep teams apart."""
import psycopg
import pytest

from audit_agent.db import Scope

from conftest import ADMIN, G_ADMIN, G_CRIT, GROWTH, ORPHAN, U_HIGH, UK


def fps(db, scope, table="findings"):
    with db.scoped(scope) as conn:
        return {r["fingerprint"] for r in conn.execute(f"select fingerprint from {table}").fetchall()}


def test_team_sees_only_its_own_team_findings(db):
    assert fps(db, GROWTH) == {G_CRIT, "a000000000000002"}
    assert fps(db, UK) == {U_HIGH}


def test_admin_only_findings_hidden_from_their_own_team(db):
    assert G_ADMIN not in fps(db, GROWTH)


def test_admin_sees_everything_including_unowned(db):
    seen = fps(db, ADMIN)
    assert {G_CRIT, G_ADMIN, U_HIGH, ORPHAN} <= seen


def test_no_scope_means_no_rows(db):
    with db.conn.transaction():
        assert db.conn.execute("select count(*) n from findings").fetchone()["n"] == 0
    assert fps(db, Scope(user_id="x", team_ids=(), role="team_member")) == set()


def test_scope_does_not_leak_to_next_transaction_on_same_connection(db):
    assert fps(db, GROWTH)
    with db.conn.transaction():
        assert db.conn.execute("select count(*) n from findings").fetchone()["n"] == 0


def test_notes_from_other_team_are_invisible(db):
    with db.scoped(GROWTH) as conn:
        assert conn.execute("select count(*) n from team_notes").fetchone()["n"] == 0
    with db.scoped(UK) as conn:
        assert conn.execute("select count(*) n from team_notes").fetchone()["n"] == 1


def test_app_can_only_insert_proposed_notes_for_own_team(db):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH) as conn:
            conn.execute("insert into team_notes (team_id, kind, text, author) values "
                         "('uk_engineering','context','writing into another team','x')")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH) as conn:
            conn.execute("insert into team_notes (team_id, kind, text, status, author) values "
                         "('growth_engineering','context','self-activated note','active','x')")
    with db.scoped(GROWTH) as conn:
        conn.execute("insert into team_notes (team_id, kind, text, author) values "
                     "('growth_engineering','context','a proper proposal','x')")


def test_app_cannot_update_findings_or_read_audit_log(db):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH) as conn:
            conn.execute("update findings set status = 'fixed'")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(ADMIN) as conn:
            conn.execute("select * from audit_log")


def test_sessions_are_private_to_their_user(db):
    with db.scoped(GROWTH) as conn:
        conn.execute("insert into session_turns (user_id, session_id, turn, role, content) "
                     "values ('user-growth','s1',1,'user','hello')")
    with db.scoped(Scope(user_id="someone-else", team_ids=("growth_engineering",))) as conn:
        assert conn.execute("select count(*) n from session_turns").fetchone()["n"] == 0
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH) as conn:
            conn.execute("insert into session_turns (user_id, session_id, turn, role, content) "
                         "values ('someone-else','s1',1,'user','impersonation')")


def test_worker_can_only_write_investigations_for_its_team(db):
    worker = Scope(user_id="worker:investigate", team_ids=("growth_engineering",), role="worker")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(worker) as conn:
            conn.execute("insert into investigations (fingerprint, team_id, evidence_hash, prompt_version, "
                         "model, explanation) values (%s,'uk_engineering','h','v','m','{}')", (U_HIGH,))
