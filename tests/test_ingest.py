"""Ingest lifecycle against real Postgres, connected as the ingest login (no BYPASSRLS)."""
import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from psycopg.rows import dict_row

from audit_agent import ingest as ingest_mod
from audit_agent.collectors import dependabot, ownership
from audit_agent.handlers import migrate, notify
from audit_agent.prompts import PROMPT_VERSION

from conftest import DBNAME, HOST, PORT, _admin_dsn
from test_collectors import OrgGitHub, alert

T0 = datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc)
CRIT = "GHSA-2c3f-4g5h-6j7m"
HIGH = "GHSA-3f4g-5h6j-7m8p"


@pytest.fixture()
def conn(pg):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute("truncate teams, repo_owners, findings, finding_events, weekly_aggregates, runs, "
                  "run_collectors, investigations, team_notes, session_turns, user_prefs, audit_log cascade")
    with psycopg.connect(f"host={HOST} port={PORT} user=ingest_login dbname={DBNAME}",
                         autocommit=True, row_factory=dict_row) as c:
        yield c


class Store:
    """Stands in for S3: collector outputs by key."""
    def __init__(self):
        self.objs = {}

    def put(self, run, out):
        key = f"runs/{run}/{out.collector}.json"
        self.objs[key] = json.loads(json.dumps(out.to_json(), default=str))
        return {"collector": out.collector, "status": "succeeded", "key": key, "count": len(out.findings),
                "complete": out.complete}

    def load(self, key):
        return self.objs[key]


def run(conn, store, run_id, gh, now, extra=()):
    results = [store.put(run_id, ownership.collect(gh)), store.put(run_id, dependabot.collect(gh)), *extra]
    return ingest_mod.ingest(conn, run_id, results, store.load, now=now)


def q(conn, sql, *p):
    return conn.execute(sql, p).fetchall()


def test_first_run_assigns_owners_and_queues_investigations(conn):
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", CRIT, "critical"), alert("de-pipeline", HIGH, "high"),
                           alert("random-tool", HIGH, "high"), alert("exp-motors", HIGH, "low", pkg="x")])
    s = run(conn, Store(), "r1", gh, T0)
    teams = {r["resource"]: r["team_id"] for r in q(conn, "select resource, team_id from findings where source='dependabot'")}
    assert teams == {"mktp-growth-api": "uk_engineering", "de-pipeline": "de", "random-tool": None, "exp-motors": "expertise"}
    # unowned repos are findings with no team, visible to admins only
    assert {r["resource"] for r in q(conn, "select resource from findings where source='ownership'")} == {"random-tool", "wp-platform"}
    queued = {i["team_id"] for i in s["investigate"]}
    assert queued == {"uk_engineering", "de"}                 # critical/high, owned, dependabot only
    assert s["opened"] == 6 and s["status"] == "succeeded"
    agg = q(conn, "select counts from weekly_aggregates where team_id='uk_engineering'")[0]["counts"]
    assert agg["open"] == {"critical": 1} and agg["opened"] == 1


def test_complete_run_fixes_missing_and_reopens_returning(conn):
    store = Store()
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", CRIT, "critical"), alert("de-pipeline", HIGH, "high")])
    run(conn, store, "r1", gh, T0)
    gh.alerts = [alert("mktp-growth-api", CRIT, "critical")]                      # de alert resolved
    s2 = run(conn, store, "r2", gh, T0 + timedelta(days=7))
    assert s2["fixed"] == 1
    assert q(conn, "select status from findings where resource='de-pipeline'")[0]["status"] == "fixed"
    gh.alerts = [alert("mktp-growth-api", CRIT, "critical"), alert("de-pipeline", HIGH, "high")]
    s3 = run(conn, store, "r3", gh, T0 + timedelta(days=14))
    assert s3["reopened"] == 1
    events = [r["event"] for r in q(conn, "select e.event from finding_events e join findings f using (fingerprint) "
                                          "where f.resource='de-pipeline' order by e.id")]
    assert events == ["opened", "fixed", "reopened"]


def test_failed_collector_never_marks_findings_fixed(conn):
    store = Store()
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", CRIT, "critical")])
    run(conn, store, "r1", gh, T0)
    results = [store.put("r2", ownership.collect(gh)),
               {"collector": "dependabot", "status": "failed", "error": "GitHub 502"}]
    s = ingest_mod.ingest(conn, "r2", results, store.load, now=T0 + timedelta(days=7))
    assert s["status"] == "partial" and s["fixed"] == 0
    assert q(conn, "select status from findings where source='dependabot'")[0]["status"] == "open"
    assert q(conn, "select status, error from run_collectors where run_id='r2' and collector='dependabot'")[0]["error"] == "GitHub 502"


def test_incomplete_output_never_marks_findings_fixed(conn):
    store = Store()
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", CRIT, "critical")])
    run(conn, store, "r1", gh, T0)
    out = dependabot.collect(OrgGitHub(alerts=[]))
    out.complete = False
    s = ingest_mod.ingest(conn, "r2", [store.put("r2", out)], store.load, now=T0 + timedelta(days=7))
    assert s["fixed"] == 0 and any("incomplete" in w for w in s["warnings"])


def test_suppressed_stays_suppressed(conn):
    store = Store()
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", CRIT, "critical")])
    run(conn, store, "r1", gh, T0)
    conn.execute("update findings set status='suppressed' where source='dependabot'")
    s = run(conn, store, "r2", gh, T0 + timedelta(days=7))
    assert q(conn, "select status from findings where source='dependabot'")[0]["status"] == "suppressed"
    assert s["investigate"] == []


def test_queue_skips_investigated_unless_evidence_changes(conn):
    store = Store()
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", CRIT, "critical")])
    s1 = run(conn, store, "r1", gh, T0)
    fp = s1["investigate"][0]["fingerprint"][2:]
    conn.execute("insert into investigations (fingerprint, team_id, evidence_hash, prompt_version, model, explanation) "
                 "values (%s, 'uk_engineering', 'h', %s, 'm', '{}')", (fp, PROMPT_VERSION))
    assert run(conn, store, "r2", gh, T0 + timedelta(days=7))["investigate"] == []
    gh.alerts = [alert("mktp-growth-api", CRIT, "critical", number=55)]          # only a volatile field changed
    assert run(conn, store, "r3", gh, T0 + timedelta(days=14))["investigate"] == []
    gh.alerts = [alert("mktp-growth-api", CRIT, "critical", patched="2.3.5")]    # real evidence changed
    assert [i["fingerprint"] for i in run(conn, store, "r4", gh, T0 + timedelta(days=21))["investigate"]] == [f"F-{fp}"]


def test_ownership_changes_move_findings_and_drop_deleted_repos(conn):
    store = Store()
    gh = OrgGitHub(alerts=[alert("random-tool", HIGH, "high")])
    run(conn, store, "r1", gh, T0)
    assert q(conn, "select team_id from findings where source='dependabot'")[0]["team_id"] is None
    gh.admins["growth-engineering"].add("random-tool")
    gh.repos = [r for r in gh.repos if r["name"] != "exp-motors"]
    s = run(conn, store, "r2", gh, T0 + timedelta(days=7))
    assert q(conn, "select team_id from findings where source='dependabot'")[0]["team_id"] == "growth_engineering"
    assert not q(conn, "select 1 from repo_owners where repo='exp-motors'")
    assert q(conn, "select status from findings where source='ownership' and resource='random-tool'")[0]["status"] == "fixed"
    assert s["investigate"][0]["team_id"] == "growth_engineering"


def test_first_seen_uses_the_source_open_date(conn):
    store = Store()
    a = alert("mktp-growth-api", CRIT, "critical")
    a["created_at"] = "2026-09-15T08:00:00Z"
    future = alert("de-pipeline", HIGH, "high")
    future["created_at"] = "2030-01-01T00:00:00Z"
    run(conn, store, "r1", OrgGitHub(alerts=[a, future]), T0)
    rows = {r["resource"]: r["first_seen"] for r in q(conn, "select resource, first_seen from findings where source='dependabot'")}
    assert rows["mktp-growth-api"] == datetime(2026, 9, 15, 8, 0, tzinfo=timezone.utc)
    assert rows["de-pipeline"] == T0                       # never in the future


def test_ingest_is_atomic(conn):
    store = Store()
    gh = OrgGitHub()
    bad = {"collector": "dependabot", "status": "succeeded", "key": "missing"}
    with pytest.raises(KeyError):
        ingest_mod.ingest(conn, "r1", [store.put("r1", ownership.collect(gh)), bad], store.load, now=T0)
    assert q(conn, "select count(*) n from repo_owners")[0]["n"] == 0
    assert q(conn, "select count(*) n from runs")[0]["n"] == 0


def test_migrate_is_idempotent(pg):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        h1 = migrate.apply(c, use_iam=False)
        h2 = migrate.apply(c, use_iam=False)
        assert h1 == h2
        assert c.execute("select count(*) from pg_roles where rolname in ('audit_app_login','audit_ingest_login')").fetchone()[0] == 2


def test_notify_messages():
    ok = notify.format_message({"run_id": "r9", "ingest": {
        "status": "partial", "opened": 3, "fixed": 1, "reopened": 0, "warnings": ["guardduty: incomplete output"],
        "collectors": [{"collector": "dependabot", "status": "succeeded"},
                       {"collector": "guardduty", "status": "failed", "error": "AccessDenied"}]},
        "investigations": [{"status": "investigated"}, {"status": "cached"}, {"status": "failed"}]})
    assert ":warning:" in ok and "guardduty (AccessDenied)" in ok and "3 new, 1 fixed" in ok and "1 investigated" in ok
    fail = notify.format_message({"run_id": "r9", "error": {"Error": "States.TaskFailed", "Cause": "boom"}})
    assert fail.startswith(":x:") and "boom" in fail
