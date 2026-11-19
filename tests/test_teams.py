"""Dashboard-managed teams: RLS on who may change what, sign-in by e-mail membership, instant
repo/URL reassignment, ingest precedence (dashboard > rule > YAML), partial-scan safety."""
import json

import psycopg
import pytest
from psycopg.rows import dict_row

from audit_agent import ingest as ingest_mod
from audit_agent import teams as T
from audit_agent.auth import AuthError, resolve_scope
from audit_agent.collectors import dependabot, ownership
from audit_agent.collectors.base import CollectorOutput, FindingRecord
from audit_agent.config import Settings
from audit_agent.db import Scope
from audit_agent.handlers import chat
from audit_agent.handlers.deps import Deps, set_deps

from conftest import ADMIN, DBNAME, G_CRIT, GROWTH, HOST, PORT, U_HIGH, _admin_dsn
from test_collectors import OrgGitHub, alert
from test_handlers import FakeVerifier, event
from test_ingest import T0, Store

GROWTH_LEAD = Scope(user_id="lead-growth", team_ids=("growth_engineering",), role="team_lead")


def owner(sql, params=()):
    with psycopg.connect(_admin_dsn(DBNAME), row_factory=dict_row) as c:
        return c.execute(sql, params).fetchall()


def as_owner(sql, params=()):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute(sql, params)


# ── RLS ────────────────────────────────────────────────────────────────────
def test_only_admins_create_teams(db):
    with db.scoped(ADMIN) as c:
        tid = T.create_team(c, ADMIN, "Platform Security")
    assert tid == "platform_security"
    assert owner("select source, created_by from teams where id = %s", (tid,))[0] == \
        {"source": "dashboard", "created_by": "user-admin"}
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH_LEAD) as c:
            c.execute("insert into teams (id, name, source) values ('rogue', 'Rogue', 'dashboard')")


def test_lead_manages_own_members_only(db):
    with db.scoped(GROWTH_LEAD) as c:
        T.set_member(c, GROWTH_LEAD, "growth_engineering", "Dev@Example.com")
    assert owner("select email, role from team_members")[0] == {"email": "dev@example.com", "role": "member"}
    # a lead can't make leads, can't touch another team
    for team, role in (("growth_engineering", "lead"), ("uk_engineering", "member")):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with db.scoped(GROWTH_LEAD) as c:
                T.set_member(c, GROWTH_LEAD, team, "x@example.com", role)
    # plain members can't add anyone
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH) as c:
            T.set_member(c, GROWTH, "growth_engineering", "y@example.com")


def test_team_rows_are_visible_to_the_team_only(db):
    as_owner("insert into team_members (team_id, email, role, added_by) values "
             "('growth_engineering','a@x.io','member','t'),('uk_engineering','b@x.io','member','t')")
    with db.scoped(GROWTH) as c:
        assert [r["email"] for r in c.execute("select email from team_members").fetchall()] == ["a@x.io"]
        view = T.overview(c, GROWTH)
    assert [t["id"] for t in view["teams"]] == ["growth_engineering"] and view["unowned_repos"] == []
    with db.scoped(ADMIN) as c:
        view = T.overview(c, ADMIN)
    assert {t["id"] for t in view["teams"]} == {"growth_engineering", "uk_engineering"}
    assert view["unowned_repos"] == ["orphan-repo"]


def test_slack_webhook_is_never_returned(db):
    hook = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"
    with db.scoped(GROWTH_LEAD) as c:
        T.set_settings(c, GROWTH_LEAD, "growth_engineering", {"slack_webhook": hook, "sla_days": {"high": 14}})
        view = T.overview(c, GROWTH_LEAD)
    s = view["teams"][0]["settings"]
    assert s["slack"] is True and "SECRET" not in json.dumps(view) and s["sla_days"] == {"critical": 7, "high": 14}


@pytest.mark.parametrize("body,msg", [
    ({"slack_webhook": "https://evil.example.com/hook"}, "hooks.slack.com"),
    ({"jira_enabled": True}, "project key before"),
    ({"jira_project": "bad key"}, "project key"),
    ({"sla_days": {"high": 0}}, "1 to 365"),
    ({"sla_days": {"medium": 5}}, "sla_days"),
])
def test_settings_validation(db, body, msg):
    with pytest.raises(T.TeamError, match=msg):
        with db.scoped(ADMIN) as c:
            T.set_settings(c, ADMIN, "growth_engineering", body)


@pytest.mark.parametrize("url", ["http://localhost:8080/", "https://10.0.0.5/", "ftp://x.io", "https://a b"])
def test_dast_targets_must_be_public_http(url):
    with pytest.raises(T.TeamError):
        T.norm_url(url)


# ── Sign-in ────────────────────────────────────────────────────────────────
def test_sign_in_uses_dashboard_membership_by_email(db):
    as_owner("insert into team_members (team_id, email, role, added_by) values "
             "('uk_engineering','new.dev@corp.com','member','admin')")
    s = resolve_scope({"oid": "u1", "preferred_username": "New.Dev@corp.com", "groups": [], "roles": []}, db)
    assert s.team_ids == ("uk_engineering",) and s.role == "team_member"
    # legacy Entra group mapping still counts, and the two combine
    s = resolve_scope({"oid": "u1", "email": "new.dev@corp.com", "groups": ["g-growth"], "roles": []}, db)
    assert s.team_ids == ("growth_engineering", "uk_engineering")


def test_lead_only_when_lead_of_every_team(db):
    as_owner("insert into team_members (team_id, email, role, added_by) values "
             "('uk_engineering','l@corp.com','lead','admin')")
    assert resolve_scope({"oid": "u", "email": "l@corp.com", "roles": []}, db).role == "team_lead"
    as_owner("insert into team_members (team_id, email, role, added_by) values "
             "('growth_engineering','l@corp.com','member','admin')")
    # lead of one, member of another: member rights everywhere, never more
    assert resolve_scope({"oid": "u", "email": "l@corp.com", "roles": []}, db).role == "team_member"


def test_archived_team_grants_nothing(db):
    as_owner("insert into team_members (team_id, email, role, added_by) values ('uk_engineering','a@corp.com','member','x')")
    as_owner("update teams set archived_at = now() where id = 'uk_engineering'")
    with pytest.raises(AuthError, match="not in any team"):
        resolve_scope({"oid": "u", "email": "a@corp.com", "roles": []}, db)


# ── Instant reassignment ───────────────────────────────────────────────────
def test_assigning_a_repo_moves_its_findings_now(db):
    with db.scoped(ADMIN) as c:
        out = T.set_asset(c, ADMIN, "uk_engineering", "repo", "mktp-growth-api")
    assert out["findings_moved"] == 2          # dependabot + readme on that repo
    assert owner("select team_id, source from repo_owners where repo = 'mktp-growth-api'")[0] == \
        {"team_id": "uk_engineering", "source": "dashboard"}
    assert owner("select team_id from findings where fingerprint = %s", (G_CRIT,))[0]["team_id"] == "uk_engineering"
    # the growth team no longer sees it; uk does
    with db.scoped(GROWTH) as c:
        assert not c.execute("select 1 from findings where fingerprint = %s", (G_CRIT,)).fetchone()


def test_only_admins_move_repos(db):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.scoped(GROWTH_LEAD) as c:
            T.set_asset(c, GROWTH_LEAD, "growth_engineering", "repo", "mktp-uk-site")
    with db.scoped(GROWTH_LEAD) as c:        # and can't re-team findings directly: RLS matches no rows
        assert c.execute("update findings set team_id = 'growth_engineering' where fingerprint = %s",
                         (U_HIGH,)).rowcount == 0
    assert owner("select team_id from findings where fingerprint = %s", (U_HIGH,))[0]["team_id"] == "uk_engineering"


# ── API through the chat function ──────────────────────────────────────────
@pytest.fixture()
def api(db):
    def call(claims, method, path, body=None):
        set_deps(Deps(settings=Settings.from_env(), db=db, verifier=FakeVerifier(claims), llm_for=None, github=None))
        e = event(body or {})
        e["rawPath"] = f"/api/{path}"
        e["requestContext"] = {"http": {"method": method}}
        if method == "GET":
            e["queryStringParameters"] = body or {}
        r = chat.handler(e, None)
        return r["statusCode"], json.loads(r["body"])
    yield call
    set_deps(None)


ADMIN_CLAIMS = {"oid": "user-admin", "roles": ["security.admin"], "groups": []}
GROWTH_CLAIMS = {"oid": "user-growth", "groups": ["g-growth"], "roles": []}


def test_api_team_lifecycle(api):
    assert api(ADMIN_CLAIMS, "POST", "teams/create", {"name": "Payments"})[1]["team_id"] == "payments"
    assert api(ADMIN_CLAIMS, "POST", "teams/member", {"team_id": "payments", "email": "p@corp.com", "role": "lead"})[0] == 200
    st, out = api(ADMIN_CLAIMS, "POST", "teams/assign", {"team_id": "payments", "repos": ["orphan-repo"]})
    assert st == 200 and out["findings_moved"] == 1
    assert api(ADMIN_CLAIMS, "POST", "teams/asset", {"team_id": "payments", "kind": "url", "value": "https://pay.example.com"})[0] == 200
    teams = {t["id"]: t for t in api(ADMIN_CLAIMS, "GET", "teams")[1]["teams"]}
    assert teams["payments"]["members"][0]["email"] == "p@corp.com"
    assert {a["value"] for a in teams["payments"]["assets"]} == {"orphan-repo", "https://pay.example.com/"}
    # the new lead signs in by e-mail and sees their team
    st, out = api({"oid": "p1", "email": "p@corp.com", "roles": []}, "GET", "teams")
    assert st == 200 and [t["id"] for t in out["teams"]] == ["payments"] and out["teams"][0]["can_manage"]


def test_api_refuses_non_admin_team_changes(api):
    for path, body in (("teams/create", {"name": "X"}), ("teams/asset", {"team_id": "growth_engineering", "kind": "repo",
                       "value": "mktp-uk-site"}), ("teams/rule", {"team_id": "growth_engineering", "kind": "topic", "value": "x"})):
        assert api(GROWTH_CLAIMS, "POST", path, body)[0] == 403
    assert api(GROWTH_CLAIMS, "POST", "teams/member", {"team_id": "growth_engineering", "email": "z@corp.com"})[0] == 403
    assert api(ADMIN_CLAIMS, "POST", "teams/member", {"team_id": "nope", "email": "z@corp.com"})[0] == 400


# ── Ingest precedence ──────────────────────────────────────────────────────
@pytest.fixture()
def iconn(pg):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute("truncate teams, repo_owners, findings, finding_events, weekly_aggregates, runs, run_collectors, "
                  "investigations, team_notes, session_turns, user_prefs, audit_log cascade")
    with psycopg.connect(f"host={HOST} port={PORT} user=ingest_login dbname={DBNAME}",
                         autocommit=True, row_factory=dict_row) as c:
        yield c


def _run(conn, store, run_id, gh, extra=()):
    results = [store.put(run_id, ownership.collect(gh)), store.put(run_id, dependabot.collect(gh)), *extra]
    return ingest_mod.ingest(conn, run_id, results, store.load, now=T0)


def test_dashboard_assignment_beats_rules_beats_yaml(iconn):
    gh = OrgGitHub(repos=[{"name": "mktp-uk-site"}, {"name": "random-tool", "topics": ["payments"]},
                          {"name": "pay-api"}], alerts=[alert("random-tool", "GHSA-1111-2222-3333", "high")])
    _run(iconn, Store(), "r1", gh)
    iconn.execute("insert into teams (id, name, source) values ('payments', 'Payments', 'dashboard')")
    iconn.execute("insert into team_rules (team_id, kind, value, added_by) values ('payments','topic','payments','a'),"
                  "('payments','name_prefix','pay-','a')")
    iconn.execute("insert into team_assets (kind, value, team_id, added_by) values ('repo','mktp-uk-site','payments','a')")
    _run(iconn, Store(), "r2", gh)
    owners = {r["repo"]: (r["team_id"], r["source"]) for r in iconn.execute("select * from repo_owners").fetchall()}
    assert owners["mktp-uk-site"] == ("payments", "dashboard")                    # explicit beats YAML admin rule
    assert owners["random-tool"] == ("payments", "dashboard rule: topic payments")
    assert owners["pay-api"] == ("payments", "dashboard rule: name_prefix pay-")
    assert iconn.execute("select team_id from findings where resource = 'random-tool' and source = 'dependabot'"
                         ).fetchone()["team_id"] == "payments"


def test_yaml_never_overwrites_a_dashboard_team(iconn):
    _run(iconn, Store(), "r1", OrgGitHub())
    iconn.execute("update teams set name = 'Apps (renamed)', source = 'dashboard' where id = 'uk_engineering'")
    _run(iconn, Store(), "r2", OrgGitHub())
    assert iconn.execute("select name from teams where id = 'uk_engineering'").fetchone()["name"] == "Apps (renamed)"


def test_partial_scan_only_closes_what_it_scanned(iconn):
    _run(iconn, Store(), "r0", OrgGitHub())
    store = Store()

    def sast(scanned, repos_with_hits):
        out = CollectorOutput("sast", complete=True, scope_resources=scanned)
        out.findings = [FindingRecord(source="sast", resource=r, rule="py.sqli", location="a.py#abc",
                                      title="sqli", severity="high") for r in repos_with_hits]
        return out
    ingest_mod.ingest(iconn, "r1", [store.put("r1", sast(["mktp-uk-site", "de-pipeline"], ["mktp-uk-site", "de-pipeline"]))],
                      store.load, now=T0)
    # next week de-pipeline failed to clone: its finding must stay open; mktp-uk-site was fixed
    ingest_mod.ingest(iconn, "r2", [store.put("r2", sast(["mktp-uk-site"], []))], store.load, now=T0)
    status = {r["resource"]: r["status"] for r in iconn.execute("select resource, status from findings where source='sast'")}
    assert status == {"mktp-uk-site": "fixed", "de-pipeline": "open"}


def test_dast_findings_follow_the_url_owner(iconn):
    _run(iconn, Store(), "r0", OrgGitHub())
    iconn.execute("insert into team_assets (kind, value, team_id, added_by) values "
                  "('url','https://shop.example.com/','de','a')")
    store = Store()
    out = CollectorOutput("dast", complete=True, scope_resources=["https://shop.example.com/"])
    out.findings = [FindingRecord(source="dast", resource="https://shop.example.com/", rule="zap-10038",
                                  title="CSP missing", severity="medium", team_hint="uk_engineering")]
    ingest_mod.ingest(iconn, "r1", [store.put("r1", out)], store.load, now=T0)
    assert iconn.execute("select team_id from findings where source = 'dast'").fetchone()["team_id"] == "de"
