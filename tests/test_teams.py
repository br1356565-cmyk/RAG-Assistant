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
        view = T.summary(c, GROWTH)
        repos = T.list_repos(c, GROWTH)
        with pytest.raises(T.TeamError):
            T.detail(c, GROWTH, "uk_engineering")
    assert [t["id"] for t in view["teams"]] == ["growth_engineering"] and "unowned" not in view
    assert [r["repo"] for r in repos["repos"]] == ["mktp-growth-api"]       # only its own repos
    with db.scoped(ADMIN) as c:
        view = T.summary(c, ADMIN)
        unowned = T.list_repos(c, ADMIN, team="unowned")
    assert {t["id"] for t in view["teams"]} == {"growth_engineering", "uk_engineering"}
    assert view["unowned"] == 1 and [r["repo"] for r in unowned["repos"]] == ["orphan-repo"]


def test_slack_webhook_is_never_returned(db):
    hook = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"
    with db.scoped(GROWTH_LEAD) as c:
        T.set_settings(c, GROWTH_LEAD, "growth_engineering", {"slack_webhook": hook, "sla_days": {"high": 14}})
        view = T.detail(c, GROWTH_LEAD, "growth_engineering")
    s = view["settings"]
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
    d = api(ADMIN_CLAIMS, "GET", "teams/detail", {"team_id": "payments"})[1]
    assert d["members"][0]["email"] == "p@corp.com" and d["urls"][0]["url"] == "https://pay.example.com/"
    assert d["pinned_repos"] == 1 and d["activity"][0]["action"] == "set_asset"
    # the new lead signs in by e-mail and sees their team
    st, out = api({"oid": "p1", "email": "p@corp.com", "roles": []}, "GET", "teams")
    assert st == 200 and [t["id"] for t in out["teams"]] == ["payments"] and out["teams"][0]["can_manage"]
    assert out["teams"][0]["repos"] == 1 and out["teams"][0]["members"] == 1


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


# ── At scale: inventory, bulk, rules, import ───────────────────────────────
@pytest.fixture()
def many(db):
    rows = ",".join(f"('svc-{i:03d}', null, 'no rule matched', '{{\"team-pay\"}}')" if i % 3 == 0 else
                    f"('svc-{i:03d}', null, 'no rule matched', '{{}}')" for i in range(120))
    as_owner(f"insert into repo_owners (repo, team_id, source, topics) values {rows}")
    as_owner("insert into repo_owners (repo, team_id, source) values ('pay-ledger', 'uk_engineering', 'rule: x')")
    return db


def test_repo_inventory_paginates_filters_and_sorts(many):
    with many.scoped(ADMIN) as c:
        p1 = T.list_repos(c, ADMIN, team="unowned", size=50)
        p3 = T.list_repos(c, ADMIN, team="unowned", size=50, page=3)
        search = T.list_repos(c, ADMIN, q="svc-01")
        topic = T.list_repos(c, ADMIN, q="team-pay")
        by_high = T.list_repos(c, ADMIN, sort="high", size=1)
        cfg = T.list_repos(c, ADMIN, source="config")
        with pytest.raises(T.TeamError):
            T.list_repos(c, ADMIN, sort="drop table")
    assert p1["total"] == 121 and p1["pages"] == 3 and len(p1["repos"]) == 50 and len(p3["repos"]) == 21
    assert [r["repo"] for r in search["repos"]] == [f"svc-{i:03d}" for i in range(10, 20)]
    assert topic["total"] == 40                                     # matched by topic, not just name
    assert by_high["repos"][0]["repo"] == "mktp-growth-api"        # the critical finding sorts first
    assert {r["repo"] for r in cfg["repos"]} >= {"mktp-growth-api", "pay-ledger"}


def test_like_wildcards_are_escaped(many):
    with many.scoped(ADMIN) as c:
        assert T.list_repos(c, ADMIN, q="%")["total"] == 0 and T.list_repos(c, ADMIN, q="_")["total"] == 0


def test_bulk_assign_by_filter_and_unpin(many):
    with many.scoped(ADMIN) as c:
        targets = T.matching_repos(c, ADMIN, q="svc-0")
        out = T.bulk_assign(c, ADMIN, "growth_engineering", targets)
    assert out["assigned"] == 100
    assert owner("select count(*) n from repo_owners where team_id = 'growth_engineering' and source = 'dashboard'")[0]["n"] == 100
    with many.scoped(ADMIN) as c:
        assert T.bulk_unpin(c, ADMIN, targets[:10])["unpinned"] == 10
        assert T.list_repos(c, ADMIN, source="dashboard")["total"] == 90
    assert owner("select count(*) n from team_changes where action in ('bulk_assign','bulk_unpin')")[0]["n"] == 2


def test_rule_preview_and_apply_now_respect_precedence(many):
    as_owner("insert into team_assets (kind, value, team_id, added_by) values ('repo','svc-003','uk_engineering','a')")
    as_owner("update repo_owners set team_id = 'uk_engineering', source = 'dashboard' where repo = 'svc-003'")
    with many.scoped(ADMIN) as c:
        prev = T.rule_matches(c, "topic", "team-pay")
        out = T.apply_rule_now(c, ADMIN, "growth_engineering", "topic", "team-pay")
    assert prev["count"] == 40 and prev["would_change"] == 39       # the explicitly assigned one is kept
    assert out == {"matched": 40, "changed": 39, "findings_moved": 0}
    assert owner("select team_id from repo_owners where repo = 'svc-003'")[0]["team_id"] == "uk_engineering"
    assert owner("select source from repo_owners where repo = 'svc-006'")[0]["source"] == "dashboard rule: topic team-pay"
    # a later rule never steals repos an earlier dashboard rule already owns
    with many.scoped(ADMIN) as c:
        assert T.rule_matches(c, "name_prefix", "svc-00")["would_change"] == 6   # svc-000..009 minus 000,003,006,009


def test_import_applies_valid_rows_and_reports_bad_ones(many):
    text = "repo,team\nsvc-001,growth_engineering\nsvc-002,App Engineering\nsvc-004,nope\nbad name!,de\nnew-repo,uk_engineering"
    with many.scoped(ADMIN) as c:
        out = T.import_ownership(c, ADMIN, text)
    assert out["applied"] == 3 and [e["line"] for e in out["errors"]] == [4, 5] and out["unknown_repos"] == ["new-repo"]
    assert owner("select team_id from repo_owners where repo = 'svc-002'")[0]["team_id"] == "uk_engineering"  # by name
    with many.scoped(ADMIN) as c:                                    # mostly garbage: nothing applied
        assert T.import_ownership(c, ADMIN, "a,x\nb,y\nsvc-007,de")["applied"] == 0


def test_bulk_add_members(many):
    with many.scoped(GROWTH_LEAD) as c:
        out = T.add_members(c, GROWTH_LEAD, "growth_engineering", "a@corp.com, B@corp.com\nnot-an-email; c@corp.com")
    assert out == {"added": 3, "invalid": ["not-an-email"]}


def test_api_repos_and_bulk_routes(api, many):
    st, out = api(ADMIN_CLAIMS, "GET", "teams/repos", {"team": "unowned", "size": "10", "page": "2"})
    assert st == 200 and out["page"] == 2 and len(out["repos"]) == 10
    st, out = api(ADMIN_CLAIMS, "POST", "teams/assign", {"team_id": "uk_engineering", "filter": {"q": "svc-11"}})
    assert st == 200 and out["assigned"] == 10
    assert api(ADMIN_CLAIMS, "GET", "teams/rule-preview", {"kind": "name_prefix", "value": "svc-"})[1]["count"] == 120
    assert api(GROWTH_CLAIMS, "POST", "teams/assign", {"team_id": "growth_engineering", "repos": ["svc-001"]})[0] == 403
    assert api(GROWTH_CLAIMS, "POST", "teams/import", {"text": "svc-001,growth_engineering"})[0] == 403
    assert api(GROWTH_CLAIMS, "GET", "teams/activity")[0] == 403
    assert len(api(ADMIN_CLAIMS, "GET", "teams/repos/export")[1]["repos"]) == 124
