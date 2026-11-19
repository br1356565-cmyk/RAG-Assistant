"""SAST/DAST collectors, the scanner drivers' pure parts, the weekly digest and the Jira sync."""
import hashlib
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

import psycopg
import pytest
from psycopg.rows import dict_row

from audit_agent import digest, jira
from audit_agent.collectors import dast, sast
from audit_agent.handlers import deliver, prepare

from conftest import DBNAME, HOST, PORT, ROOT, _admin_dsn

NOW = datetime.now(timezone.utc)


class FakeS3:
    def __init__(self, objs=None):
        self.objs = dict(objs or {})
        self.puts = {}

    def get_object(self, Bucket, Key):
        if Key not in self.objs:
            raise KeyError(Key)
        body = self.objs[Key]

        class B:
            def read(self_inner):
                return json.dumps(body).encode()
        return {"Body": B()}

    def put_object(self, Bucket, Key, Body, ContentType=None):
        self.puts[Key] = json.loads(Body)


# ── SAST ───────────────────────────────────────────────────────────────────
def semgrep_result(check="python.lang.security.audit.formatted-sql-query", path="app/db.py", line=10,
                   sev="ERROR", sha="aaa111", conf="HIGH", impact="HIGH"):
    return {"check_id": check, "path": path, "line": line, "end_line": line, "severity": sev, "message": "SQL built",
            "snippet_sha": sha, "confidence": conf, "impact": impact, "cwe": ["CWE-89"]}


def test_sast_identity_survives_line_moves_and_severity_maps():
    a, _ = sast.to_findings("api", [semgrep_result(line=10)])
    b, _ = sast.to_findings("api", [semgrep_result(line=42)])          # same code, moved down
    assert a[0].fingerprint == b[0].fingerprint and a[0].severity == "critical"
    c, _ = sast.to_findings("api", [semgrep_result(sev="WARNING", conf="LOW")])
    assert c[0].severity == "medium" and "line" in c[0].details


def test_sast_collector_scopes_to_scanned_repos_and_fails_without_manifest():
    s3 = FakeS3({"runs/r1/sast-raw/_manifest.json": {"scanned": ["api"], "failed": {"web": "clone failed"}},
                 "runs/r1/sast-raw/api.json": {"repo": "api", "results": [semgrep_result()]}})
    out = sast.collect(s3, "b", "r1")
    assert out.scope_resources == ["api"] and len(out.findings) == 1 and "web" in out.warnings[0]
    with pytest.raises(RuntimeError, match="no SAST scan output"):
        sast.collect(FakeS3(), "b", "r1")


def test_sast_caps_noisy_repos():
    res = [semgrep_result(sha=f"s{i}", sev="INFO") for i in range(sast.MAX_PER_REPO + 5)]
    found, dropped = sast.to_findings("noisy", res)
    assert len(found) == sast.MAX_PER_REPO and dropped == 5


def _load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "src" / "scanner" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sast_driver_keeps_no_code(tmp_path):
    drv = _load_script("sast_scan")
    (tmp_path / "a.py").write_text("x = 1\npassword = 'hunter2-super-secret'\n")
    r = drv.slim({"check_id": "generic.secrets.hardcoded", "path": "a.py", "start": {"line": 2}, "end": {"line": 2},
                  "extra": {"severity": "ERROR", "message": "Hardcoded secret", "lines": "password = 'hunter2'",
                            "metadata": {"confidence": "HIGH"}}}, tmp_path)
    assert "hunter2" not in json.dumps(r) and len(r["snippet_sha"]) == 12
    # whitespace-only edits keep the identity
    (tmp_path / "a.py").write_text("x = 1\npassword   =  'hunter2-super-secret'\n")
    assert drv.snippet_hash(tmp_path, "a.py", 2, 2) == r["snippet_sha"]


# ── DAST ───────────────────────────────────────────────────────────────────
ZAP = {"site": [{"@name": "https://shop.example.com", "alerts": [
    {"pluginid": "10038", "name": "Content Security Policy (CSP) Header Not Set", "riskcode": "2",
     "riskdesc": "Medium (High)", "confidence": "3", "cweid": "693", "desc": "<p>No CSP</p>",
     "solution": "<p>Set the header</p>", "instances": [{"uri": "https://shop.example.com/", "method": "GET",
                                                          "evidence": "<script>steal()</script>"}]},
    {"pluginid": "10049", "name": "Storable content", "riskcode": "0", "instances": []},
]}]}


def test_dast_parses_zap_and_drops_evidence_and_info():
    out = dast.to_findings("https://shop.example.com/", "web", ZAP)
    assert len(out) == 1
    f = out[0]
    assert (f.rule, f.severity, f.team_hint) == ("zap-10038", "medium", "web")
    assert "steal()" not in json.dumps(f.details) and f.details["solution"] == "Set the header"


def test_dast_collector_reads_manifest():
    url = "https://shop.example.com/"
    key = hashlib.sha256(url.encode()).hexdigest()[:16]
    s3 = FakeS3({"runs/r1/dast-raw/_manifest.json": {"scanned": [url], "failed": {}},
                 f"runs/r1/dast-raw/{key}.json": {"url": url, "team_id": "web", "report": ZAP}})
    out = dast.collect(s3, "b", "r1")
    assert out.scope_resources == [url] and out.findings[0].resource == url


# ── DB-backed: prepare, digest, Jira ───────────────────────────────────────
@pytest.fixture()
def iconn(seeded):
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute("insert into team_members (team_id, email, role, added_by) values "
                  "('growth_engineering','dev@corp.com','member','a'),('growth_engineering','lead@corp.com','lead','a')")
        c.execute("insert into team_assets (kind, value, team_id, added_by) values "
                  "('url','https://shop.example.com/','growth_engineering','a')")
    with psycopg.connect(f"host={HOST} port={PORT} user=ingest_login dbname={DBNAME}",
                         autocommit=True, row_factory=dict_row) as c:
        yield c


def test_prepare_exports_dast_targets(iconn):
    s3 = FakeS3()
    assert prepare.export(iconn, s3, "b") == {"dast_targets": 1}
    assert s3.puts["config/dast_targets.json"] == [{"url": "https://shop.example.com/", "team_id": "growth_engineering"}]


class FakeSES:
    def __init__(self, fail_for=()):
        self.sent, self.fail_for = [], set(fail_for)

    def send_email(self, FromEmailAddress, Destination, Content):
        to = Destination["ToAddresses"][0]
        if to in self.fail_for:
            raise RuntimeError("MessageRejected: address not verified")
        self.sent.append({"to": to, "subject": Content["Simple"]["Subject"]["Data"],
                          "html": Content["Simple"]["Body"]["Html"]["Data"]})


class FakeHTTP:
    def __init__(self):
        self.posts = []

    def post(self, url, json, timeout):
        self.posts.append((url, json))

        class R:
            status_code = 200
        return R()


def test_digest_goes_to_each_member_and_the_team_channel(iconn):
    iconn.execute("insert into team_settings (team_id, slack_webhook) values "
                  "('growth_engineering','https://hooks.slack.com/services/T/B/x')")
    iconn.execute("update findings set title = '<img src=x onerror=alert(1)>' where severity = 'critical'")
    ses, http = FakeSES(fail_for={"lead@corp.com"}), FakeHTTP()
    out = digest.deliver(iconn, ses=ses, http=http, sender="audit@corp.com", dashboard_url="https://d.example.com/")
    assert [m["to"] for m in ses.sent] == ["dev@corp.com"] and out["emails"] == 1 and out["slack"] == 1
    assert "lead@corp.com" in out["errors"][0]                       # one bad address doesn't stop the rest
    assert "<img" not in ses.sent[0]["html"] and "&lt;img" in ses.sent[0]["html"]
    assert ses.sent[0]["subject"].startswith("[DevOps audit] Growth Engineering: 1 critical")
    assert http.posts[0][0].endswith("/T/B/x") and "Growth Engineering" in http.posts[0][1]["text"]


def test_digest_counts_overdue_against_team_sla(iconn):
    iconn.execute("insert into team_settings (team_id, sla_days) values ('growth_engineering', '{\"critical\": 30}')")
    d = digest.build(iconn, {"id": "growth_engineering", "name": "G"}, NOW, {"critical": 30})
    assert d["overdue"] == 1                                         # the critical one is 41 days old
    assert digest.build(iconn, {"id": "growth_engineering", "name": "G"}, NOW, {"critical": 60})["overdue"] == 0


class FakeJira:
    def __init__(self):
        self.created, self.comments, self.closed, self.n = [], [], [], 0

    def account_id(self, email):
        return None if not email else f"acc-{email.split('@')[0]}"

    def create(self, project, issue_type, summary, description, labels, assignee=None, priority=None):
        self.n += 1
        self.created.append({"project": project, "summary": summary, "assignee": assignee, "priority": priority,
                             "labels": labels})
        return f"{project}-{self.n}"

    def comment(self, key, body):
        self.comments.append((key, body))

    def close(self, key):
        self.closed.append(key)
        return True


def test_jira_create_close_and_follow_up(iconn):
    iconn.execute("insert into team_settings (team_id, jira_enabled, jira_project, jira_assignee, sla_days) values "
                  "('growth_engineering', true, 'SEC', 'owner@corp.com', '{\"critical\": 7, \"high\": 30}')")
    j = FakeJira()
    out = jira.sync(iconn, j, now=NOW)
    # only high+ (the critical one), one ticket per repo+rule; uk team has Jira off
    assert out["created"] == 1 and j.created[0]["project"] == "SEC" and j.created[0]["priority"] == "Highest"
    assert j.created[0]["assignee"] == "acc-owner" and "[CRITICAL]" in j.created[0]["summary"]
    assert jira.sync(iconn, j, now=NOW)["created"] == 0               # idempotent
    # 10 days later, past the 7-day SLA: one follow-up mentioning assignee + lead, then not again for a week
    later = NOW + timedelta(days=10)
    assert jira.sync(iconn, j, now=later)["followups"] == 1
    mentions = [n["attrs"]["id"] for n in j.comments[-1][1]["content"][0]["content"] if n["type"] == "mention"]
    assert mentions == ["acc-owner", "acc-lead"]
    assert jira.sync(iconn, j, now=later + timedelta(days=2))["followups"] == 0
    # fixed: the ticket closes itself
    iconn.execute("update findings set status = 'fixed' where severity = 'critical'")
    out = jira.sync(iconn, j, now=later + timedelta(days=3))
    assert out["closed"] == 1 and j.closed == ["SEC-1"]
    assert iconn.execute("select status from jira_tickets").fetchone()["status"] == "closed"
    # it comes back: a new ticket, same row
    iconn.execute("update findings set status = 'open' where severity = 'critical'")
    assert jira.sync(iconn, j, now=later + timedelta(days=4))["created"] == 1
    assert iconn.execute("select issue_key, status from jira_tickets").fetchone() == {"issue_key": "SEC-2", "status": "open"}


def test_jira_caps_creation_per_run(iconn):
    iconn.execute("insert into team_settings (team_id, jira_enabled, jira_project) values ('growth_engineering', true, 'SEC')")
    iconn.execute("update findings set severity = 'high' where team_id = 'growth_engineering' and data_class = 'team'")
    out = jira.sync(iconn, FakeJira(), now=NOW, max_create=1)
    assert out["created"] == 1 and out["deferred"] == 1


def test_deliver_never_raises(iconn):
    class Boom(FakeJira):
        def create(self, *a, **k):
            raise jira.JiraError("HTTP 401")
    iconn.execute("insert into team_settings (team_id, jira_enabled, jira_project) values ('growth_engineering', true, 'SEC')")
    out = deliver.run(iconn, ses=None, http=None, jira_client=Boom(), sender=None, dashboard_url="", max_create=5)
    assert out["jira"]["created"] == 0 and "401" in out["jira"]["errors"][0] and "teams" in out["digest"]


def test_jira_client_rejects_non_https():
    with pytest.raises(jira.JiraError):
        jira.JiraClient("http://x.atlassian.net", "a@b.c", "t")


def test_scanner_scripts_are_self_contained():
    """The drivers run inside the semgrep / ZAP images: stdlib + boto3/PyJWT only, no audit_agent."""
    for name in ("sast_scan", "dast_scan"):
        src = (ROOT / "src" / "scanner" / f"{name}.py").read_text()
        assert "audit_agent" not in src and "import httpx" not in src
