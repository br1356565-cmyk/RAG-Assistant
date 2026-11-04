"""The local prototype: run_weekly end to end, then the dev server over real HTTP."""
import json
import re
import sys
import threading
import urllib.error
import urllib.request

import pytest

from audit_agent.config import Settings
from audit_agent.db import Database
from audit_agent.handlers.deps import Deps

from conftest import DBNAME, HOST, PORT, FakeGitHub, FakeLLM, call, say, tools
from test_collectors import OrgGitHub, alert
from test_ingest import conn  # noqa: F401  (fixture: empty database)

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "local"))
import dev_server  # noqa: E402
import run_weekly  # noqa: E402
from devauth import DevVerifier, load_personas  # noqa: E402

GHSA = "GHSA-2c3f-4g5h-6j7m"
APP = f"host={HOST} port={PORT} user=app_login dbname={DBNAME}"
INGEST = f"host={HOST} port={PORT} user=ingest_login dbname={DBNAME}"


def investigation_llm():
    """Investigates whatever finding it's given: looks up the advisory, then submits."""
    def submit(messages):
        fid = re.search(r'"id":"(F-[0-9a-f]{16})"', messages[1]["content"]).group(1)
        return tools(call("submit_investigation", {
            "summary": "example-http-lib below 2.3.4 lets a crafted header crash the service.",
            "impact": {"verdict": "likely", "reasoning": "Runtime dependency."},
            "fix": {"action": "Upgrade example-http-lib to 2.3.4.", "target_version": "2.3.4",
                    "breaking_changes": "none_listed"},
            "sources": [{"kind": "finding", "ref": fid}, {"kind": "advisory", "ref": GHSA}],
            "confidence": "high"}))
    return FakeLLM([tools(call("get_advisory", {"ghsa_id": GHSA})), submit] * 5)


@pytest.fixture()
def weekly(conn, tmp_path):
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", GHSA, "critical"), alert("exp-motors", GHSA, "high", pkg="lib-b")])
    gh.advisory = FakeGitHub().advisory
    lines = []
    result = run_weekly.run(github=gh, llm_for=lambda t: investigation_llm(), app_dsn=APP, ingest_dsn=INGEST,
                            collectors=["ownership", "dependabot"], max_investigations=10,
                            data_dir=tmp_path, log=lines.append)
    return result, lines


def test_run_weekly_collects_ingests_and_investigates(weekly):
    result, lines = weekly
    assert [i["status"] for i in result["investigations"]] == ["investigated", "investigated"]
    assert any("collected dependabot: 2 findings" in l for l in lines)
    assert "DevOps audit run" in lines[-1]


def test_dev_server_brief_and_chat_respect_personas(weekly):
    personas = load_personas()
    chat_llm = FakeLLM([tools(call("search_findings", {"severity": ["critical"]})), say("Fix the critical one.")])
    deps = Deps(settings=Settings.from_env(), db=Database(dsn=APP), verifier=DevVerifier(personas),
                llm_for=lambda t: chat_llm, github=FakeGitHub())
    server = dev_server.serve(deps, personas, port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    def get(path, persona=None):
        req = urllib.request.Request(base + path, headers={"x-user-authorization": f"Bearer dev:{persona}"} if persona else {})
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode()

    try:
        assert '"devMode": true' in get("/config.js")[1]
        assert "<title>DevOps Audit Assistant</title>" in get("/")[1]

        uk = json.loads(get("/api/brief", "uk-lead")[1])
        assert [t["id"] for t in uk["teams"]] == ["uk_engineering"]
        assert uk["teams"][0]["top"][0]["summary"].startswith("example-http-lib")   # stored investigation
        exp = json.loads(get("/api/brief", "growth-engineer")[1])
        assert exp["teams"][0]["top"] == []                                         # growth owns neither repo
        admin = json.loads(get("/api/brief", "security-admin")[1])
        assert admin["unowned_repos"] == 2

        with pytest.raises(urllib.error.HTTPError) as e:
            get("/api/brief", "nobody")
        assert e.value.code == 401

        body = json.dumps({"question": "What should we fix first?"}).encode()
        req = urllib.request.Request(base + "/api/chat", data=body, method="POST", headers={
            "content-type": "application/json", "x-user-authorization": "Bearer dev:uk-lead"})
        with urllib.request.urlopen(req) as r:
            answer = json.loads(r.read())
        assert answer["answer"] == "Fix the critical one." and answer["status"] == "answered"
        found = json.loads([m for m in chat_llm.calls[1]["messages"] if m["role"] == "tool"][0]["content"])
        assert {f["resource"] for f in found["findings"]} == {"mktp-growth-api"}    # UK's repo only
    finally:
        server.shutdown()
        deps.db.close()


def test_guard_refuses_to_run_in_aws(monkeypatch):
    import common
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "x")
    with pytest.raises(SystemExit):
        common.guard_local()


def test_dev_server_runs_chat_as_a_job_with_progress(weekly):
    import time
    personas = load_personas()
    chat_llm = FakeLLM([tools(call("search_findings", {"severity": ["critical"]})), say("Fix the critical one.")])
    deps = Deps(settings=Settings.from_env(), db=Database(dsn=APP), verifier=DevVerifier(personas),
                llm_for=lambda t: chat_llm, github=FakeGitHub())
    deps.dispatch = dev_server.thread_dispatcher(deps, lambda: Database(dsn=APP))
    server = dev_server.serve(deps, personas, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    auth = {"x-user-authorization": "Bearer dev:uk-lead"}
    try:
        req = urllib.request.Request(base + "/api/chat", method="POST", data=json.dumps(
            {"question": "What should we fix first?"}).encode(), headers={"content-type": "application/json", **auth})
        with urllib.request.urlopen(req) as r:
            assert r.status == 202
            job_id = json.loads(r.read())["job_id"]
        for _ in range(50):
            with urllib.request.urlopen(urllib.request.Request(f"{base}/api/chat/job?id={job_id}", headers=auth)) as r:
                job = json.loads(r.read())
            if job["status"] != "running":
                break
            time.sleep(0.1)
        assert job["status"] == "done", job
        assert "Searching critical findings" in job["steps"]
        assert job["result"]["answer"] == "Fix the critical one."
    finally:
        server.shutdown()
        deps.db.close()


def test_dev_server_review_and_fix_flow(weekly, tmp_path, monkeypatch):
    """Draft a fix as an engineer, approve it as the lead, get a (dry-run) pull request."""
    from fix_local import build_fix_client

    class Repo(FakeGitHub):
        def read_file(self, repo, path):
            if path == "package.json":
                return json.dumps({"name": repo, "dependencies": {"example-http-lib": "^2.3.1"}}, indent=2) + "\n"
            return None

    monkeypatch.setenv("AUDIT_DB_APP_DSN", APP)
    monkeypatch.delenv("FIX_GITHUB_TOKEN", raising=False)
    personas = load_personas()
    deps = Deps(settings=Settings.from_env(), db=Database(dsn=APP), verifier=DevVerifier(personas),
                llm_for=lambda t: None, github=Repo())
    deps.fix_client, where = build_fix_client(deps.github, out=tmp_path)
    assert "dry run" in where
    server = dev_server.serve(deps, personas, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def api(method, path, persona, body=None):
        req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body else None,
                                     headers={"content-type": "application/json",
                                              "x-user-authorization": f"Bearer dev:{persona}"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        brief = api("GET", "/api/brief", "uk-lead")[1]
        fid = brief["teams"][0]["top"][0]["id"]
        status, drafted = api("POST", "/api/fixes/request", "uk-lead", {"finding_id": fid})
        assert status == 200 and drafted["status"] == "awaiting_approval", drafted
        assert drafted["manifest"] == "package.json"                      # mapped from package-lock.json
        reviews = api("GET", "/api/reviews", "uk-lead")[1]
        assert reviews["can_decide"] and reviews["fixes"][0]["fix_request_id"] == drafted["fix_request_id"]
        assert api("GET", "/api/reviews", "growth-engineer")[1]["fixes"] == []          # other team's fix
        status, out = api("POST", "/api/fixes/decide", "uk-lead",
                          {"fix_request_id": drafted["fix_request_id"], "decision": "approved"})
        assert status == 200 and out["status"] == "opened" and out["pr_url"].startswith("file://")
        written = list(tmp_path.rglob("package.json"))
        assert len(written) == 1 and '"^2.3.4"' in written[0].read_text()
        assert (written[0].parent / "PULL_REQUEST.md").exists()
    finally:
        server.shutdown()
        deps.db.close()
