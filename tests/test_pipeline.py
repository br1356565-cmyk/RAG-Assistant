"""The whole weekly flow in order: collect -> ingest -> investigate -> a user asks in chat."""
import json

import psycopg
from psycopg.rows import dict_row

from audit_agent import ingest as ingest_mod
from audit_agent.collectors import dependabot, ownership
from audit_agent.config import Settings
from audit_agent.handlers import chat, investigate
from audit_agent.handlers.deps import Deps, set_deps

from conftest import DBNAME, HOST, PORT, FakeGitHub, FakeLLM, _admin_dsn, call, say, tools
from test_collectors import OrgGitHub, alert
from test_handlers import FakeVerifier, event
from test_ingest import Store, conn  # noqa: F401  (fixture)

GHSA = "GHSA-2c3f-4g5h-6j7m"


def test_weekly_flow_end_to_end(conn, db):
    # 1-2. collect and ingest (db fixture seeded test data; conn fixture then truncated it)
    gh = OrgGitHub(alerts=[alert("mktp-growth-api", GHSA, "critical")])
    store = Store()
    results = [store.put("r1", ownership.collect(gh)), store.put("r1", dependabot.collect(gh))]
    summary = ingest_mod.ingest(conn, "r1", results, store.load)
    assert len(summary["investigate"]) == 1
    item = summary["investigate"][0]
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute("update teams set entra_group_id = 'g-uk' where id = 'uk_engineering'")

    # 3. investigate the queued item (as the Step Functions Map would)
    report = {
        "summary": "example-http-lib below 2.3.4 lets a crafted header crash mktp-growth-api.",
        "impact": {"verdict": "likely", "reasoning": "Runtime dependency in package-lock.json."},
        "fix": {"action": "Upgrade example-http-lib to 2.3.4.", "target_version": "2.3.4", "breaking_changes": "unknown"},
        "sources": [{"kind": "finding", "ref": item["fingerprint"]}, {"kind": "advisory", "ref": GHSA}],
        "confidence": "medium",
    }
    inv_llm = FakeLLM([tools(call("get_advisory", {"ghsa_id": GHSA})), tools(call("submit_investigation", report))])
    set_deps(Deps(settings=Settings.from_env(), db=db, verifier=None, llm_for=lambda t: inv_llm, github=FakeGitHub()))
    try:
        assert investigate.handler(item, None)["status"] == "investigated"
        # the finding given to the model carried the collector's fix detail
        task = inv_llm.calls[0]["messages"][1]["content"]
        assert '"first_patched":"2.3.4"' in task and '"scope":"runtime"' in task

        # 4. a UK engineer asks; the answer is grounded in the stored investigation
        fid = item["fingerprint"]
        chat_llm = FakeLLM([tools(call("search_findings", {"severity": ["critical"]})),
                            tools(call("get_finding", {"id": fid})),
                            say(f"Upgrade example-http-lib to 2.3.4 [{fid}].")])
        set_deps(Deps(settings=Settings.from_env(), db=db,
                      verifier=FakeVerifier({"oid": "eng-1", "name": "Ravi", "groups": ["g-uk"], "roles": []}),
                      llm_for=lambda t: chat_llm, github=FakeGitHub()))
        body = json.loads(chat.handler(event({"question": "What do we fix first?"}), None)["body"])
        assert body["cited"] == [fid] and body["as_of"] is not None
        finding_msg = [m for m in chat_llm.calls[2]["messages"] if m["role"] == "tool"][-1]
        assert json.loads(finding_msg["content"])["latest_investigation"]["fix"]["target_version"] == "2.3.4"
    finally:
        set_deps(None)
