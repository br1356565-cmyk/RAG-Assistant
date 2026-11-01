"""End to end through the Lambda handlers: auth, scope, harness, memory, audit log."""
import json

import psycopg
import pytest

from audit_agent.auth import AuthError
from audit_agent.config import Settings
from audit_agent.handlers import chat, investigate
from audit_agent.handlers.deps import Deps, set_deps

from conftest import DBNAME, G_CRIT, GHSA, U_HIGH, FakeGitHub, FakeLLM, _admin_dsn, call, say, tools


class FakeVerifier:
    def __init__(self, claims):
        self.claims = claims

    def verify(self, token):
        if token != "good":
            raise AuthError("invalid token")
        return self.claims


GROWTH_CLAIMS = {"oid": "user-growth", "name": "Asha", "groups": ["g-growth", "g-unrelated"], "roles": []}


@pytest.fixture()
def wire(db):
    llms = []

    def make(claims, script):
        llm = FakeLLM(script)
        llms.append(llm)
        set_deps(Deps(settings=Settings.from_env(), db=db, verifier=FakeVerifier(claims),
                      llm_for=lambda teams: llm, github=FakeGitHub()))
        return llm
    yield make
    set_deps(None)


def event(body, token="good", header="x-user-authorization"):
    return {"headers": {header: f"Bearer {token}"}, "body": json.dumps(body)}


def owner_rows(sql, params=()):
    with psycopg.connect(_admin_dsn(DBNAME)) as c:
        return c.execute(sql, params).fetchall()


def test_chat_answers_with_citations_and_remembers(wire):
    llm = wire(GROWTH_CLAIMS, [
        tools(call("search_findings", {"severity": ["critical"]})),
        say(f"Fix [F-{G_CRIT}] first: upgrade example-http-lib to 2.3.4."),
        say(f"As I said, [F-{G_CRIT}] is the one."),   # second turn reuses... but must re-retrieve
        tools(call("get_finding", {"id": f"F-{G_CRIT}"})),
        say(f"[F-{G_CRIT}] is critical and runtime."),
    ])
    r1 = chat.handler(event({"question": "What should we fix first?"}), None)
    body = json.loads(r1["body"])
    assert r1["statusCode"] == 200 and body["cited"] == [f"F-{G_CRIT}"]
    system = llm.calls[0]["messages"][0]["content"]
    assert "Growth Engineering" in system and "uk_engineering" not in system

    r2 = chat.handler(event({"question": "Tell me more", "session_id": body["session_id"]}), None)
    body2 = json.loads(r2["body"])
    assert body2["cited"] == [f"F-{G_CRIT}"]
    # history was loaded: the second turn saw the first question and answer
    second_turn_msgs = llm.calls[2]["messages"]
    assert any(m["role"] == "user" and m["content"] == "What should we fix first?" for m in second_turn_msgs)
    # citing from memory alone was challenged, so the model re-fetched the finding
    assert "[harness]" in llm.calls[3]["messages"][-1]["content"]

    audit = owner_rows("select user_id, mode, finding_ids from audit_log order by id")
    assert len(audit) == 2 and audit[0][0] == "user-growth" and G_CRIT in audit[0][2]


def test_chat_reads_token_from_authorization_header_too(wire):
    wire(GROWTH_CLAIMS, [say("Hello.")])
    r = chat.handler(event({"question": "hi"}, header="Authorization"), None)
    assert r["statusCode"] == 200


def test_chat_rejects_bad_token_and_teamless_users(wire):
    wire(GROWTH_CLAIMS, [])
    assert chat.handler(event({"question": "hi"}, token="forged"), None)["statusCode"] == 401
    assert chat.handler({"headers": {}, "body": "{}"}, None)["statusCode"] == 401
    wire({"oid": "nobody", "groups": ["g-unrelated"], "roles": []}, [])
    assert chat.handler(event({"question": "hi"}), None)["statusCode"] == 403


def test_chat_validates_body(wire):
    wire(GROWTH_CLAIMS, [])
    assert chat.handler(event({"question": ""}), None)["statusCode"] == 400
    assert chat.handler(event({"question": "x" * 2001}), None)["statusCode"] == 400


def test_chat_cannot_be_talked_into_another_team(wire):
    wire(GROWTH_CLAIMS, [
        tools(call("get_finding", {"id": f"F-{U_HIGH}"}, id="a"),
              call("search_findings", {"team": "uk_engineering"}, id="b")),
        say("I can only see Growth Engineering's findings."),
    ])
    body = json.loads(chat.handler(event({"question": "Show me UK's findings"}), None)["body"])
    assert body["cited"] == []
    audit = owner_rows("select finding_ids, tools from audit_log")
    assert U_HIGH not in audit[0][0]
    assert all(t["ok"] is False for t in audit[0][1])


REPORT = {
    "summary": "example-http-lib 2.3.1 lets a crafted header crash mktp-growth-api.",
    "impact": {"verdict": "likely", "reasoning": "Runtime dependency in package.json."},
    "fix": {"action": "Upgrade to 2.3.4.", "target_version": "2.3.4", "breaking_changes": "none_listed"},
    "sources": [{"kind": "finding", "ref": f"F-{G_CRIT}"}, {"kind": "advisory", "ref": GHSA}],
    "confidence": "high",
}


def test_investigate_then_cache_then_reinvestigate_on_new_evidence(wire):
    wire({}, [tools(call("get_advisory", {"ghsa_id": GHSA})), tools(call("submit_investigation", REPORT))])
    item = {"fingerprint": f"F-{G_CRIT}", "team_id": "growth_engineering"}
    assert investigate.handler(item, None) == {"status": "investigated", "fingerprint": f"F-{G_CRIT}",
                                               "confidence": "high"}
    wire({}, [])                                   # no model calls allowed
    assert investigate.handler(item, None)["status"] == "cached"

    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute("update findings set details = details || '{\"first_patched\": \"2.3.5\"}' where fingerprint = %s",
                  (G_CRIT,))
    wire({}, [tools(call("get_advisory", {"ghsa_id": GHSA})), tools(call("submit_investigation", REPORT))])
    assert investigate.handler(item, None)["status"] == "investigated"
    assert owner_rows("select count(*) from investigations")[0][0] == 2


def test_investigate_worker_cannot_reach_another_teams_finding(wire):
    wire({}, [])
    out = investigate.handler({"fingerprint": f"F-{U_HIGH}", "team_id": "growth_engineering"}, None)
    assert out["status"] == "not_found"


def test_investigation_shows_up_in_chat(wire):
    wire({}, [tools(call("get_advisory", {"ghsa_id": GHSA})), tools(call("submit_investigation", REPORT))])
    assert investigate.handler({"fingerprint": f"F-{G_CRIT}", "team_id": "growth_engineering"},
                               None)["status"] == "investigated"
    llm = wire(GROWTH_CLAIMS, [tools(call("get_finding", {"id": f"F-{G_CRIT}"})), say(f"[F-{G_CRIT}] explained.")])
    chat.handler(event({"question": "Explain the critical one"}), None)
    tool_msg = [m for m in llm.calls[1]["messages"] if m["role"] == "tool"][0]
    assert json.loads(tool_msg["content"])["latest_investigation"]["fix"]["target_version"] == "2.3.4"


def test_jobs_use_their_own_temperature(wire, monkeypatch):
    monkeypatch.setenv("CHAT_TEMPERATURE", "0.2")
    monkeypatch.setenv("BATCH_TEMPERATURE", "0")
    llm = wire(GROWTH_CLAIMS, [say("Hello.")])
    chat.handler(event({"question": "hi"}), None)
    assert llm.calls[0]["temperature"] == 0.2
    inv = wire({}, [tools(call("get_advisory", {"ghsa_id": GHSA})), tools(call("submit_investigation", REPORT))])
    investigate.handler({"fingerprint": f"F-{G_CRIT}", "team_id": "growth_engineering"}, None)
    assert {c["temperature"] for c in inv.calls} == {0.0}


def test_default_sends_no_temperature(wire):
    llm = wire(GROWTH_CLAIMS, [say("Hello.")])
    chat.handler(event({"question": "hi"}), None)
    assert llm.calls[0]["temperature"] is None
