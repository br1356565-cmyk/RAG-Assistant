"""Harness behaviour with a scripted model: tool execution, error recovery, limits,
citation checking and structured submission."""
import json

from audit_agent.harness import Harness, HarnessConfig
from audit_agent.tools import ToolContext, tools_for

from conftest import G_CRIT, GHSA, GROWTH, U_HIGH, FakeGitHub, FakeLLM, call, say, tools


def run(db, script, mode="chat", **cfg):
    llm = FakeLLM(script)
    ctx = ToolContext(scope=GROWTH, db=db, github=FakeGitHub(), mode=mode)
    h = Harness(llm, tools_for(mode), HarnessConfig(mode=mode, model="m", **cfg))
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "q"}]
    return h.run(ctx, msgs), llm, msgs


def tool_results(msgs):
    return [json.loads(m["content"].split("…[truncated")[0]) if not m["content"].endswith("query]")
            else m["content"] for m in msgs if m["role"] == "tool"]


def test_tool_then_grounded_answer(db):
    res, llm, msgs = run(db, [
        tools(call("search_findings", {"severity": ["critical"]})),
        say(f"One critical: [F-{G_CRIT}] in mktp-growth-api."),
    ])
    assert res.status == "answered"
    assert res.cited == [f"F-{G_CRIT}"]
    assert G_CRIT in res.finding_ids
    assert [s.name for s in res.steps if s.kind == "tool"] == ["search_findings"]
    assert llm.calls[0]["user"] == "user-growth" and "team:growth_engineering" in llm.calls[0]["tags"]


def test_citation_of_unretrieved_finding_gets_one_correction(db):
    res, llm, msgs = run(db, [
        tools(call("search_findings", {})),
        say(f"See [F-{G_CRIT}] and [F-{U_HIGH}]."),          # U_HIGH was never retrieved
        say(f"See [F-{G_CRIT}]."),
    ])
    assert res.status == "answered" and res.cited == [f"F-{G_CRIT}"]
    nudge = llm.calls[2]["messages"][-1]["content"]
    assert nudge.startswith("[harness]") and U_HIGH in nudge


def test_persistent_bad_citation_is_stripped(db):
    res, _, _ = run(db, [say(f"Trust me: [F-{U_HIGH}]"), say(f"Still [F-{U_HIGH}]")])
    assert res.status == "answered" and U_HIGH not in res.text and res.cited == []


def test_unknown_tool_and_bad_args_become_errors_not_crashes(db):
    res, _, msgs = run(db, [
        tools(call("drop_tables", {}, id="c1"), call("search_findings", {"limit": 999}, id="c2")),
        say("I could not search."),
    ])
    errs = [json.loads(m["content"])["error"] for m in msgs if m["role"] == "tool"]
    assert "Unknown tool" in errs[0] and "Invalid arguments" in errs[1]
    assert res.status == "answered"
    assert [s.ok for s in res.steps if s.kind == "tool"] == [False, False]


def test_foreign_finding_lookup_is_refused_by_scope(db):
    res, _, msgs = run(db, [tools(call("get_finding", {"id": f"F-{U_HIGH}"})), say("Not visible to you.")])
    assert "No finding" in json.loads(msgs[-2]["content"])["error"]
    assert U_HIGH not in res.finding_ids


def test_repeated_identical_calls_are_cut_off(db):
    same = lambda: tools(call("get_trend", {"weeks": 4}))
    res, _, msgs = run(db, [same(), same(), same(), say("done")])
    last_tool = [m for m in msgs if m["role"] == "tool"][-1]
    assert "already made this exact call" in last_tool["content"]


def test_round_limit_forces_a_final_answer(db):
    loop = [tools(call("get_trend", {"weeks": w})) for w in (1, 2, 3)]
    res, llm, _ = run(db, loop + [say("Partial answer: trend looks flat.")], max_rounds=3)
    assert res.status == "limit" and res.text.startswith("Partial answer")
    assert "Stop calling tools" in llm.calls[-1]["messages"][-1]["content"]


def test_tool_results_are_capped(db):
    res, _, msgs = run(db, [tools(call("search_findings", {"limit": 25})), say("ok")], tool_result_max_chars=80)
    content = [m for m in msgs if m["role"] == "tool"][0]["content"]
    assert len(content) < 200 and "truncated" in content


def test_untrusted_content_is_wrapped(db):
    res, _, msgs = run(db, [tools(call("get_advisory", {"ghsa_id": GHSA})), say("ok")])
    payload = json.loads([m for m in msgs if m["role"] == "tool"][0]["content"])
    assert payload["notice"].startswith("Third-party content")
    assert "IGNORE PREVIOUS INSTRUCTIONS" in payload["data"]["description"]   # kept as data, labelled


def test_model_failure_returns_friendly_error(db):
    def boom(_):
        raise RuntimeError("gateway down")
    res, _, _ = run(db, [boom])
    assert res.status == "error" and "unavailable" in res.text


# ── investigate mode ──────────────────────────────────────────────────────
GOOD_REPORT = {
    "summary": "example-http-lib 2.3.1 lets a crafted header crash mktp-growth-api.",
    "impact": {"verdict": "likely", "reasoning": "Runtime dependency in package.json, imported in src/server.js."},
    "fix": {"action": "Upgrade example-http-lib to 2.3.4 in package.json.", "target_version": "2.3.4",
            "breaking_changes": "none_listed"},
    "sources": [{"kind": "advisory", "ref": GHSA}, {"kind": "file", "ref": "mktp-growth-api/package.json"}],
    "confidence": "high",
}


def test_investigation_submits_grounded_report(db):
    res, llm, _ = run(db, [
        tools(call("get_advisory", {"ghsa_id": GHSA}, id="a"),
              call("read_repo_file", {"repo": "mktp-growth-api", "path": "package.json"}, id="b")),
        tools(call("submit_investigation", GOOD_REPORT)),
    ], mode="investigate")
    assert res.status == "submitted" and res.data["fix"]["target_version"] == "2.3.4"
    assert "propose_team_note" not in llm.calls[0]["tools"]


def test_investigation_rejects_ungrounded_then_accepts(db):
    res, _, msgs = run(db, [
        tools(call("submit_investigation", GOOD_REPORT, id="s1")),            # nothing retrieved yet
        tools(call("get_advisory", {"ghsa_id": GHSA}, id="a"),
              call("read_repo_file", {"repo": "mktp-growth-api", "path": "package.json"}, id="b")),
        tools(call("submit_investigation", GOOD_REPORT, id="s2")),
    ], mode="investigate")
    first = json.loads([m for m in msgs if m["role"] == "tool"][0]["content"])
    assert "not retrieved" in first["error"]
    assert res.status == "submitted"


def test_investigation_text_reply_gets_nudged_then_forced(db):
    res, llm, _ = run(db, [
        say("It's probably fine."),
        say("Really, it's fine."),
        tools(call("submit_investigation", {**GOOD_REPORT, "sources": [{"kind": "finding", "ref": f"F-{G_CRIT}"}],
                                            "confidence": "low"})),
    ], mode="investigate")
    # second text reply ends the loop; finalize forces the submit tool
    assert llm.calls[-1]["tool_choice"] == {"type": "function", "function": {"name": "submit_investigation"}}
    # the forced submission cites a finding this run never retrieved, so grounding still rejects it
    assert res.status == "limit" and res.data is None


def test_forced_submission_succeeds_when_grounded(db):
    res, _, _ = run(db, [
        tools(call("get_advisory", {"ghsa_id": GHSA})),
        say("It's probably fine."),
        say("Really."),
        tools(call("submit_investigation", {**GOOD_REPORT, "sources": [{"kind": "advisory", "ref": GHSA}],
                                            "confidence": "low"})),
    ], mode="investigate")
    assert res.status == "submitted" and res.data["confidence"] == "low"
