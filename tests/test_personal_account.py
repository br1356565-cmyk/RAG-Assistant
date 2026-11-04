"""Demo deployment paths: a GitHub App on a personal account, and Bedrock without the gateway."""
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from audit_agent.collectors import dependabot, ownership
from audit_agent.github import GitHubApp, GitHubToken
from audit_agent.llm import BedrockLLM, LLMResponse, to_converse

from test_collectors import alert


@pytest.fixture(scope="module")
def pem():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def user_account(pem, alerts_by_repo, disabled=(), forbidden=()):
    seen = []

    def handle(req: httpx.Request):
        seen.append(req.url.path)
        if req.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "t"})
        if req.url.path == "/installation/repositories":
            return httpx.Response(200, json={"total_count": 4, "repositories": [
                {"name": "shop-web", "owner": {"login": "balaji"}, "topics": ["team-web"]},
                {"name": "etl-jobs", "owner": {"login": "balaji"}, "topics": ["team-data"]},
                {"name": "infra-terraform", "owner": {"login": "Balaji"}},
                {"name": "scratch", "owner": {"login": "balaji"}},
                {"name": "old", "owner": {"login": "balaji"}, "archived": True},
                {"name": "someone-elses", "owner": {"login": "other"}},
            ]})
        repo = req.url.path.split("/")[3]
        if repo in disabled:
            return httpx.Response(403, json={"message": "Dependabot alerts are disabled for this repository."})
        if repo in forbidden:
            return httpx.Response(403, json={"message": "Resource not accessible by integration"})
        return httpx.Response(200, json=alerts_by_repo.get(repo, []))

    gh = GitHubApp("balaji", "1", "2", pem, owner_type="user",
                   http=httpx.Client(transport=httpx.MockTransport(handle)))
    return gh, seen


def per_repo_alert(repo, ghsa, sev, number=1):
    a = alert(repo, ghsa, sev, number=number)
    del a["repository"]               # the per-repo endpoint doesn't include it
    return a


def test_user_account_ownership_by_topic(pem, monkeypatch):
    monkeypatch.setenv("OWNERSHIP_CONFIG", "ownership.demo.yml")
    monkeypatch.setenv("TEAM_GROUP_IDS", json.dumps({"web": "grp-web"}))
    gh, seen = user_account(pem, {})
    out = ownership.collect(gh)
    o = {x["repo"]: x["team_id"] for x in out.owners}
    assert o == {"shop-web": "web", "etl-jobs": "data", "infra-terraform": "platform", "scratch": None}
    assert {t["id"]: t["entra_group_id"] for t in out.teams}["web"] == "grp-web"
    assert not any("/teams/" in p for p in seen)            # no team endpoints for a personal account


def test_user_account_dependabot_reads_each_repo(pem):
    gh, seen = user_account(pem, {"shop-web": [per_repo_alert("shop-web", "GHSA-aaaa-bbbb-cccc", "high")]},
                            disabled={"scratch"})
    out = dependabot.collect(gh)
    assert [f.resource for f in out.findings] == ["shop-web"]
    assert out.complete is True and "disabled" in out.warnings[0]
    assert "/repos/balaji/old/dependabot/alerts" not in seen


def test_unreadable_repo_makes_output_incomplete(pem):
    gh, _ = user_account(pem, {}, forbidden={"etl-jobs"})
    out = dependabot.collect(gh)
    assert out.complete is False and "etl-jobs" in out.warnings[-1]


def test_bad_settings_are_rejected(monkeypatch, pem):
    with pytest.raises(ValueError):
        GitHubApp("x", "1", "2", pem, owner_type="enterprise")
    monkeypatch.setenv("OWNERSHIP_CONFIG", "../../etc/passwd")
    with pytest.raises(ValueError):
        ownership.load_config()
    monkeypatch.setenv("OWNERSHIP_CONFIG", "ownership.demo.yml")
    monkeypatch.setenv("TEAM_GROUP_IDS", json.dumps({"nope": "g"}))
    with pytest.raises(ValueError):
        ownership.load_config()


def test_personal_token_lists_own_repos():
    paths = []

    def handle(req):
        paths.append((req.url.path, dict(req.url.params)))
        return httpx.Response(200, json=[{"name": "a"}])

    gh = GitHubToken("balaji", "ghp_x", owner_type="user", http=httpx.Client(transport=httpx.MockTransport(handle)))
    assert [r["name"] for r in gh.list_org_repos()] == ["a"]
    assert paths[0][0] == "/user/repos" and paths[0][1]["affiliation"] == "owner"


# ── Bedrock Converse ───────────────────────────────────────────────────────
class FakeBedrock:
    def __init__(self, reply):
        self.reply, self.kwargs = reply, None

    def converse(self, **kwargs):
        self.kwargs = kwargs
        return self.reply


HISTORY = [
    {"role": "system", "content": "You are the audit assistant."},
    {"role": "user", "content": "What should we fix?"},
    {"role": "assistant", "content": None, "tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "search_findings", "arguments": '{"limit": 3}'}},
        {"id": "c2", "type": "function", "function": {"name": "get_trend", "arguments": "{}"}}]},
    {"role": "tool", "tool_call_id": "c1", "content": '{"items": []}'},
    {"role": "tool", "tool_call_id": "c2", "content": ""},
    {"role": "user", "content": "[harness] cite findings"},
]


def test_messages_translate_to_alternating_converse_turns():
    system, turns = to_converse(HISTORY)
    assert system == [{"text": "You are the audit assistant."}]
    assert [t["role"] for t in turns] == ["user", "assistant", "user"]
    assert turns[1]["content"][0]["toolUse"] == {"toolUseId": "c1", "name": "search_findings", "input": {"limit": 3}}
    last = turns[2]["content"]
    assert [list(b)[0] for b in last] == ["toolResult", "toolResult", "text"]
    assert last[1]["toolResult"]["content"] == [{"text": "(empty)"}]       # Converse rejects empty text


def test_bedrock_request_and_response():
    fake = FakeBedrock({"output": {"message": {"role": "assistant", "content": [
        {"text": "Checking."}, {"toolUse": {"toolUseId": "t9", "name": "submit_investigation", "input": {"a": 1}}}]}},
        "usage": {"inputTokens": 900, "outputTokens": 40}, "stopReason": "tool_use"})
    tools = [{"type": "function", "function": {"name": "submit_investigation", "description": "Submit",
                                               "parameters": {"type": "object", "properties": {"a": {"type": "integer"}}}}}]
    resp = BedrockLLM("us-east-1", client=fake).complete(
        model="us.anthropic.example", messages=HISTORY, tools=tools, max_tokens=500, user="u", tags=[],
        tool_choice={"type": "function", "function": {"name": "submit_investigation"}}, temperature=0.0)
    k = fake.kwargs
    assert k["toolConfig"]["toolChoice"] == {"tool": {"name": "submit_investigation"}}
    assert k["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["properties"]["a"]["type"] == "integer"
    assert k["inferenceConfig"] == {"maxTokens": 500, "temperature": 0.0}
    assert isinstance(resp, LLMResponse) and resp.text == "Checking."
    assert resp.tool_calls[0].name == "submit_investigation" and json.loads(resp.tool_calls[0].arguments) == {"a": 1}
    assert (resp.tokens_in, resp.tokens_out) == (900, 40)
    # the response round-trips back through the translator
    assert to_converse([{"role": "user", "content": "q"}, resp.as_message()])[1][1]["content"][1]["toolUse"]["toolUseId"] == "t9"


def test_bedrock_omits_temperature_and_tools_when_unset():
    fake = FakeBedrock({"output": {"message": {"content": [{"text": "hi"}]}}, "usage": {}})
    BedrockLLM("us-east-1", client=fake).complete(model="m", messages=[{"role": "user", "content": "q"}], tools=[],
                                                 tool_choice="auto", max_tokens=10, user="u", tags=[])
    assert "temperature" not in fake.kwargs["inferenceConfig"] and "toolConfig" not in fake.kwargs


def test_harness_runs_end_to_end_on_bedrock_translation(db):
    """The real harness and tools, with Bedrock-shaped replies, against the test database."""
    from audit_agent.harness import Harness, HarnessConfig
    from audit_agent.db import Scope
    from audit_agent.tools import ToolContext, tools_for
    from conftest import G_CRIT

    replies = iter([
        {"output": {"message": {"content": [{"toolUse": {"toolUseId": "a", "name": "search_findings",
                                                         "input": {"severity": ["critical"]}}}]}},
         "usage": {"inputTokens": 10, "outputTokens": 5}},
        {"output": {"message": {"content": [{"text": f"Fix [F-{G_CRIT}] first."}]}},
         "usage": {"inputTokens": 10, "outputTokens": 5}},
    ])
    sent = []

    class Client:
        def converse(self, **kw):
            sent.append(kw)
            return next(replies)

    scope = Scope(user_id="u", team_ids=("growth_engineering",), role="team_member")
    ctx = ToolContext(scope=scope, db=db, github=None, mode="chat")
    result = Harness(BedrockLLM("us-east-1", client=Client()), tools_for("chat"),
                     HarnessConfig(mode="chat", model="m")).run(ctx, [
        {"role": "system", "content": "sys"}, {"role": "user", "content": "What first?"}])
    assert result.status == "answered" and result.cited == [f"F-{G_CRIT}"]
    assert sent[1]["messages"][-1]["content"][0]["toolResult"]["toolUseId"] == "a"


def test_migration_waits_for_the_nat(monkeypatch):
    from audit_agent.handlers import migrate

    monkeypatch.setenv("DB_MASTER_SECRET_ARN", "arn:secret")
    attempts = []

    class Flaky:
        def get_secret_value(self, SecretId):
            attempts.append(SecretId)
            if len(attempts) < 3:
                raise ConnectionError("connect timeout")
            return {"SecretString": '{"username": "m", "password": "p"}'}

    import time
    assert migrate._master_secret("us-east-1", time.monotonic() + 60, client=Flaky(), sleep=lambda s: None) == \
        {"username": "m", "password": "p"}
    assert len(attempts) == 3
    with pytest.raises(ConnectionError):
        attempts.clear()
        migrate._master_secret("us-east-1", time.monotonic() - 1, client=Flaky(), sleep=lambda s: None)


def test_reasoning_blocks_are_sent_back_unchanged():
    """Claude 5.x thinks by default; the next call must carry that turn's reasoning blocks."""
    reasoning = {"reasoningContent": {"reasoningText": {"text": "check criticals", "signature": "sig=="}}}
    redacted = {"reasoningContent": {"redactedContent": b"\x00\x01"}}
    replies = iter([
        {"output": {"message": {"content": [reasoning, redacted,
                                            {"toolUse": {"toolUseId": "t1", "name": "get_trend", "input": {}}}]}},
         "usage": {}},
        {"output": {"message": {"content": [{"text": "Done."}]}}, "usage": {}},
    ])
    sent = []

    class Client:
        def converse(self, **kw):
            sent.append(kw)
            return next(replies)

    llm = BedrockLLM("ap-southeast-2", client=Client())
    msgs = [{"role": "user", "content": "trend?"}]
    first = llm.complete(model="m", messages=msgs, tools=[], tool_choice="auto", max_tokens=10, user="u", tags=[])
    msgs += [first.as_message(), {"role": "tool", "tool_call_id": "t1", "content": "{}"}]
    llm.complete(model="m", messages=msgs, tools=[], tool_choice="auto", max_tokens=10, user="u", tags=[])
    assistant = sent[1]["messages"][1]
    assert assistant["role"] == "assistant" and assistant["content"][:2] == [reasoning, redacted]
    assert assistant["content"][2]["toolUse"]["toolUseId"] == "t1"


def test_gateway_never_receives_the_bedrock_only_key():
    from audit_agent.llm import RAW_KEY, GatewayLLM
    bodies = []

    def handle(req):
        bodies.append(json.loads(req.content))
        return httpx.Response(200, json={"id": "x", "object": "chat.completion", "created": 0, "model": "m",
                                         "choices": [{"index": 0, "finish_reason": "stop",
                                                      "message": {"role": "assistant", "content": "ok"}}]})

    GatewayLLM("http://gw/v1", "k", http_client=httpx.Client(transport=httpx.MockTransport(handle))).complete(
        model="m", messages=[{"role": "assistant", "content": "a", RAW_KEY: [{"text": "a"}]},
                             {"role": "user", "content": "q"}],
        tools=[], tool_choice="auto", max_tokens=5, user="u", tags=[])
    assert RAW_KEY not in bodies[0]["messages"][0]


def test_forced_tool_rejected_falls_back_to_auto():
    class ValidationException(Exception):
        pass

    calls = []

    class Client:
        def converse(self, **kw):
            calls.append(json.loads(json.dumps(kw["toolConfig"]["toolChoice"])))
            if "tool" in kw["toolConfig"]["toolChoice"]:
                raise ValidationException("Forced tool use is not supported for this model")
            return {"output": {"message": {"content": [
                {"toolUse": {"toolUseId": "s", "name": "submit_investigation", "input": {}}}]}}, "usage": {}}

    tools = [{"type": "function", "function": {"name": "submit_investigation", "parameters": {"type": "object"}}}]
    resp = BedrockLLM("us-east-1", client=Client()).complete(
        model="m", messages=[{"role": "user", "content": "q"}], tools=tools, max_tokens=5, user="u", tags=[],
        tool_choice={"type": "function", "function": {"name": "submit_investigation"}})
    assert calls == [{"tool": {"name": "submit_investigation"}}, {"auto": {}}]
    assert resp.tool_calls[0].name == "submit_investigation"


def test_nova_inline_thinking_is_hidden_from_users():
    fake = FakeBedrock({"output": {"message": {"content": [
        {"text": "<thinking>The user wants criticals; I should search.</thinking>\nFix the lodash upgrade first."}]}},
        "usage": {}})
    resp = BedrockLLM("ap-southeast-2", client=fake).complete(
        model="apac.amazon.nova-pro-v1:0", messages=[{"role": "user", "content": "q"}], tools=[],
        tool_choice="auto", max_tokens=10, user="u", tags=[])
    assert resp.text == "Fix the lodash upgrade first."
    assert "<thinking>" in resp.raw_content[0]["text"]       # sent back to the model unchanged
    only = FakeBedrock({"output": {"message": {"content": [{"text": "<thinking>just planning"}]}}, "usage": {}})
    assert BedrockLLM("x", client=only).complete(model="m", messages=[{"role": "user", "content": "q"}], tools=[],
                                                 tool_choice="auto", max_tokens=5, user="u", tags=[]).text is None
