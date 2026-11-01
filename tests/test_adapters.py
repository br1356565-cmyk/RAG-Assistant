"""The edges that talk to real services, driven against mocked HTTP and locally signed tokens."""
import base64
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from audit_agent.auth import AuthError, EntraVerifier, bearer_token, resolve_scope
from audit_agent.github import GitHubApp
from audit_agent.llm import GatewayKeys, GatewayLLM

TENANT, AUD = "tenant-1", "api://audit-agent"


# ── LiteLLM gateway (OpenAI-compatible) ────────────────────────────────────
def test_gateway_request_and_tool_call_parsing():
    seen = {}

    def handle(req: httpx.Request):
        seen["body"] = json.loads(req.content)
        seen["auth"] = req.headers["authorization"]
        return httpx.Response(200, json={
            "id": "x", "object": "chat.completion", "created": 0, "model": "audit-chat",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "call_1", "type": "function",
                                "function": {"name": "search_findings", "arguments": "{\"limit\":3}"}}]}}],
            "usage": {"prompt_tokens": 321, "completion_tokens": 12, "total_tokens": 333},
        })

    llm = GatewayLLM("http://gateway.internal/v1", "sk-team", http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    resp = llm.complete(model="audit-chat", messages=[{"role": "user", "content": "q"}],
                        tools=[{"type": "function", "function": {"name": "search_findings", "parameters": {}}}],
                        tool_choice="auto", max_tokens=100, user="user-1", tags=["team:growth_engineering"])
    assert resp.tool_calls[0].name == "search_findings" and json.loads(resp.tool_calls[0].arguments) == {"limit": 3}
    assert (resp.tokens_in, resp.tokens_out) == (321, 12)
    assert seen["auth"] == "Bearer sk-team"
    assert seen["body"]["metadata"] == {"tags": ["team:growth_engineering"]} and seen["body"]["user"] == "user-1"
    assert resp.as_message()["tool_calls"][0]["function"]["name"] == "search_findings"


def test_gateway_keys_pick_team_key_with_default_fallback():
    k = GatewayKeys({"default": "sk-d", "uk_engineering": "sk-uk"})
    assert k.for_teams(("uk_engineering",)) == "sk-uk"
    assert k.for_teams(("growth_engineering",)) == "sk-d"
    with pytest.raises(ValueError):
        GatewayKeys({"uk": "x"})


# ── Entra ID tokens ────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return pem, key.public_key()


class StaticJWKS:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": self.public_key})()


def token(pem, **over):
    now = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": AUD, "oid": "user-1",
              "iat": now, "exp": now + 600, "groups": ["g-growth"], "roles": []}
    claims.update(over)
    return jwt.encode(claims, pem, algorithm="RS256")


def test_entra_verifier_accepts_valid_and_rejects_tampering(keypair):
    pem, pub = keypair
    v = EntraVerifier(TENANT, AUD, jwks_client=StaticJWKS(pub))
    assert v.verify(token(pem))["oid"] == "user-1"
    for bad in (token(pem, aud="api://other"), token(pem, exp=int(time.time()) - 10),
                token(pem, iss="https://evil.example/v2.0")):
        with pytest.raises(AuthError):
            v.verify(bad)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    with pytest.raises(AuthError):
        v.verify(token(other))


def test_bearer_header_precedence():
    assert bearer_token({"x-user-authorization": "Bearer a", "Authorization": "AWS4-HMAC-SHA256 sig"}) == "a"
    with pytest.raises(AuthError):
        bearer_token({"Authorization": "AWS4-HMAC-SHA256 sig"})


def test_scope_roles_and_group_overage(db):
    s = resolve_scope({"oid": "u", "groups": ["g-growth", "g-uk"], "roles": ["team.lead"]}, db)
    assert s.team_ids == ("growth_engineering", "uk_engineering") and s.role == "team_lead"
    assert resolve_scope({"oid": "a", "groups": [], "roles": ["security.admin"]}, db).role == "security_admin"
    with pytest.raises(AuthError) as e:
        resolve_scope({"oid": "u", "_claim_names": {"groups": "src1"}}, db)
    assert e.value.status == 403


# ── GitHub App ─────────────────────────────────────────────────────────────
def test_github_app_token_exchange_and_file_read(keypair):
    pem, _ = keypair
    calls = []

    def handle(req: httpx.Request):
        calls.append((req.method, req.url.path, req.headers.get("authorization", "")[:12]))
        if req.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_install"})
        if req.url.path == "/repos/forbesadvisor/mktp-growth-api/contents/package.json":
            return httpx.Response(200, json={"type": "file", "encoding": "base64",
                                             "content": base64.b64encode(b'{"a":1}').decode()})
        return httpx.Response(404)

    gh = GitHubApp("forbesadvisor", "123", "456", pem, http=httpx.Client(transport=httpx.MockTransport(handle)))
    assert gh.read_file("mktp-growth-api", "package.json") == '{"a":1}'
    assert gh.read_file("mktp-growth-api", "missing.txt") is None
    assert [c[1] for c in calls].count("/app/installations/456/access_tokens") == 1   # token cached
    assert calls[1][2] == "Bearer ghs_i"


def test_temperature_is_sent_only_when_set():
    bodies = []

    def handle(req):
        bodies.append(json.loads(req.content))
        return httpx.Response(200, json={"id": "x", "object": "chat.completion", "created": 0, "model": "m",
                                         "choices": [{"index": 0, "finish_reason": "stop",
                                                      "message": {"role": "assistant", "content": "ok"}}]})

    llm = GatewayLLM("http://gw/v1", "k", http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    for t in (0.0, None):
        llm.complete(model="m", messages=[{"role": "user", "content": "q"}], tools=[], tool_choice="auto",
                     max_tokens=10, user="u", tags=[], temperature=t)
    assert bodies[0]["temperature"] == 0.0 and "temperature" not in bodies[1]


def test_temperature_settings_parse(monkeypatch):
    from audit_agent.config import Settings
    monkeypatch.setenv("CHAT_TEMPERATURE", "none")
    monkeypatch.setenv("BATCH_TEMPERATURE", "0")
    s = Settings.from_env()
    assert s.chat_temperature is None and s.batch_temperature == 0.0
    monkeypatch.setenv("CHAT_TEMPERATURE", "3")
    with pytest.raises(ValueError):
        Settings.from_env()
