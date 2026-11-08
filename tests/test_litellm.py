"""LiteLLM plumbing that runs in AWS without a person: the virtual-key bootstrap (LiteLLM's
API -> Secrets Manager), LiteLLM's own database created by the migrate step, and the agents
picking their keys from the secret."""
import io
import json
import urllib.error

import psycopg
import pytest

from audit_agent.handlers import llm_keys
from audit_agent.handlers.llm_keys import LiteLLM, sync

from conftest import DBNAME, _admin_dsn

SPEC = {"prefix": "audit-demo", "keys": {
    "default": {"models": ["audit-chat"], "max_budget": 10, "budget_duration": "30d", "rpm_limit": 60},
    "web": {"models": ["audit-chat"], "max_budget": 10, "budget_duration": "30d", "rpm_limit": 60}}}


class FakeProxy:
    """Stands in for LiteLLM's HTTP API (urlopen-compatible)."""

    def __init__(self, ready_after=0):
        self.keys, self.calls, self.n, self.ready_after = {}, [], 0, ready_after

    def __call__(self, req, timeout=None):
        assert req.headers["Authorization"] == "Bearer sk-master"
        path, body = req.full_url.split(":4000", 1)[1], json.loads(req.data) if req.data else None
        self.calls.append((req.get_method(), path.split("?")[0], body))
        if path == "/health/readiness":
            self.ready_after -= 1
            return self._resp(200 if self.ready_after < 0 else 503, {})
        if path.startswith("/key/info"):
            key = path.split("key=")[1]
            return self._resp(200 if key in self.keys else 404, {"info": {}})
        if path == "/key/generate":
            self.n += 1
            key = f"sk-generated-{self.n}"
            self.keys[key] = body
            return self._resp(200, {"key": key})
        if path == "/key/update":
            self.keys[body["key"]].update(body)
            return self._resp(200, {})
        if path == "/key/delete":
            for k in body["keys"]:
                self.keys.pop(k, None)
            return self._resp(200, {})
        return self._resp(404, {})

    @staticmethod
    def _resp(status, body):
        if status >= 400:
            raise urllib.error.HTTPError("u", status, "x", {}, io.BytesIO(json.dumps(body).encode()))

        class R(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        r = R(json.dumps(body).encode())
        r.status = status
        return r


class FakeSecrets:
    class exceptions:
        class ResourceNotFoundException(Exception):
            pass

    def __init__(self):
        self.value, self.puts = None, 0

    def get_secret_value(self, SecretId):
        if SecretId == "litellm":
            return {"SecretString": json.dumps({"master_key": "sk-master"})}
        if self.value is None:
            raise self.exceptions.ResourceNotFoundException()
        return {"SecretString": self.value}

    def put_secret_value(self, SecretId, SecretString):
        assert SecretId == "gateway-keys"
        self.value, self.puts = SecretString, self.puts + 1


def proxy_client(proxy):
    return LiteLLM("http://litellm.audit-demo.internal:4000", "sk-master", opener=proxy)


def test_keys_are_created_once_and_stored_in_the_secret():
    proxy, sm = FakeProxy(), FakeSecrets()
    first = sync(proxy_client(proxy), sm, "gateway-keys", SPEC)
    assert first == {"created": ["default", "web"], "kept": [], "deleted": []} and sm.puts == 1
    stored = json.loads(sm.value)
    assert set(stored) == {"default", "web"} and all(v.startswith("sk-generated-") for v in stored.values())
    gen = [b for m, p, b in proxy.calls if p == "/key/generate"]
    assert {b["key_alias"] for b in gen} == {"audit-demo-default", "audit-demo-web"}
    assert gen[0]["max_budget"] == 10 and gen[0]["models"] == ["audit-chat"] and gen[0]["metadata"]["managed_by"] == "terraform"

    second = sync(proxy_client(proxy), sm, "gateway-keys", SPEC)                 # idempotent
    assert second == {"created": [], "kept": ["default", "web"], "deleted": []} and sm.puts == 1
    assert json.loads(sm.value) == stored


def test_a_key_lost_by_litellm_is_recreated_and_dropped_keys_are_deleted():
    proxy, sm = FakeProxy(), FakeSecrets()
    sync(proxy_client(proxy), sm, "gateway-keys", SPEC)
    stored = json.loads(sm.value)
    proxy.keys.pop(stored["web"])                                                  # e.g. LiteLLM's DB was reset
    spec = {**SPEC, "keys": {"default": SPEC["keys"]["default"], "web": {**SPEC["keys"]["web"], "max_budget": 20}}}
    out = sync(proxy_client(proxy), sm, "gateway-keys", spec)
    assert out["created"] == ["web"] and json.loads(sm.value)["web"] != stored["web"]
    assert proxy.keys[json.loads(sm.value)["web"]]["max_budget"] == 20
    out = sync(proxy_client(proxy), sm, "gateway-keys", {**SPEC, "keys": {"default": SPEC["keys"]["default"]}})
    assert out["deleted"] == ["web"] and set(json.loads(sm.value)) == {"default"}
    assert json.loads(sm.value)["default"] in proxy.keys and len(proxy.keys) == 1


def test_handler_waits_for_litellm_and_never_returns_keys(monkeypatch):
    proxy, sm = FakeProxy(ready_after=2), FakeSecrets()
    monkeypatch.setenv("LITELLM_SECRET_ARN", "litellm")
    monkeypatch.setenv("LITELLM_URL", "http://litellm.audit-demo.internal:4000")
    monkeypatch.setenv("GATEWAY_KEYS_SECRET", "gateway-keys")
    monkeypatch.setenv("KEY_SPEC", json.dumps(SPEC))
    monkeypatch.setattr(llm_keys.time, "sleep", lambda s: None)
    monkeypatch.setattr(llm_keys.urllib.request, "urlopen", proxy)
    out = llm_keys.handler({}, None, sm=sm)
    assert out["status"] == "ok" and out["created"] == ["default", "web"]
    assert "sk-" not in json.dumps(out)                                            # Terraform state stays key-free
    assert [p for m, p, b in proxy.calls].count("/health/readiness") == 3


def test_handler_gives_up_if_litellm_never_starts(monkeypatch):
    proxy = FakeProxy(ready_after=10**6)
    ticks = iter(range(0, 10**6, 30))
    monkeypatch.setattr(llm_keys.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="did not become ready"):
        proxy_client(proxy).wait_ready(deadline=120, sleep=lambda s: None)


def test_spec_without_default_is_refused():
    with pytest.raises(ValueError, match="default"):
        sync(proxy_client(FakeProxy()), FakeSecrets(), "gateway-keys", {"keys": {"web": {}}})


def test_migrate_creates_litellm_database_idempotently(pg):
    from audit_agent.handlers.migrate import ensure_litellm_db
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as conn:
        conn.execute("drop database if exists litellm_test")
        conn.execute("drop role if exists litellm_test_user")
        ensure_litellm_db(conn, "litellm_test_user", "pw-one-1234", "litellm_test")
        ensure_litellm_db(conn, "litellm_test_user", "pw-two-5678", "litellm_test")   # re-run: no error
        owner = conn.execute("select pg_get_userbyid(datdba) o from pg_database where datname = 'litellm_test'").fetchone()[0]
        assert owner == "litellm_test_user"
        assert conn.execute("select rolcanlogin from pg_roles where rolname = 'litellm_test_user'").fetchone()[0]
        conn.execute("drop database litellm_test")
        conn.execute("drop role litellm_test_user")


def test_components_use_their_own_keys(monkeypatch):
    from audit_agent.config import Settings
    from audit_agent.handlers import deps
    from audit_agent.llm import GatewayKeys

    keys = GatewayKeys({"default": "sk-d", "fix": "sk-f", "web": "sk-w"})
    assert keys.named("fix") == "sk-f" and keys.named("infra") == "sk-d" and keys.for_teams(("web",)) == "sk-w"
    monkeypatch.setenv("LLM_BACKEND", "gateway")
    monkeypatch.setenv("GATEWAY_URL", "http://litellm.audit-demo.internal:4000/v1")
    monkeypatch.setattr(deps, "_keys", lambda s: keys)
    client = deps.named_llm(Settings.from_env(), "fix")
    assert client._client.api_key == "sk-f" and str(client._client.base_url).startswith("http://litellm.audit-demo.internal")
