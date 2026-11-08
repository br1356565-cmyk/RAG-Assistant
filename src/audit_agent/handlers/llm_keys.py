"""Creates the LiteLLM virtual keys and stores them in Secrets Manager. Terraform invokes it
after the LiteLLM service is up (aws_lambda_invocation), so nobody generates or copies a key.

  1. read the master key from the LiteLLM secret (Terraform generated it, write-only);
  2. wait until LiteLLM answers /health/readiness (the task may still be starting);
  3. for every key in KEY_SPEC: keep the stored key if LiteLLM still knows it (and update its
     models and budget to the spec), otherwise generate a new one; delete keys the spec dropped;
  4. write {"default": "sk-...", "<team_id>": "sk-...", "fix": ..., "infra": ...} to the
     gateway keys secret the agents read.

Idempotent: re-running changes nothing unless the spec or LiteLLM's database changed. The
return value (kept in Terraform state) has names and counts only, never a key.

KEY_SPEC (JSON): {"prefix": "audit-demo", "keys": {"<name>": {"models": [...],
  "max_budget": 5.0, "budget_duration": "30d", "rpm_limit": 60, "tpm_limit": 100000}}}
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request

log = logging.getLogger()
log.setLevel(logging.INFO)

KEY_FIELDS = ("models", "max_budget", "budget_duration", "rpm_limit", "tpm_limit")


class LiteLLM:
    def __init__(self, base_url: str, master_key: str, timeout_s: float = 15.0, opener=None):
        self.base = base_url.rstrip("/")
        self.master = master_key
        self.timeout = timeout_s
        self.open = opener or urllib.request.urlopen

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(
            self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.master}", "Content-Type": "application/json"})
        try:
            with self.open(req, timeout=self.timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except ValueError:
                return exc.code, {}

    def wait_ready(self, deadline: float, sleep=time.sleep) -> None:
        last = ""
        while time.monotonic() < deadline:
            try:
                status, _ = self._call("GET", "/health/readiness")
                if status == 200:
                    return
                last = f"HTTP {status}"
            except Exception as exc:  # noqa: BLE001 - DNS/connection errors while the task starts
                last = type(exc).__name__
            log.info(json.dumps({"event": "litellm_wait", "last": last}))
            sleep(10)
        raise TimeoutError(f"LiteLLM did not become ready ({last})")

    def key_exists(self, key: str) -> bool:
        status, _ = self._call("GET", f"/key/info?key={urllib.request.quote(key)}")
        return status == 200

    def generate(self, alias: str, spec: dict, name: str) -> str:
        status, out = self._call("POST", "/key/generate", {
            "key_alias": alias, **{k: spec[k] for k in KEY_FIELDS if k in spec},
            "metadata": {"managed_by": "terraform", "name": name}})
        if status != 200 or not out.get("key"):
            raise RuntimeError(f"/key/generate for {alias} failed: HTTP {status} {str(out)[:200]}")
        return out["key"]

    def update(self, key: str, spec: dict) -> None:
        status, out = self._call("POST", "/key/update", {"key": key, **{k: spec[k] for k in KEY_FIELDS if k in spec}})
        if status != 200:
            raise RuntimeError(f"/key/update failed: HTTP {status} {str(out)[:200]}")

    def delete(self, keys: list[str]) -> None:
        if keys:
            self._call("POST", "/key/delete", {"keys": keys})


def _stored_keys(sm, secret_id: str) -> dict:
    try:
        return json.loads(sm.get_secret_value(SecretId=secret_id)["SecretString"] or "{}")
    except sm.exceptions.ResourceNotFoundException:      # no value yet (first apply)
        return {}
    except ValueError:
        return {}


def sync(litellm: LiteLLM, sm, keys_secret: str, spec: dict) -> dict:
    prefix = spec.get("prefix", "audit")
    wanted = spec["keys"]
    if "default" not in wanted:
        raise ValueError("KEY_SPEC needs a 'default' key")
    stored = _stored_keys(sm, keys_secret)
    out, created, updated = {}, [], []
    for name, k in wanted.items():
        current = stored.get(name)
        if current and litellm.key_exists(current):
            litellm.update(current, k)
            out[name] = current
            updated.append(name)
        else:
            out[name] = litellm.generate(f"{prefix}-{name}", k, name)
            created.append(name)
    dropped = sorted(set(stored) - set(wanted))
    litellm.delete([stored[n] for n in dropped if stored.get(n)])
    if out != stored:
        sm.put_secret_value(SecretId=keys_secret, SecretString=json.dumps(out, sort_keys=True))
    return {"created": sorted(created), "kept": sorted(updated), "deleted": dropped}


def handler(event: dict, context, sm=None, litellm: LiteLLM | None = None) -> dict:
    import boto3

    region = os.environ.get("AWS_REGION", "us-east-1")
    sm = sm or boto3.client("secretsmanager", region_name=region)
    if litellm is None:
        secret = json.loads(sm.get_secret_value(SecretId=os.environ["LITELLM_SECRET_ARN"])["SecretString"])
        litellm = LiteLLM(os.environ["LITELLM_URL"], secret["master_key"])
    budget = (context.get_remaining_time_in_millis() / 1000 - 60) if context else 60
    litellm.wait_ready(time.monotonic() + max(budget, 10))
    result = sync(litellm, sm, os.environ["GATEWAY_KEYS_SECRET"], json.loads(os.environ["KEY_SPEC"]))
    log.info(json.dumps({"event": "litellm_keys", **result}))
    return {"status": "ok", **result}
