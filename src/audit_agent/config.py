"""Settings read once from the Lambda environment."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    # Database: DB_DSN for local/tests; otherwise RDS IAM auth with host/port/name/user.
    db_dsn: str | None
    db_host: str | None
    db_port: int
    db_name: str
    db_user: str
    aws_region: str

    # LiteLLM gateway (OpenAI-compatible). Keys live in Secrets Manager as
    # {"default": "sk-...", "<team_id>": "sk-..."} so spend is attributed per team.
    gateway_url: str
    gateway_keys_secret: str | None
    chat_model: str          # a LiteLLM model alias, e.g. "audit-chat" -> Bedrock Sonnet-class
    batch_model: str         # e.g. "audit-batch" -> Bedrock Haiku-class
    # None (the default) sends no temperature. Claude 5.x models reject any non-default
    # temperature with a 400, so set a number only for models that accept one
    # (e.g. 0.2 for chat, 0 for investigations on older models).
    chat_temperature: float | None
    batch_temperature: float | None

    # Confidence gate (see harness.py): answers below the threshold go back for more evidence,
    # at most max_confidence_retries times, then are returned flagged as low confidence.
    confidence_threshold: float
    max_confidence_retries: int
    verify_answers: bool       # chat: grade each answer with a separate verifier call
    verifier_model: str        # defaults to the batch model (cheaper)

    # Entra ID
    entra_tenant_id: str | None
    entra_audience: str | None

    # Model backend: "gateway" (LiteLLM, the default) or "bedrock" (Converse API directly,
    # for accounts without the gateway). With "bedrock", CHAT_MODEL/BATCH_MODEL are
    # Bedrock model or inference-profile ids.
    llm_backend: str

    # GitHub App (replaces the personal access token)
    github_org: str              # owner of the repos: an org, or a personal account
    github_owner_type: str       # "org" or "user"
    github_app_id: str | None
    github_installation_id: str | None
    github_private_key_secret: str | None

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ
        return cls(
            db_dsn=e.get("DB_DSN"),
            db_host=e.get("DB_HOST"),
            db_port=int(e.get("DB_PORT", "5432")),
            db_name=e.get("DB_NAME", "audit"),
            db_user=e.get("DB_USER", "audit_app_login"),
            aws_region=e.get("AUDIT_AWS_REGION") or e.get("AWS_REGION", "us-east-1"),
            gateway_url=e.get("GATEWAY_URL", "http://localhost:4000"),
            gateway_keys_secret=e.get("GATEWAY_KEYS_SECRET"),
            chat_model=e.get("CHAT_MODEL", "audit-chat"),
            batch_model=e.get("BATCH_MODEL", "audit-batch"),
            chat_temperature=_temperature(e.get("CHAT_TEMPERATURE", "none")),
            batch_temperature=_temperature(e.get("BATCH_TEMPERATURE", "none")),
            confidence_threshold=_fraction("CONFIDENCE_THRESHOLD", e.get("CONFIDENCE_THRESHOLD", "0.7")),
            max_confidence_retries=_bounded_int("MAX_CONFIDENCE_RETRIES", e.get("MAX_CONFIDENCE_RETRIES", "2"), 0, 5),
            verify_answers=e.get("VERIFY_ANSWERS", "true").lower() == "true",
            verifier_model=e.get("VERIFIER_MODEL") or e.get("BATCH_MODEL", "audit-batch"),
            entra_tenant_id=e.get("ENTRA_TENANT_ID"),
            entra_audience=e.get("ENTRA_AUDIENCE"),
            llm_backend=_choice("LLM_BACKEND", e.get("LLM_BACKEND", "gateway"), ("gateway", "bedrock")),
            github_org=e.get("GITHUB_ORG", "forbesadvisor"),
            github_owner_type=_choice("GITHUB_OWNER_TYPE", e.get("GITHUB_OWNER_TYPE", "org"), ("org", "user")),
            github_app_id=e.get("GITHUB_APP_ID"),
            github_installation_id=e.get("GITHUB_INSTALLATION_ID"),
            github_private_key_secret=e.get("GITHUB_PRIVATE_KEY_SECRET"),
        )


def _fraction(name: str, raw: str) -> float:
    value = float(raw)
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must be between 0 and 1")
    return value


def _bounded_int(name: str, raw: str, lo: int, hi: int) -> int:
    value = int(raw)
    if not lo <= value <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return value


def _choice(name: str, value: str, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise ValueError(f"{name} must be one of {allowed}, not {value!r}")
    return value


def _temperature(raw: str) -> float | None:
    """'none' (or empty) = don't send a temperature, for models that reject it."""
    if raw.strip().lower() in ("", "none"):
        return None
    value = float(raw)
    if not 0 <= value <= 2:
        raise ValueError(f"temperature {value} outside 0-2")
    return value


@lru_cache(maxsize=16)
def load_secret(name: str, region: str) -> str:
    """Fetch a secret once per Lambda container."""
    import boto3

    return boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=name)["SecretString"]


def load_json_secret(name: str, region: str) -> dict:
    return json.loads(load_secret(name, region))
