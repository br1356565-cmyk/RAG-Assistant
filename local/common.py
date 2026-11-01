"""Shared setup for the local prototype: .env loading and dependency wiring."""
from __future__ import annotations

import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

DATA_DIR = HERE / ".data"


def load_env(path: pathlib.Path = HERE / ".env") -> None:
    """Minimal KEY=VALUE loader; real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def env(name: str, default: str | None = None, required: bool = True) -> str | None:
    value = os.environ.get(name, default)
    if required and not value:
        sys.exit(f"Missing {name}. Copy local/.env.example to local/.env and fill it in.")
    return value


def guard_local() -> None:
    """The dev login must never run anywhere but a developer machine."""
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("AWS_EXECUTION_ENV"):
        sys.exit("Refusing to run the local prototype inside AWS.")


def llm_factory():
    from audit_agent.llm import BedrockLLM, GatewayLLM

    if env("LLM_BACKEND", "gateway") == "bedrock":       # uses your AWS_PROFILE credentials
        client = BedrockLLM(env("AWS_REGION", "us-east-1"))
    else:
        client = GatewayLLM(env("GATEWAY_URL"), env("GATEWAY_API_KEY"))
    return lambda team_ids: client


def github_client():
    from audit_agent.github import GitHubToken

    return GitHubToken(env("GITHUB_ORG", "forbesadvisor"), env("GITHUB_TOKEN"),
                       owner_type=env("GITHUB_OWNER_TYPE", "org"))
