"""Dependencies built once per Lambda container. Tests replace them with set_deps()."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from ..config import Settings, load_json_secret, load_secret
from ..db import Database
from ..github import GitHubApp, GitHubClient
from ..llm import LLM, BedrockLLM, GatewayKeys, GatewayLLM


@dataclass
class Deps:
    settings: Settings
    db: Database
    verifier: Any                                   # .verify(token) -> claims
    llm_for: Callable[[tuple[str, ...]], LLM]       # team ids -> client with that team's gateway key
    github: GitHubClient | None


_deps: Deps | None = None


def set_deps(deps: Deps | None) -> None:
    global _deps
    _deps = deps


def get_deps() -> Deps:
    global _deps
    if _deps is None:
        _deps = _build()
    return _deps


def _build() -> Deps:
    from ..auth import EntraVerifier

    s = Settings.from_env()
    llm_for = _bedrock(s) if s.llm_backend == "bedrock" else _gateway(s)

    github = None
    if s.github_app_id and s.github_installation_id and s.github_private_key_secret:
        github = GitHubApp(s.github_org, s.github_app_id, s.github_installation_id,
                           load_secret(s.github_private_key_secret, s.aws_region), owner_type=s.github_owner_type)

    verifier = EntraVerifier(s.entra_tenant_id, s.entra_audience) if s.entra_tenant_id else None
    return Deps(settings=s, db=Database(s), verifier=verifier, llm_for=llm_for, github=github)


def _gateway(s: Settings) -> Callable[[tuple[str, ...]], LLM]:
    if s.gateway_keys_secret:
        keys = GatewayKeys(load_json_secret(s.gateway_keys_secret, s.aws_region))
    else:
        keys = GatewayKeys({"default": os.environ["GATEWAY_API_KEY"]})
    clients: dict[str, GatewayLLM] = {}

    def llm_for(team_ids: tuple[str, ...]) -> LLM:
        key = keys.for_teams(team_ids)
        if key not in clients:
            clients[key] = GatewayLLM(s.gateway_url, key)
        return clients[key]
    return llm_for


def _bedrock(s: Settings) -> Callable[[tuple[str, ...]], LLM]:
    client = BedrockLLM(s.aws_region)
    return lambda team_ids: client
