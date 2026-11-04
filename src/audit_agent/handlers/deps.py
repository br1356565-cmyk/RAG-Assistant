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
    # Starts a chat job in the background (payload {"_job": {...}}). None = answer synchronously.
    dispatch: Callable[[dict], None] | None = None
    memory: Any = None          # PostgresMemory (default) or AgentCoreMemory
    gateway: Any = None         # GatewayClient: remote GitHub/diagnostics tools behind AgentCore Gateway
    ssm: Any = None             # in-process diagnostics (local); remote ones go through the gateway
    fix_client: Any = None      # LocalFixClient or A2AFixClient
    runtime: Any = None         # RuntimeClient: chat answered by the agent on AgentCore Runtime
    scope_key: bytes | None = None
    states: Any = None          # Step Functions client, to release review gates


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
    dispatch = _self_invoker() if os.environ.get("CHAT_ASYNC") == "true" else None
    db = Database(s)
    return Deps(settings=s, db=db, verifier=verifier, llm_for=llm_for, github=github, dispatch=dispatch,
                **_agentcore_parts(s, db))


# Gateway tool names are "<target>___<tool>"; Terraform owns the target names and passes the
# map as GATEWAY_TOOLS (JSON). The defaults match terraform/agentcore.tf.
DEFAULT_GATEWAY_TOOLS = {"get_advisory": "gh-advisory___get_advisory", "read_repo_file": "gh-file___read_repo_file",
                         "search_code": "gh-search___search_code"}
DIAGNOSTIC_GATEWAY_TOOLS = {"list_instances": "ops-instances___list_instances",
                            "run_diagnostic": "ops-diagnostic___run_diagnostic"}


def gateway_tool_names(include_write: bool = False) -> dict[str, str]:
    import json

    raw = os.environ.get("GATEWAY_TOOLS")
    if raw:
        names = json.loads(raw)
    else:
        names = dict(DEFAULT_GATEWAY_TOOLS)
        if os.environ.get("DIAGNOSTICS_ENABLED") == "true":
            names |= DIAGNOSTIC_GATEWAY_TOOLS
        names["open_fix_pr"] = "gh-write___open_fix_pr"
    if not include_write:
        names.pop("open_fix_pr", None)
    return names


def _agentcore_parts(s: Settings, db: Database) -> dict:
    """Optional AgentCore pieces, each switched on by its environment variable."""
    import boto3

    from ..memory import AgentCoreMemory, PostgresMemory

    e = os.environ
    parts: dict = {"memory": AgentCoreMemory(e["MEMORY_ID"], region=s.aws_region) if e.get("MEMORY_ID")
                   else PostgresMemory(db)}
    key = load_secret(e["SCOPE_KEY_SECRET"], s.aws_region).encode() if e.get("SCOPE_KEY_SECRET") else None
    parts["scope_key"] = key
    if e.get("GATEWAY_MCP_URL") and key:
        from ..gateway_client import GatewayClient, sigv4_signer
        parts["gateway"] = GatewayClient(e["GATEWAY_MCP_URL"], gateway_tool_names(), key,
                                         signer=sigv4_signer(s.aws_region))
    if e.get("FIX_AGENT_URL") and key:
        from ..fix_client import A2AFixClient
        from ..gateway_client import sigv4_signer
        parts["fix_client"] = A2AFixClient(e["FIX_AGENT_URL"], key, signer=sigv4_signer(s.aws_region))
    if e.get("AGENT_RUNTIME_URL"):
        from ..runtime_client import RuntimeClient
        parts["runtime"] = RuntimeClient(e["AGENT_RUNTIME_URL"])
    if e.get("STATE_MACHINE_ARN"):
        parts["states"] = boto3.client("stepfunctions", region_name=s.aws_region)
    return parts


def _self_invoker() -> Callable[[dict], None]:
    """Invoke this same function (its `live` alias) asynchronously for a background job."""
    import json

    import boto3

    client = boto3.client("lambda")
    name = os.environ["AWS_LAMBDA_FUNCTION_NAME"]

    def dispatch(payload: dict) -> None:
        client.invoke(FunctionName=name, Qualifier="live", InvocationType="Event",
                      Payload=json.dumps(payload).encode())
    return dispatch


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
