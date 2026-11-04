"""Lambda behind AgentCore Gateway: runs the remote tools.

Gateway invokes this function with the tool's arguments as the event and the tool name in
context.client_context.custom["bedrockAgentCoreToolName"] ("<target>___<tool>").

Every call must carry a valid scope token (_scope), signed by the harness after the model
chose the call. The scope rebuilt from it is enforced exactly as for in-process tools:
ownership checks in the tool, row-level security in the database.

Targets:
  github_read  get_advisory, read_repo_file, search_code     (both agents)
  ops_read     list_instances, run_diagnostic                (audit agent)
  aws_read     list_log_groups, query_logs, list_team_resources, describe_resource,
               noncompliant_resources                        (audit agent)
  github_write open_fix_pr                                   (fix agent only; Policy + approval check)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from ..config import Settings, load_secret
from ..db import Database
from ..github import GitHubApp
from ..scope_token import ScopeTokenError, verify
from ..tools.base import REGISTRY, ToolContext, ToolError, tools_for

log = logging.getLogger()
log.setLevel(logging.INFO)

READ_TOOLS = {"get_advisory", "read_repo_file", "search_code", "list_instances", "run_diagnostic",
              "list_log_groups", "query_logs", "list_team_resources", "describe_resource", "noncompliant_resources"}
WRITE_TOOLS = {"open_fix_pr"}


@dataclass
class SSMClients:
    client: Any
    ec2: Any


@lru_cache(maxsize=1)
def _env():
    import boto3

    s = Settings.from_env()
    key = load_secret(os.environ["SCOPE_KEY_SECRET"], s.aws_region).encode()
    github = GitHubApp(s.github_org, s.github_app_id, s.github_installation_id,
                       load_secret(s.github_private_key_secret, s.aws_region), owner_type=s.github_owner_type)
    ssm = SSMClients(boto3.client("ssm"), boto3.client("ec2")) if os.environ.get("DIAGNOSTICS_DOCUMENT") else None
    from ..tools.aws_ops import AwsClients
    ssm_aws = (ssm, AwsClients.from_env(s.aws_region))
    return s, key, Database(s), github, ssm_aws


def tool_name(context) -> str:
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    full = custom.get("bedrockAgentCoreToolName") or ""
    return full.split("___", 1)[-1]


def handler(event: dict, context, env=None) -> dict:
    s, key, db, github, clients = env or _env()
    ssm, aws = clients if isinstance(clients, tuple) else (clients, None)
    name = tool_name(context)
    args = dict(event or {})
    token = args.pop("_scope", None)
    try:
        if not token:
            raise ScopeTokenError("missing scope token")
        scope, claims = verify(str(token), key)
    except ScopeTokenError as exc:
        log.warning(json.dumps({"event": "gateway_tool_denied", "tool": name, "reason": str(exc)}))
        return {"error": f"refused: {exc}"}

    try:
        if name in WRITE_TOOLS:
            from fix_agent.github_write import WriteRefused, open_fix_pr
            try:
                out = open_fix_pr(db, scope, args.get("fix_request_id", ""), claims)
            except WriteRefused as exc:            # a deliberate refusal: pass its reason on
                return {"error": str(exc)}
            return {"data": out}
        if name not in READ_TOOLS or name not in REGISTRY:
            return {"error": f"unknown tool {name!r}"}
        tool = REGISTRY[name]
        ctx = ToolContext(scope=scope, db=db, github=github, mode="remote", ssm=ssm, aws=aws)
        result = tool.handler(ctx, tool.args_model.model_validate(args))
        return {"data": result.data, "finding_ids": sorted(result.finding_ids), "sources": sorted(result.sources)}
    except ToolError as exc:
        return {"error": str(exc)}
    except Exception:  # noqa: BLE001
        log.exception("gateway tool %s failed", name)
        return {"error": f"{name} failed unexpectedly"}
    finally:
        log.info(json.dumps({"event": "gateway_tool", "tool": name, "user": scope.user_id if token else None}))


# Make sure every registered tool module is loaded (REGISTRY is filled on import).
tools_for("chat")
