"""Fix agent entry point on AgentCore Runtime (code deploy: entry_point ["fix_main.py"])."""
from __future__ import annotations

import logging
import os

logging.basicConfig(level=logging.INFO)


def build():
    from langgraph.checkpoint.postgres import PostgresSaver

    from audit_agent.config import Settings, load_secret
    from audit_agent.db import Database
    from audit_agent.gateway_client import GatewayClient, sigv4_signer
    from audit_agent.handlers.deps import gateway_tool_names
    from audit_agent.llm import BedrockLLM, GatewayLLM

    from fix_agent.a2a_server import FixExecutor
    from fix_agent.graph import FixDeps
    from fix_agent.service import FixService

    s = Settings.from_env()
    key = load_secret(os.environ["SCOPE_KEY_SECRET"], s.aws_region).encode()
    names = gateway_tool_names(include_write=True)
    wanted = ("read_repo_file", "open_fix_pr", "list_infra_files", "read_infra_file", "open_infra_pr",
              "list_team_resources", "describe_resource")
    gateway = GatewayClient(os.environ["GATEWAY_MCP_URL"], {k: names[k] for k in wanted if k in names},
                            key, signer=sigv4_signer(s.aws_region))
    db = Database(s)

    def read_file(scope, repo, path):
        out = gateway.call("read_repo_file", {"repo": repo, "path": path}, scope)
        if "error" in out:
            raise RuntimeError(out["error"])
        return out["data"]

    def open_pr(scope, fix_request_id):
        out = gateway.call("open_fix_pr", {"fix_request_id": fix_request_id}, scope)
        if "error" in out:
            raise RuntimeError(out["error"])
        return out["data"]

    llm = BedrockLLM(s.aws_region) if s.llm_backend == "bedrock" else GatewayLLM(s.gateway_url, os.environ.get("GATEWAY_API_KEY", ""))
    saver = PostgresSaver(Database(s).conn)    # its own connection; tables created by the migrate step
    service = FixService(FixDeps(db=db, read_file=read_file, open_pr=open_pr, llm=llm, model=s.batch_model), saver)
    return FixExecutor(service, key, infra=build_infra(db, gateway, llm, s, saver))


def build_infra(db, gateway, llm, s, saver):
    """The Terraform drafter: its repo, AWS and write tools go through the Gateway (Policy
    allows them for this role); memory and history are read in-process under row-level security."""
    if os.environ.get("INFRA_DRAFTER") != "true":
        return None
    from types import SimpleNamespace

    from audit_agent.tools import tools_for
    from fix_agent.infra_graph import InfraDeps
    from fix_agent.infra_service import InfraService

    def read_infra(scope, path):
        out = gateway.call("read_infra_file", {"path": path}, scope)
        return None if "error" in out else out["data"]["content"]

    def open_pr(scope, request_id):
        out = gateway.call("open_infra_pr", {"request_id": request_id}, scope)
        if "error" in out:
            raise RuntimeError(out["error"])
        return out["data"]

    tool_deps = SimpleNamespace(gateway=gateway, aws=None, ssm=None, fix_client=None)
    deps = InfraDeps(db=db, tools=lambda: tools_for("infra", tool_deps), llm_for=lambda teams: llm,
                     model=os.environ.get("INFRA_MODEL") or s.chat_model, read_infra=read_infra, open_pr=open_pr,
                     repo=os.environ.get("INFRA_REPO", "demo-infra-terraform"))
    return InfraService(deps, saver)


if __name__ == "__main__":
    from bedrock_agentcore.runtime.a2a import serve_a2a

    from fix_agent.a2a_server import context_builder

    serve_a2a(build(), context_builder=context_builder())
