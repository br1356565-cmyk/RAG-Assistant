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
    gateway = GatewayClient(os.environ["GATEWAY_MCP_URL"],
                            {k: names[k] for k in ("read_repo_file", "open_fix_pr")},
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
    return FixExecutor(service, key)


if __name__ == "__main__":
    from bedrock_agentcore.runtime.a2a import serve_a2a

    from fix_agent.a2a_server import context_builder

    serve_a2a(build(), context_builder=context_builder())
