"""Remote versions of tools: same name, schema, modes and flags, but executed by the tool
Lambda behind AgentCore Gateway. The model sees no difference."""
from __future__ import annotations

from dataclasses import replace

from .base import Tool, ToolContext, ToolError, ToolResult


def remote_version(tool: Tool, gateway) -> Tool:
    def handler(ctx: ToolContext, args) -> ToolResult:
        try:
            out = gateway.call(tool.name, args.model_dump(mode="json", exclude_none=True), ctx.scope)
        except Exception as exc:  # noqa: BLE001 - surface as a tool error the model can react to
            raise ToolError(f"{tool.name} is unavailable right now ({type(exc).__name__}).") from exc
        if "error" in out:
            raise ToolError(str(out["error"])[:500])
        return ToolResult(out.get("data"), finding_ids=set(out.get("finding_ids") or []),
                          sources=set(out.get("sources") or []))
    return replace(tool, handler=handler)
