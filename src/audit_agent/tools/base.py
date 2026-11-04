"""Tool registry.

A tool is a typed function: a Pydantic model describes its arguments (and generates the
JSON schema the model sees), the handler receives a ToolContext built from the verified
request, never from the model. Tools have no way to widen their own scope.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, ValidationError

from ..db import Database, Scope
from ..github import GitHubClient

FP_RE = re.compile(r"^(?:F-)?([0-9a-f]{16})$")


def ref(fingerprint: str) -> str:
    return f"F-{fingerprint}"


def parse_ref(value: str) -> str:
    m = FP_RE.match(value.strip())
    if not m:
        raise ToolError("Finding ids look like F-0123456789abcdef")
    return m.group(1)


class ToolError(Exception):
    """An expected failure, shown to the model so it can adjust."""


class Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class ToolContext:
    scope: Scope
    db: Database
    github: GitHubClient | None = None
    mode: str = "chat"
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ssm: Any = None             # diagnostics: object with .client (SSM) and .ec2 (EC2); None = off
    aws: Any = None             # AWS read tools: object with .logs, .tagging, .config (each optional)
    extra: dict = field(default_factory=dict)  # mode-specific context, e.g. the infra request being drafted
    fix_client: Any = None      # request_fix: object with .request_fix(scope, fingerprint); None = off
    # What this run has actually seen; used to check citations and sources.
    retrieved_findings: set[str] = field(default_factory=set)
    retrieved_sources: set[str] = field(default_factory=set)

    def teams_for(self, team: str | None) -> tuple[str, ...]:
        """Resolve an optional team argument against the caller's scope.

        Narrowing only: a team outside the caller's scope is refused here, and row-level
        security would return nothing for it anyway. Admins without a team get every team.
        """
        if team:
            if self.scope.is_admin or team in self.scope.team_ids:
                return (team,)
            raise ToolError(f"Team '{team}' is outside your access.")
        if self.scope.is_admin:
            with self.db.scoped(self.scope) as conn:
                return tuple(r["id"] for r in conn.execute("select id from teams order by id").fetchall())
        if not self.scope.team_ids:
            raise ToolError("You belong to no team; pass `team` to choose one.")
        return self.scope.team_ids

    def team_filter(self, team: str | None) -> tuple[str, list]:
        """SQL filter for findings. Admins may pass team='unowned' to see repos nobody owns."""
        if team == "unowned":
            if not self.scope.is_admin:
                raise ToolError("Only security admins can view unowned findings.")
            return "team_id is null", []
        return "team_id = any(%s)", [list(self.teams_for(team))]


@dataclass
class ToolResult:
    data: Any
    finding_ids: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    args_model: type[Args]
    handler: Callable[[ToolContext, Any], ToolResult]
    modes: frozenset[str]
    terminal: bool = False      # a successful call ends the run (structured output)
    untrusted: bool = False     # result contains third-party text: wrap as data

    def schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": _clean_schema(self.args_model.model_json_schema()),
            },
        }

    def parse(self, raw: str) -> Args:
        try:
            return self.args_model.model_validate_json(raw or "{}")
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc']) or 'arguments'}: {e['msg']}" for e in exc.errors()[:5]
            )
            raise ToolError(f"Invalid arguments: {problems}") from exc


def _clean_schema(node: Any) -> Any:
    """Drop Pydantic 'title' noise to save tokens; keep everything the model needs."""
    if isinstance(node, dict):
        return {k: _clean_schema(v) for k, v in node.items() if k != "title"}
    if isinstance(node, list):
        return [_clean_schema(v) for v in node]
    return node


REGISTRY: dict[str, Tool] = {}


def tool(name: str, description: str, args: type[Args], modes: set[str], *,
         terminal: bool = False, untrusted: bool = False):
    def register(fn: Callable[[ToolContext, Any], ToolResult]):
        if name in REGISTRY:
            raise ValueError(f"duplicate tool {name}")
        REGISTRY[name] = Tool(name, description, args, fn, frozenset(modes), terminal, untrusted)
        return fn
    return register


def tools_for(mode: str, deps: Any = None) -> list[Tool]:
    """The tools a mode may use. With a Gateway client in `deps`, the GitHub and diagnostics
    tools run remotely behind AgentCore Gateway instead of in-process (same schemas)."""
    from . import advisory, aws_ops, diagnostics, findings, fix, infra, notes, repo, submit  # noqa: F401  (registers tools)

    tools = [t for t in REGISTRY.values() if mode in t.modes]
    gateway = getattr(deps, "gateway", None)
    remote = set(gateway.tool_names) if gateway is not None else set()
    # Optional tools appear only where they can work.
    if getattr(deps, "fix_client", None) is None:
        tools = [t for t in tools if t.name != "request_fix"]
    if getattr(deps, "ssm", None) is None:
        tools = [t for t in tools if t.name not in DIAGNOSTIC_TOOLS or t.name in remote]
    aws = getattr(deps, "aws", None)
    if getattr(aws, "logs", None) is None:
        tools = [t for t in tools if t.name not in LOG_TOOLS or t.name in remote]
    if getattr(aws, "config", None) is None:
        tools = [t for t in tools if t.name not in CONFIG_TOOLS or t.name in remote]
    if gateway is not None:
        from .remote import remote_version
        tools = [remote_version(t, gateway) if t.name in remote else t for t in tools]
    return tools


DIAGNOSTIC_TOOLS = {"list_instances", "run_diagnostic"}
LOG_TOOLS = {"list_log_groups", "query_logs"}
CONFIG_TOOLS = {"list_team_resources", "describe_resource", "noncompliant_resources"}
