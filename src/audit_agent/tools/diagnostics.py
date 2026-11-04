"""Read-only server diagnostics through AWS Systems Manager. No SSH, no shell for the model.

The model picks an instance and one check from a fixed menu; the commands themselves live
in an SSM document (terraform/diagnostics.tf) with validated parameters. Only instances
tagged agent-diagnostics=allowed AND team=<one of the caller's teams> are reachable (admins:
any allowed instance); IAM also restricts Run Command to that tag and that document.
Output is third-party text (logs are attacker-controllable), so it is wrapped as untrusted.

Anything that changes state (restart, clean up a disk) is not here: that goes through the
fix agent's approval gate.
"""
from __future__ import annotations

import os
import time
from typing import Literal

from pydantic import Field

from .base import Args, ToolContext, ToolError, ToolResult, tool

CHECKS = ("disk_usage", "memory", "top_processes", "listening_ports", "service_status", "recent_logs", "uptime")
MAX_OUTPUT = 4_000


def _allowlist(env: str) -> list[str]:
    return [x for x in os.environ.get(env, "").split(",") if x]


def _ssm(ctx: ToolContext):
    if ctx.ssm is None:
        raise ToolError("Server diagnostics are not configured in this environment.")
    return ctx.ssm


def _allowed_instances(ctx: ToolContext) -> list[dict]:
    ec2 = ctx.ssm.ec2
    filters = [{"Name": "tag:agent-diagnostics", "Values": ["allowed"]},
               {"Name": "instance-state-name", "Values": ["running"]}]
    if not ctx.scope.is_admin:
        filters.append({"Name": "tag:team", "Values": list(ctx.scope.team_ids) or ["-"]})
    out = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=filters):
        for res in page["Reservations"]:
            for i in res["Instances"]:
                tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                out.append({"instance_id": i["InstanceId"], "name": tags.get("Name", ""),
                            "team": tags.get("team"), "type": i.get("InstanceType")})
    return out


class NoArgs(Args):
    pass


@tool(
    "list_instances",
    "Servers you may run diagnostics on (tagged for agent diagnostics and owned by your team).",
    NoArgs, {"chat"},
)
def list_instances(ctx: ToolContext, a: NoArgs) -> ToolResult:
    _ssm(ctx)
    return ToolResult({"instances": _allowed_instances(ctx),
                       "services": _allowlist("DIAGNOSTIC_SERVICES"), "logs": _allowlist("DIAGNOSTIC_LOGS")})


class DiagnosticArgs(Args):
    instance_id: str = Field(pattern=r"^i-[0-9a-f]{8,17}$")
    check: Literal["disk_usage", "memory", "top_processes", "listening_ports", "service_status",
                   "recent_logs", "uptime"]
    target: str | None = Field(None, max_length=64, description="Service name for service_status, log name for recent_logs")


@tool(
    "run_diagnostic",
    "Run one read-only check on a server: disk_usage, memory, top_processes, listening_ports, uptime, "
    "service_status (needs target = service) or recent_logs (needs target = log name). Use list_instances first.",
    DiagnosticArgs, {"chat"}, untrusted=True,
)
def run_diagnostic(ctx: ToolContext, a: DiagnosticArgs) -> ToolResult:
    ssm = _ssm(ctx)
    if a.instance_id not in {i["instance_id"] for i in _allowed_instances(ctx)}:
        raise ToolError(f"Instance {a.instance_id} is not available for diagnostics in your scope.")
    target = ""
    if a.check == "service_status":
        if a.target not in _allowlist("DIAGNOSTIC_SERVICES"):
            raise ToolError(f"service must be one of {_allowlist('DIAGNOSTIC_SERVICES')}")
        target = a.target
    elif a.check == "recent_logs":
        if a.target not in _allowlist("DIAGNOSTIC_LOGS"):
            raise ToolError(f"log must be one of {_allowlist('DIAGNOSTIC_LOGS')}")
        target = a.target
    cmd = ssm.client.send_command(
        InstanceIds=[a.instance_id], DocumentName=os.environ["DIAGNOSTICS_DOCUMENT"],
        Parameters={"check": [a.check], "target": [target or "none"]},
        TimeoutSeconds=30, Comment=f"agent diagnostic by {ctx.scope.user_id}"[:100],
    )["Command"]["CommandId"]
    deadline = time.monotonic() + 25
    while True:
        time.sleep(1.5)
        try:
            inv = ssm.client.get_command_invocation(CommandId=cmd, InstanceId=a.instance_id)
        except ssm.client.exceptions.InvocationDoesNotExist:
            inv = {"Status": "Pending"}
        if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
            break
        if time.monotonic() > deadline:
            raise ToolError("The check did not finish within 25 seconds.")
    output = (inv.get("StandardOutputContent") or "")[:MAX_OUTPUT]
    return ToolResult({"instance_id": a.instance_id, "check": a.check, "target": target or None,
                       "status": inv["Status"], "output": output,
                       "error": (inv.get("StandardErrorContent") or "")[:500] or None},
                      sources={f"diagnostic:{a.instance_id}:{a.check}"})
