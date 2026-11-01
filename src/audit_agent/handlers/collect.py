"""Collector Lambda (outside the VPC: it only calls GitHub/AWS APIs and writes to S3).

Input:  {"collector": "dependabot", "run_id": "<execution name>"}
Output: {"collector", "status": "succeeded", "key", "count", "complete", "warnings"}
Raises on failure so Step Functions records the collector as failed.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from ..collectors import dependabot, guardduty, ownership
from ..collectors.base import CollectorOutput
from ..config import Settings, load_secret
from ..github import GitHubApp

log = logging.getLogger()
log.setLevel(logging.INFO)


@dataclass
class CollectDeps:
    github: Any
    s3: Any
    bucket: str
    aws_session: Callable[[], Any]


_deps: CollectDeps | None = None


def set_deps(d: CollectDeps | None) -> None:
    global _deps
    _deps = d


def _build() -> CollectDeps:
    import boto3

    s = Settings.from_env()
    gh = GitHubApp(s.github_org, s.github_app_id, s.github_installation_id,
                   load_secret(s.github_private_key_secret, s.aws_region), owner_type=s.github_owner_type)

    def aws_session():
        role = os.environ.get("SECURITY_AUDIT_ROLE_ARN")
        if not role:
            return boto3.Session()
        c = boto3.client("sts").assume_role(RoleArn=role, RoleSessionName="devops-audit-collector")["Credentials"]
        return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                             aws_session_token=c["SessionToken"])

    return CollectDeps(github=gh, s3=boto3.client("s3"), bucket=os.environ["DATA_BUCKET"], aws_session=aws_session)


def run(name: str, d: CollectDeps) -> CollectorOutput:
    if name == "ownership":
        return ownership.collect(d.github)
    if name == "dependabot":
        return dependabot.collect(d.github)
    if name == "guardduty":
        regions = [r for r in os.environ.get("GUARDDUTY_REGIONS", "").split(",") if r] or guardduty.DEFAULT_REGIONS
        team = ownership.load_config().get("aws_findings_team", "platform_devops")
        return guardduty.collect(d.aws_session(), regions, team)
    raise ValueError(f"unknown collector {name!r}")


def handler(event: dict, context) -> dict:
    global _deps
    d = _deps or (_deps := _build())
    name, run_id = str(event["collector"]), str(event["run_id"])
    out = run(name, d)
    key = f"runs/{run_id}/{name}.json"
    d.s3.put_object(Bucket=d.bucket, Key=key, Body=json.dumps(out.to_json(), default=str).encode(),
                    ContentType="application/json")
    result = {"collector": name, "status": "succeeded", "key": key, "count": len(out.findings),
              "complete": out.complete, "warnings": out.warnings[:20]}
    log.info(json.dumps({"event": "collect", "run_id": run_id, **result}))
    return result
