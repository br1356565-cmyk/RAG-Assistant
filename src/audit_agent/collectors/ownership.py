"""Repo ownership: the single answer to "whose repo is this", used by every report."""
from __future__ import annotations

import json
import os
import pathlib
import re

import yaml

from .base import CollectorOutput, FindingRecord

DATA_DIR = pathlib.Path(__file__).resolve().parents[1] / "data"
DEFAULT_CONFIG = DATA_DIR / "ownership.yml"


def config_path() -> pathlib.Path:
    """OWNERSHIP_CONFIG picks a bundled file by name (e.g. ownership.demo.yml)."""
    name = os.environ.get("OWNERSHIP_CONFIG", "ownership.yml")
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.ya?ml", name):
        raise ValueError(f"OWNERSHIP_CONFIG must be a file name in audit_agent/data, not {name!r}")
    return DATA_DIR / name


def load_config(path: pathlib.Path | None = None) -> dict:
    cfg = yaml.safe_load((path or config_path()).read_text())
    ids = [t["id"] for t in cfg["teams"]]
    # Entra group object ids differ per tenant, so they can come from the environment
    # (Terraform var team_group_ids) instead of being committed: {"team_id": "group-oid"}.
    group_ids = json.loads(os.environ.get("TEAM_GROUP_IDS") or "{}")
    unknown = set(group_ids) - set(ids)
    if unknown:
        raise ValueError(f"TEAM_GROUP_IDS names unknown team(s): {sorted(unknown)}")
    for t in cfg["teams"]:
        if t["id"] in group_ids:
            t["entra_group_id"] = group_ids[t["id"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate team ids in ownership config")
    for rule in cfg.get("rules", []):
        if rule["team"] not in ids:
            raise ValueError(f"rule refers to unknown team {rule['team']}")
    return cfg


def _matches(rule: dict, name: str, topics: set[str], admin_sets: dict[str, set[str]]) -> str | None:
    """Return a short reason if the rule matches, else None."""
    n = name.lower()
    if slug := rule.get("admin_of_github_team"):
        if name in admin_sets.get(slug, set()):
            return f"admin of {slug}"
    for t in rule.get("topic", []):
        if t in topics:
            return f"topic {t}"
    for p in rule.get("name_prefix", []):
        if n.startswith(p):
            return f"name starts with {p}"
    for s in rule.get("name_suffix", []):
        if n.endswith(s):
            return f"name ends with {s}"
    for c in rule.get("name_contains", []):
        if c in n:
            return f"name contains {c}"
    return None


def classify(name: str, topics: set[str], cfg: dict, admin_sets: dict[str, set[str]]) -> tuple[str | None, str, str]:
    """-> (team or None, source, confidence)."""
    if name in (cfg.get("overrides") or {}):
        return cfg["overrides"][name], "override", "confirmed"
    for rule in cfg.get("rules", []):
        reason = _matches(rule, name, topics, admin_sets)
        if reason:
            confidence = "confirmed" if reason.startswith("admin of") else "likely"
            return rule["team"], f"rule: {reason}", confidence
    if cfg.get("fallback_team"):
        return cfg["fallback_team"], "fallback", "unknown"
    return None, "no rule matched", "unknown"


def collect(github, cfg: dict | None = None) -> CollectorOutput:
    cfg = cfg or load_config()
    known = {t["id"] for t in cfg["teams"]}
    admin_sets = {r["admin_of_github_team"]: github.team_admin_repos(r["admin_of_github_team"])
                  for r in cfg.get("rules", []) if r.get("admin_of_github_team")}
    out = CollectorOutput("ownership", complete=True, owners=[], teams=cfg["teams"])
    for repo in github.list_org_repos():
        if repo.get("archived") or repo.get("disabled"):
            continue
        name = repo["name"]
        team, source, confidence = classify(name, {t.lower() for t in repo.get("topics") or []}, cfg, admin_sets)
        if team and team not in known:
            out.warnings.append(f"{name}: assigned to unknown team '{team}' ({source})")
            source, team, confidence = f"{source} -> unknown team {team}", None, "unknown"
        out.owners.append({"repo": name, "team_id": team, "source": source, "confidence": confidence})
        if team is None:
            out.findings.append(FindingRecord(
                source="ownership", resource=name, rule="no_owner", severity="low",
                title=f"Repo has no owning team ({source})", details={"reason": source}))
    return out
