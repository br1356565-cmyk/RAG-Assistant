"""Plain-English progress labels for tool calls ("Checking GitHub advisory GHSA-…").

Arguments come from the model, so they are treated as untrusted text: parsed defensively,
shortened, and stripped of control characters. The web app renders labels as text only.
"""
from __future__ import annotations

import json
import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def _s(value, limit: int = 60) -> str:
    text = _CONTROL.sub(" ", str(value)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def label(name: str, raw_args: str | None) -> str:
    try:
        a = json.loads(raw_args or "{}")
        if not isinstance(a, dict):
            a = {}
    except (json.JSONDecodeError, TypeError):
        a = {}

    if name == "get_team_overview":
        return "Loading your team's overview"
    if name == "search_findings":
        parts = []
        sev = a.get("severity")
        if isinstance(sev, list) and sev:
            parts.append(", ".join(_s(x, 10) for x in sev[:4]))
        if a.get("source"):
            parts.append(_s(a["source"], 20))
        text = "Searching " + (" ".join(parts) + " findings" if parts else "findings")
        if a.get("repo"):
            text += f" in {_s(a['repo'])}"
        if a.get("text"):
            text += f" for “{_s(a['text'], 40)}”"
        return text
    if name == "get_finding":
        return f"Opening finding {_s(a.get('id', ''), 20)}".strip()
    if name == "get_trend":
        return "Looking at the weekly trend"
    if name == "list_team_notes":
        return "Checking team notes (accepted risks, context)"
    if name == "propose_team_note":
        return "Drafting a team note for a lead to approve"
    if name == "get_advisory":
        return f"Checking GitHub advisory {_s(a.get('ghsa_id', ''), 30)}".strip()
    if name == "read_repo_file":
        return f"Reading {_s(a.get('path', 'a file'), 50)} in {_s(a.get('repo', 'the repo'))} on GitHub"
    if name == "search_code":
        return f"Searching {_s(a.get('repo', 'the repo'))} on GitHub for “{_s(a.get('query', ''), 40)}”"
    if name == "submit_investigation":
        return "Writing up the investigation"
    return f"Running {_s(name, 40)}"
