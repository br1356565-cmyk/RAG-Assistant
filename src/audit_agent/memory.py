"""Session memory (short-term), investigation memory and the audit log.

Team knowledge (long-term, shared) lives in team_notes and is reached through tools.
Every function here runs inside a scoped transaction, so RLS applies.
"""
from __future__ import annotations

import hashlib
import json

from .db import Database, Scope

HISTORY_TURNS = 8          # user + assistant messages kept in context
MAX_STORED_CHARS = 4_000


def load_history(db: Database, scope: Scope, session_id: str) -> list[dict]:
    with db.scoped(scope) as conn:
        rows = conn.execute(
            "select role, content from session_turns where user_id = %s and session_id = %s "
            "and expires_at > now() order by turn desc limit %s",
            (scope.user_id, session_id, HISTORY_TURNS),
        ).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


def append_turns(db: Database, scope: Scope, session_id: str, question: str, answer: str,
                 cited: list[str]) -> None:
    with db.scoped(scope) as conn:
        last = conn.execute(
            "select coalesce(max(turn), 0) t from session_turns where user_id = %s and session_id = %s",
            (scope.user_id, session_id),
        ).fetchone()["t"]
        conn.execute(
            "insert into session_turns (user_id, session_id, turn, role, content, cited) values "
            "(%s, %s, %s, 'user', %s, '{}'), (%s, %s, %s, 'assistant', %s, %s)",
            (scope.user_id, session_id, last + 1, question[:MAX_STORED_CHARS],
             scope.user_id, session_id, last + 2, answer[:MAX_STORED_CHARS], cited),
        )


def evidence_hash(finding: dict) -> str:
    """Changes only when the evidence does: severity, status, rule, title or source details.
    Fields starting with '_' in details are treated as volatile and ignored."""
    basis = {
        "severity": finding["severity"], "status": finding["status"], "rule": finding["rule"],
        "title": finding["title"],
        "details": {k: v for k, v in (finding.get("details") or {}).items() if not k.startswith("_")},
    }
    return hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()[:32]


def cached_investigation(db: Database, scope: Scope, fingerprint: str, ev_hash: str,
                         prompt_version: str) -> dict | None:
    with db.scoped(scope) as conn:
        row = conn.execute(
            "select explanation from investigations where fingerprint = %s and evidence_hash = %s "
            "and prompt_version = %s", (fingerprint, ev_hash, prompt_version),
        ).fetchone()
    return row["explanation"] if row else None


def save_investigation(db: Database, scope: Scope, fingerprint: str, team_id: str, ev_hash: str,
                       prompt_version: str, model: str, explanation: dict) -> None:
    with db.scoped(scope) as conn:
        conn.execute(
            "insert into investigations (fingerprint, team_id, evidence_hash, prompt_version, model, explanation) "
            "values (%s, %s, %s, %s, %s, %s) on conflict (fingerprint, evidence_hash, prompt_version) do nothing",
            (fingerprint, team_id, ev_hash, prompt_version, model, json.dumps(explanation)),
        )


def write_audit(db: Database, scope: Scope, *, mode: str, question: str | None, tools: list[dict],
                finding_ids: set[str], model: str, tokens: int) -> None:
    with db.scoped(scope) as conn:
        conn.execute(
            "insert into audit_log (user_id, team_ids, mode, question, tools, finding_ids, model, tokens) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s)",
            (scope.user_id, list(scope.team_ids), mode, (question or "")[:2000], json.dumps(tools),
             sorted(finding_ids), model, tokens),
        )
