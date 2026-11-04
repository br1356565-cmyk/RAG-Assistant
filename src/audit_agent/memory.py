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
    """The latest investigation for this exact evidence and prompt, unless a person rejected
    or disputed it (then it is done again)."""
    with db.scoped(scope) as conn:
        row = conn.execute(
            "select explanation, review_state(id, needs_review) as state from investigations "
            "where fingerprint = %s and evidence_hash = %s and prompt_version = %s "
            "order by created_at desc, id desc limit 1", (fingerprint, ev_hash, prompt_version),
        ).fetchone()
    if not row or row["state"] in ("rejected", "disputed"):
        return None
    return row["explanation"]


def save_investigation(db: Database, scope: Scope, fingerprint: str, team_id: str, ev_hash: str,
                       prompt_version: str, model: str, explanation: dict, *, needs_review: bool = False,
                       confidence: float | None = None, run_id: str | None = None) -> int:
    with db.scoped(scope) as conn:
        return conn.execute(
            "insert into investigations (fingerprint, team_id, evidence_hash, prompt_version, model, explanation, "
            "needs_review, confidence, run_id) values (%s, %s, %s, %s, %s, %s, %s, %s, %s) returning id",
            (fingerprint, team_id, ev_hash, prompt_version, model, json.dumps(explanation), needs_review,
             confidence, run_id),
        ).fetchone()["id"]


def write_audit(db: Database, scope: Scope, *, mode: str, question: str | None, tools: list[dict],
                finding_ids: set[str], model: str, tokens: int) -> None:
    with db.scoped(scope) as conn:
        conn.execute(
            "insert into audit_log (user_id, team_ids, mode, question, tools, finding_ids, model, tokens) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s)",
            (scope.user_id, list(scope.team_ids), mode, (question or "")[:2000], json.dumps(tools),
             sorted(finding_ids), model, tokens),
        )


# ── Conversation memory backends ─────────────────────────────────────────────
class PostgresMemory:
    """Short-term memory in the session_turns table (local, tests, and the Lambda path)."""

    def __init__(self, db: Database):
        self.db = db

    def load(self, scope: Scope, session_id: str) -> list[dict]:
        return load_history(self.db, scope, session_id)

    def append(self, scope: Scope, session_id: str, question: str, answer: str, cited: list[str]) -> None:
        append_turns(self.db, scope, session_id, question, answer, cited)

    def recall(self, scope: Scope, query: str) -> list[str]:
        return []


class AgentCoreMemory:
    """AgentCore Memory: short-term events per (user, session), plus long-term records that
    the memory's strategies extract (conversation summaries, user preferences).

    Isolation: actorId is always the verified user's id, and long-term retrieval is limited
    to the namespace path /users/<that id>/, so one user's memory never reaches another.
    Remembered text is context for the model, never evidence: citations must still be
    fetched in the current run (the harness enforces that)."""

    def __init__(self, memory_id: str, client=None, region: str | None = None):
        if client is None:
            import boto3
            client = boto3.client("bedrock-agentcore", region_name=region)
        self.memory_id, self.client = memory_id, client

    @staticmethod
    def _actor(scope: Scope) -> str:
        return scope.user_id.replace("/", "_")

    def load(self, scope: Scope, session_id: str) -> list[dict]:
        resp = self.client.list_events(memoryId=self.memory_id, actorId=self._actor(scope), sessionId=session_id,
                                       includePayloads=True, maxResults=HISTORY_TURNS * 2)
        events = sorted(resp.get("events", []), key=lambda e: str(e.get("eventTimestamp")))
        out: list[dict] = []
        for e in events:
            for item in e.get("payload", []):
                conv = item.get("conversational") or {}
                role = {"USER": "user", "ASSISTANT": "assistant"}.get(conv.get("role"))
                text = (conv.get("content") or {}).get("text")
                if role and text:
                    out.append({"role": role, "content": text})
        return out[-HISTORY_TURNS:]

    def append(self, scope: Scope, session_id: str, question: str, answer: str, cited: list[str]) -> None:
        from datetime import datetime, timezone
        self.client.create_event(
            memoryId=self.memory_id, actorId=self._actor(scope), sessionId=session_id,
            eventTimestamp=datetime.now(timezone.utc),
            payload=[{"conversational": {"role": "USER", "content": {"text": question[:MAX_STORED_CHARS]}}},
                     {"conversational": {"role": "ASSISTANT", "content": {"text": answer[:MAX_STORED_CHARS]}}}])

    def recall(self, scope: Scope, query: str, top_k: int = 3) -> list[str]:
        try:
            resp = self.client.retrieve_memory_records(
                memoryId=self.memory_id, namespacePath=f"/users/{self._actor(scope)}/",
                searchCriteria={"searchQuery": query[:500], "topK": top_k})
        except Exception:  # noqa: BLE001 - long-term memory is a nice-to-have, never a blocker
            return []
        return [str((r.get("content") or {}).get("text", ""))[:500]
                for r in resp.get("memoryRecordSummaries", []) if (r.get("content") or {}).get("text")]
