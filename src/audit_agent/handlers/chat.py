"""Chat Lambda, served through a Lambda function URL behind CloudFront.

Request:  POST {"question": "...", "session_id": "optional"}
          header x-user-authorization: Bearer <Entra access token>
Response: {"session_id", "answer", "cited": ["F-..."], "status", "as_of"}

The response is returned whole, not streamed: Lambda response streaming is native only
for Node.js runtimes. To stream from Python later, run behind the Lambda Web Adapter.
"""
from __future__ import annotations

import base64
import json
import logging
import uuid

from ..auth import AuthError, bearer_token, resolve_scope
from ..harness import Harness, HarnessConfig
from ..memory import append_turns, load_history, write_audit
from ..prompts import CHAT_SYSTEM, scope_card
from ..tools import ToolContext, tools_for
from ..tools.findings import TeamArg, get_team_overview
from .deps import get_deps

log = logging.getLogger()
log.setLevel(logging.INFO)

MAX_QUESTION = 2000


def handler(event: dict, context) -> dict:
    deps = get_deps()
    try:
        claims = deps.verifier.verify(bearer_token(event.get("headers") or {}))
        scope = resolve_scope(claims, deps.db)
    except AuthError as exc:
        return _resp(exc.status, {"error": str(exc)})

    try:
        body = _json_body(event)
        question = str(body.get("question", "")).strip()
        if not 1 <= len(question) <= MAX_QUESTION:
            raise ValueError(f"question must be 1 to {MAX_QUESTION} characters")
        session_id = str(body.get("session_id") or uuid.uuid4())
        if len(session_id) > 64:
            raise ValueError("session_id too long")
    except (ValueError, json.JSONDecodeError) as exc:
        return _resp(400, {"error": str(exc)})

    deadline = context.get_remaining_time_in_millis() / 1000 - 3 if context else 50.0
    ctx = ToolContext(scope=scope, db=deps.db, github=deps.github, mode="chat")
    overview = get_team_overview(ctx, TeamArg()).data
    messages = [
        {"role": "system", "content": CHAT_SYSTEM.format(
            scope_card=scope_card(claims.get("name", "user"), overview))},
        *load_history(deps.db, scope, session_id),
        {"role": "user", "content": question},
    ]
    cfg = HarnessConfig(mode="chat", model=deps.settings.chat_model, deadline_s=deadline,
                        temperature=deps.settings.chat_temperature)
    result = Harness(deps.llm_for(scope.team_ids), tools_for("chat"), cfg).run(ctx, messages)

    answer = result.text or "I couldn't produce an answer. Please try again."
    if result.status != "error":
        append_turns(deps.db, scope, session_id, question, answer, result.cited)
    write_audit(deps.db, scope, mode="chat", question=question, tools=result.tool_log(),
                finding_ids=result.finding_ids, model=cfg.model, tokens=result.tokens)
    log.info(json.dumps({
        "event": "chat", "user": scope.user_id, "teams": scope.team_ids, "status": result.status,
        "rounds": result.rounds, "tokens": result.tokens, "tools": result.tool_log(),
    }))
    return _resp(200, {"session_id": session_id, "answer": answer, "cited": result.cited,
                       "status": result.status, "as_of": overview.get("as_of")})


def _json_body(event: dict) -> dict:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    body = json.loads(raw)
    if not isinstance(body, dict):
        raise ValueError("body must be a JSON object")
    return body


def _resp(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, default=str)}
