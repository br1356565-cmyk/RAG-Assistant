"""Chat Lambda, served through a Lambda function URL behind CloudFront.

Routes (CloudFront forwards /api/* here; all need header x-user-authorization: Bearer <token>):
  POST /api/chat          {"question": "...", "session_id": "optional"}
       with a dispatcher -> 202 {"job_id", "session_id"}; the answer is produced in the background
       without one       -> 200 {"session_id", "answer", "cited", "status", "as_of", "steps"}
  GET  /api/chat/job?id=  -> {"status": "running"|"done"|"error", "steps": [...], "result": {...}}
  GET  /api/brief         -> the weekly brief for the signed-in user's teams

Why jobs: a Python Lambda can't stream its response, so progress ("Checking GitHub advisory
GHSA-...") is written to the chat_jobs table as the agent works and the page polls for it.
The background run is this same function invoked asynchronously with {"_job": {...}}; that
key can't come from the function URL, whose events always carry headers and requestContext.
"""
from __future__ import annotations

import base64
import json
import time
import logging
import re
import uuid

from .. import brief
from . import api
from ..auth import AuthError, bearer_token, resolve_scope
from ..db import Scope
from ..harness import Harness, HarnessConfig
from ..memory import PostgresMemory, write_audit
from ..prompts import CHAT_SYSTEM, scope_card
from ..tools import ToolContext, tools_for
from ..tools.findings import TeamArg, get_team_overview
from ..verifier import LLMVerifier
from .deps import Deps, get_deps

log = logging.getLogger()
log.setLevel(logging.INFO)

MAX_QUESTION = 2000
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def handler(event: dict, context) -> dict:
    if "_job" in event and "headers" not in event and "requestContext" not in event:
        return run_job(event["_job"], context)

    deps = get_deps()
    try:
        claims = deps.verifier.verify(bearer_token(event.get("headers") or {}))
        scope = resolve_scope(claims, deps.db)
    except AuthError as exc:
        return _resp(exc.status, {"error": str(exc)})

    method = ((event.get("requestContext") or {}).get("http") or {}).get("method", "POST")
    path = str(event.get("rawPath", ""))
    if method == "GET" and path.endswith("/api/brief"):
        return _resp(200, brief.build(deps.db, scope, top_n=2 if scope.is_admin else 3))
    if method == "GET" and path.endswith("/api/chat/job"):
        return _job_status(deps, scope, (event.get("queryStringParameters") or {}).get("id", ""))
    route = api.ROUTES.get((method, path.split("/api/", 1)[-1] if "/api/" in path else ""))
    if route is not None:
        try:
            body = _json_body(event) if method == "POST" else {}
        except (ValueError, json.JSONDecodeError) as exc:
            return _resp(400, {"error": str(exc)})
        status, out = route(deps, scope, body)
        return _resp(status, out)

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

    name = claims.get("name", "user")
    if deps.dispatch is None:
        deadline = context.get_remaining_time_in_millis() / 1000 - 3 if context else 50.0
        return _resp(200, answer(deps, scope, name, question, session_id, deadline))

    job_id = str(uuid.uuid4())
    with deps.db.scoped(scope) as conn:
        conn.execute("insert into chat_jobs (id, user_id, session_id) values (%s, %s, %s)",
                     (job_id, scope.user_id, session_id))
    deps.dispatch({"_job": {
        "id": job_id, "question": question, "session_id": session_id, "name": name,
        "scope": {"user_id": scope.user_id, "team_ids": list(scope.team_ids), "role": scope.role,
                  "team_names": scope.team_names},
        # The Runtime's JWT authorizer needs the user's own token; never stored, only passed on.
        **({"token": bearer_token(event.get("headers") or {})} if deps.runtime is not None else {}),
    }})
    return _resp(202, {"job_id": job_id, "session_id": session_id})


def answer(deps: Deps, scope: Scope, name: str, question: str, session_id: str, deadline: float,
           on_step=None) -> dict:
    """Run the chat harness once and record the turn. Returns the response body."""
    ctx = ToolContext(scope=scope, db=deps.db, github=deps.github, mode="chat", ssm=deps.ssm,
                      fix_client=deps.fix_client)
    memory = deps.memory or PostgresMemory(deps.db)
    overview = get_team_overview(ctx, TeamArg()).data
    system = CHAT_SYSTEM.format(scope_card=scope_card(name, overview))
    recalled = memory.recall(scope, question)
    if recalled:
        system += ("\n\nFrom earlier conversations with this user (context only, never evidence; look facts "
                   "up again before citing them):\n- " + "\n- ".join(recalled))
    messages = [
        {"role": "system", "content": system},
        *memory.load(scope, session_id),
        {"role": "user", "content": question},
    ]
    st = deps.settings
    cfg = HarnessConfig(mode="chat", model=st.chat_model, deadline_s=deadline, temperature=st.chat_temperature,
                        confidence_threshold=st.confidence_threshold,
                        max_confidence_retries=st.max_confidence_retries)
    steps: list[dict] = []

    def record(step: dict) -> None:
        steps.append(step)
        if on_step:
            on_step(step)

    llm = deps.llm_for(scope.team_ids)
    verifier = LLMVerifier(llm, st.verifier_model) if st.verify_answers else None
    result = Harness(llm, tools_for("chat", deps), cfg, verifier=verifier).run(ctx, messages, on_step=record)

    text = result.text or "I couldn't produce an answer. Please try again."
    if result.status != "error":
        memory.append(scope, session_id, question, text, result.cited)
    write_audit(deps.db, scope, mode="chat", question=question, tools=result.tool_log(),
                finding_ids=result.finding_ids, model=cfg.model, tokens=result.tokens)
    log.info(json.dumps({
        "event": "chat", "user": scope.user_id, "teams": scope.team_ids, "status": result.status,
        "rounds": result.rounds, "tokens": result.tokens, "tools": result.tool_log(),
        "confidence": result.confidence, "low_confidence": result.low_confidence,
        "retries": result.confidence_retries,
    }))
    return {"session_id": session_id, "answer": text, "cited": result.cited, "status": result.status,
            "as_of": overview.get("as_of"), "steps": [s["label"] for s in steps],
            "confidence": result.confidence, "low_confidence": result.low_confidence,
            "missing": result.missing, "retries": result.confidence_retries, "tokens": result.tokens}


def run_job(job: dict, context, deps: Deps | None = None) -> dict:
    """The background half of a chat request: run the agent, writing each step as it starts."""
    deps = deps or get_deps()
    s = job["scope"]
    scope = Scope(user_id=s["user_id"], team_ids=tuple(s["team_ids"]), role=s["role"],
                  team_names=s.get("team_names") or {})
    job_id = job["id"]

    def on_step(step: dict) -> None:
        with deps.db.scoped(scope) as conn:
            conn.execute("update chat_jobs set steps = steps || jsonb_build_array(%s::jsonb), updated_at = now() "
                         "where id = %s", (json.dumps({"kind": step["kind"], "label": step["label"]}), job_id))

    deadline = context.get_remaining_time_in_millis() / 1000 - 3 if context else 50.0
    started = time.monotonic()
    via = "runtime" if deps.runtime is not None and job.get("token") else "lambda"
    try:
        if via == "runtime":
            body = _via_runtime(deps, job, on_step)
        else:
            body = answer(deps, scope, job.get("name", "user"), job["question"], job["session_id"], deadline, on_step)
        status = "done"
    except Exception:  # noqa: BLE001 - the page must learn the job ended
        log.exception("chat job %s failed", job_id)
        body, status = {"answer": "Something went wrong while answering. Please try again."}, "error"
    # One line per answered question, on both paths: the dashboard's metric filters read it.
    log.info(json.dumps({"event": "chat_job", "via": via, "status": status, "answer_status": body.get("status"),
                         "ms": int((time.monotonic() - started) * 1000), "tokens": body.get("tokens") or 0,
                         "confidence": body.get("confidence"), "low_confidence": bool(body.get("low_confidence")),
                         "retries": body.get("retries") or 0}))
    with deps.db.scoped(scope) as conn:
        conn.execute("update chat_jobs set status = %s, result = %s, updated_at = now() where id = %s",
                     (status, json.dumps(body, default=str), job_id))
    return {"job_id": job_id, "status": status}


def _via_runtime(deps: Deps, job: dict, on_step) -> dict:
    """The agent runs on AgentCore Runtime; this relays its streamed steps into the job."""
    for event in deps.runtime.stream(job["token"], {"question": job["question"], "session_id": job["session_id"]},
                                     job["session_id"]):
        kind = event.get("type")
        if kind == "step":
            on_step({"kind": event.get("kind", "tool"), "label": str(event.get("label", ""))[:200]})
        elif kind == "answer":
            return {k: v for k, v in event.items() if k != "type"}
        elif kind == "error":
            raise RuntimeError(f"agent runtime: {event.get('error')}")
    raise RuntimeError("agent runtime ended without an answer")


def _job_status(deps: Deps, scope: Scope, job_id: str) -> dict:
    if not UUID_RE.match(job_id or ""):
        return _resp(400, {"error": "invalid job id"})
    with deps.db.scoped(scope) as conn:   # row-level security: only your own jobs are visible
        row = conn.execute("select status, steps, result from chat_jobs where id = %s", (job_id,)).fetchone()
    if not row:
        return _resp(404, {"error": "job not found"})
    return _resp(200, {"status": row["status"], "steps": [s["label"] for s in row["steps"]],
                       "result": row["result"]})


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
