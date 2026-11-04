"""Investigation Lambda, run by a Step Functions Map state after each weekly ingest.

Input (one Map item):  {"fingerprint": "F-0123456789abcdef", "team_id": "growth_engineering", "run_id": "..."}
Output:                {"status": "investigated" | "cached" | "skipped" | "not_found" | "failed", ...}

Confidence gate: a low-confidence submission is sent back for more evidence (capped
retries); if it is still low, it is saved with needs_review and waits for a team lead
before it appears in the brief.

The worker's scope is the finding's team only, so its tools and inserts are confined to
that team by the same row-level security as user requests.
"""
from __future__ import annotations

import json
import logging

from ..db import Scope
from ..harness import Harness, HarnessConfig
from ..memory import cached_investigation, evidence_hash, save_investigation, write_audit
from ..prompts import INVESTIGATE_SYSTEM, PROMPT_VERSION, investigate_task
from ..tools import ToolContext, ToolError, tools_for
from ..tools.base import parse_ref, ref
from ..tools.findings import FindingArg, get_finding, load_finding
from .deps import get_deps

log = logging.getLogger()
log.setLevel(logging.INFO)

WORKER = "worker:investigate"


def handler(event: dict, context) -> dict:
    deps = get_deps()
    fp = parse_ref(str(event["fingerprint"]))
    team = str(event["team_id"])
    scope = Scope(user_id=WORKER, team_ids=(team,), role="worker")
    ctx = ToolContext(scope=scope, db=deps.db, github=deps.github, mode="investigate")

    try:
        finding = load_finding(ctx, fp)["finding"]
    except ToolError:
        return {"status": "not_found", "fingerprint": ref(fp)}
    if finding["status"] != "open":
        return {"status": "skipped", "fingerprint": ref(fp), "reason": "not open"}

    ev_hash = evidence_hash(finding)
    if cached_investigation(deps.db, scope, fp, ev_hash, PROMPT_VERSION):
        return {"status": "cached", "fingerprint": ref(fp)}

    # The finding itself is given up front and counts as retrieved evidence.
    view = get_finding(ctx, FindingArg(id=ref(fp)))
    ctx.retrieved_findings |= view.finding_ids
    ctx.retrieved_sources |= view.sources

    deadline = context.get_remaining_time_in_millis() / 1000 - 5 if context else 120.0
    st = deps.settings
    cfg = HarnessConfig(mode="investigate", model=st.batch_model, max_rounds=10,
                        max_tokens_total=50_000, max_output_tokens=1_000, deadline_s=deadline,
                        temperature=st.batch_temperature, confidence_threshold=st.confidence_threshold,
                        max_confidence_retries=st.max_confidence_retries)
    messages = [{"role": "system", "content": INVESTIGATE_SYSTEM},
                {"role": "user", "content": investigate_task(view.data)}]
    result = Harness(deps.llm_for((team,)), tools_for("investigate", deps), cfg).run(ctx, messages)

    write_audit(deps.db, scope, mode="investigate", question=ref(fp), tools=result.tool_log(),
                finding_ids=result.finding_ids, model=cfg.model, tokens=result.tokens)
    log.info(json.dumps({"event": "investigate", "finding": ref(fp), "team": team, "status": result.status,
                         "rounds": result.rounds, "tokens": result.tokens, "tools": result.tool_log(),
                         "confidence": result.confidence, "low_confidence": result.low_confidence,
                         "retries": result.confidence_retries}))

    if result.status != "submitted":
        return {"status": "failed", "fingerprint": ref(fp), "reason": result.status}
    save_investigation(deps.db, scope, fp, team, ev_hash, PROMPT_VERSION, cfg.model, result.data,
                       needs_review=result.low_confidence, confidence=result.confidence,
                       run_id=event.get("run_id"))
    return {"status": "investigated", "fingerprint": ref(fp), "confidence": result.data["confidence"],
            "needs_review": result.low_confidence, "retries": result.confidence_retries}
