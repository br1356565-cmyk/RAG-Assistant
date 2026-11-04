"""Answer verification for the confidence gate.

A second, separate model call grades whether the chat answer is supported by the evidence
the run actually retrieved. Self-reported confidence from the answering model is poorly
calibrated; an independent check against the evidence is more reliable, and it names what
is missing so the harness can send the agent back to look for it.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from .llm import LLM

log = logging.getLogger(__name__)

MAX_EVIDENCE_CHARS = 12_000

RUBRIC = """You check answers from a DevOps security assistant before users see them.

Rate how well the ANSWER is supported by the EVIDENCE for the QUESTION.
- confidence 0.9-1.0: every factual claim (finding ids, packages, versions, repos, counts, dates)
  appears in the evidence, and the answer addresses the question.
- confidence 0.5-0.8: mostly supported, but something the question asks about was not checked.
- confidence below 0.5: claims are missing from the evidence, contradict it, or the answer does
  not address the question.
- If the question needs no data (a greeting, how to use the assistant), confidence is 1.0.
- An answer that plainly says data is unavailable, when the evidence shows the lookup came back
  empty, is supported.
List in `missing` what the assistant should look up to answer better (at most 3 short items).
Call the `verdict` tool exactly once."""

VERDICT_TOOL = {"type": "function", "function": {
    "name": "verdict",
    "description": "Report how well the answer is supported.",
    "parameters": {"type": "object", "properties": {
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "supported": {"type": "boolean"},
        "missing": {"type": "array", "items": {"type": "string"}, "maxItems": 3},
    }, "required": ["confidence", "supported", "missing"]},
}}


@dataclass
class Verdict:
    confidence: float
    supported: bool
    missing: list[str] = field(default_factory=list)
    tokens: int = 0


class LLMVerifier:
    def __init__(self, llm: LLM, model: str, max_tokens: int = 400):
        self.llm, self.model, self.max_tokens = llm, model, max_tokens

    def __call__(self, question: str, answer: str, evidence: list[str], user: str = "verifier") -> Verdict | None:
        joined = "\n---\n".join(evidence) or "(no tools were called)"
        if len(joined) > MAX_EVIDENCE_CHARS:
            joined = joined[:MAX_EVIDENCE_CHARS] + "\n[evidence truncated]"
        messages = [
            {"role": "system", "content": RUBRIC},
            {"role": "user", "content": f"QUESTION:\n{question}\n\nANSWER:\n{answer}\n\nEVIDENCE:\n{joined}"},
        ]
        try:
            resp = self.llm.complete(model=self.model, messages=messages, tools=[VERDICT_TOOL],
                                     tool_choice={"type": "function", "function": {"name": "verdict"}},
                                     max_tokens=self.max_tokens, user=user, tags=["mode:verify"])
            call = next(c for c in resp.tool_calls if c.name == "verdict")
            data = json.loads(call.arguments)
            conf = min(1.0, max(0.0, float(data["confidence"])))
            missing = [str(m)[:120] for m in (data.get("missing") or [])][:3]
            return Verdict(conf, bool(data.get("supported", conf >= 0.5)), missing,
                           tokens=resp.tokens_in + resp.tokens_out)
        except Exception:  # noqa: BLE001 - a broken verifier must not block answers
            log.warning("verifier failed; answer passes unverified", exc_info=True)
            return None
