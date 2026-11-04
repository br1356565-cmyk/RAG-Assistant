"""Run the golden questions and score them.

    python evals/run.py                     # replay mode: scripted model steps (the CI gate)
    python evals/run.py --model live        # a real model (local/.env: LLM_BACKEND, GATEWAY_URL/...)
    python evals/run.py --only iso-         # cases whose id starts with iso-
    python evals/run.py --report out.json   # also write the full results

Replay mode tests what this code guarantees, whatever the model does: tool scoping, the
citation check, the confidence gate and its retry cap, proposals instead of writes. Live
mode measures the model on the same questions through the same production code path.

Gate (exit code 1 when missed):
  isolation  100% of cases, both modes: an answer never contains another team's repos or
             finding ids, or admin-only details for a non-admin
  grounding  100% of cases, both modes: every cited id was retrieved in that run and is in scope
  expect     replay 100%; live >= --min-expect (default 0.8)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import sys
import time
from datetime import date, timedelta

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("VERIFY_ANSWERS", "false")

import yaml  # noqa: E402

import world  # noqa: E402
from audit_agent.config import Settings  # noqa: E402
from audit_agent.handlers import chat  # noqa: E402
from audit_agent.handlers.deps import Deps  # noqa: E402
from audit_agent.llm import LLMResponse, ToolCall  # noqa: E402

CITE_RE = re.compile(r"F-[0-9a-f]{16}")


class ReplayLLM:
    """Plays a case's script. Tool steps become tool calls; ECHO answers with everything the
    tools returned (so leaks surface); a forced `verdict` call returns the next scripted score."""

    def __init__(self, script: list[dict], verdicts: list[float]):
        self.script, self.verdicts, self.calls = list(script), list(verdicts), 0

    def complete(self, *, model, messages, tools, tool_choice, max_tokens, user, tags, temperature=None):
        self.calls += 1
        if isinstance(tool_choice, dict) and tool_choice.get("function", {}).get("name") == "verdict":
            score = self.verdicts.pop(0) if self.verdicts else 0.9
            return LLMResponse(text=None, tool_calls=[ToolCall(id=f"v{self.calls}", name="verdict", arguments=json.dumps(
                {"confidence": score, "supported": score >= 0.7, "missing": [] if score >= 0.7 else ["evidence for the claim"]}))],
                tokens_in=50, tokens_out=10)
        if not self.script:
            return LLMResponse(text="I could only find what is shown above.", tokens_in=50, tokens_out=10)
        step = self.script.pop(0)
        if "tool" in step:
            args = {k: _template(v) for k, v in (step.get("args") or {}).items()}
            return LLMResponse(text=None, tool_calls=[ToolCall(id=f"c{self.calls}", name=step["tool"],
                                                               arguments=json.dumps(args))], tokens_in=80, tokens_out=20)
        if step["answer"] == "ECHO":
            seen = [m["content"] for m in messages if m.get("role") == "tool"]
            ids = sorted(set(CITE_RE.findall(" ".join(seen))))
            return LLMResponse(text="Here is what I found:\n" + "\n".join(seen) + "\n" + " ".join(f"[{i}]" for i in ids),
                               tokens_in=80, tokens_out=60)
        return LLMResponse(text=step["answer"], tokens_in=80, tokens_out=30)


def _template(v):
    if isinstance(v, str) and v.startswith("TODAY+"):
        return (date.today() + timedelta(days=int(v[6:]))).isoformat()
    return v


def live_llm():
    sys.path.insert(0, str(HERE.parent / "local"))
    from common import llm_factory, load_env
    load_env()
    return llm_factory()(())


def run_case(case: dict, mode: str, settings: Settings, llm=None) -> dict:
    scope = world.PERSONAS[case["persona"]]
    verify = bool(case.get("verify")) if mode == "replay" else settings.verify_answers
    model = ReplayLLM(case.get("script", []), case.get("verdicts", [])) if mode == "replay" else llm
    st = dataclasses.replace(settings, verify_answers=verify)
    db = world.app_db()
    deps = Deps(settings=st, db=db, verifier=None, llm_for=lambda t: model, github=world.EvalGitHub())
    t0 = time.monotonic()
    try:
        body = chat.answer(deps, scope, "Eval user", case["question"], f"eval-{case['id']}", 50.0)
        error = None
    except Exception as exc:  # noqa: BLE001
        body, error = {}, f"{type(exc).__name__}: {exc}"
    finally:
        db.close()
    audit = world.owner_query("select tools, finding_ids from audit_log where user_id = %s and question = %s "
                              "order by id desc limit 1", (scope.user_id, case["question"]))
    tools_called = [t["name"] for t in (audit[0][0] if audit else [])]
    retrieved = {f"F-{fp}" for fp in (audit[0][1] if audit else [])}
    return score(case, scope, body, tools_called, retrieved, error, int((time.monotonic() - t0) * 1000))


def score(case, scope, body, tools_called, retrieved, error, ms) -> dict:
    text = body.get("answer") or ""
    cited = set(body.get("cited") or [])
    lower = text.lower()
    leaks = sorted(m for m in world.out_of_scope_markers(scope) if m.lower() in lower or m in cited)
    in_scope_ids = {f"F-{fp}" for fp, team, *_rest in world.FINDINGS
                    if scope.is_admin or (team in scope.team_ids and _rest[5] == "team")}
    ungrounded = sorted(c for c in cited if c not in retrieved or c not in in_scope_ids)

    exp, failed = case.get("expect") or {}, []
    for c in exp.get("cite", []):
        if c not in cited:
            failed.append(f"did not cite {c}")
    if exp.get("any") and not any(w.lower() in lower for w in exp["any"]):
        failed.append(f"none of {exp['any']} in the answer")
    for w in exp.get("none", []):
        if w.lower() in lower or w in cited:
            failed.append(f"answer contains '{w}'")
    for t in exp.get("tools", []):
        if t not in tools_called:
            failed.append(f"did not call {t}")
    if "retries" in exp and body.get("retries") != exp["retries"]:
        failed.append(f"retries {body.get('retries')} != {exp['retries']}")
    if "low_confidence" in exp and bool(body.get("low_confidence")) != exp["low_confidence"]:
        failed.append(f"low_confidence {body.get('low_confidence')} != {exp['low_confidence']}")
    if case.get("after_sql"):
        got = world.owner_query(case["after_sql"])[0][0]
        if got != case["after_equals"]:
            failed.append(f"after: {got} != {case['after_equals']}")
    if error:
        failed.append(error)
    return {"id": case["id"], "persona": case["persona"], "isolation": not leaks, "leaks": leaks,
            "grounded": not ungrounded, "ungrounded": ungrounded, "expect": not failed, "failed": failed,
            "confidence": body.get("confidence"), "retries": body.get("retries"), "ms": ms,
            "tools": tools_called, "answer": text[:600]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["replay", "live"], default="replay")
    ap.add_argument("--only", default="")
    ap.add_argument("--min-expect", type=float, default=0.8)
    ap.add_argument("--report")
    ap.add_argument("--no-build", action="store_true", help="reuse the eval database")
    a = ap.parse_args(argv)

    cases = [c for c in yaml.safe_load((HERE / "golden.yml").read_text())["cases"] if c["id"].startswith(a.only)]
    if not a.no_build:
        world.build()
    settings = Settings.from_env()
    llm = live_llm() if a.model == "live" else None
    results = [run_case(c, a.model, settings, llm) for c in cases]

    n = len(results)
    iso = sum(r["isolation"] for r in results) / n
    grd = sum(r["grounded"] for r in results) / n
    exp = sum(r["expect"] for r in results) / n
    need_exp = 1.0 if a.model == "replay" else a.min_expect
    for r in results:
        mark = "ok " if r["isolation"] and r["grounded"] and r["expect"] else "FAIL"
        detail = "; ".join([*(f"LEAK {x}" for x in r["leaks"]), *(f"UNGROUNDED {x}" for x in r["ungrounded"]), *r["failed"]])
        print(f"{mark} {r['id']:<28} {r['persona']:<12} {r['ms']:>6} ms  {detail}")
    print(f"\n{a.model}: {n} cases · isolation {iso:.0%} · grounding {grd:.0%} · expectations {exp:.0%} "
          f"(gate: 100% / 100% / {need_exp:.0%})")
    if a.report:
        pathlib.Path(a.report).write_text(json.dumps({"mode": a.model, "isolation": iso, "grounding": grd,
                                                      "expect": exp, "results": results}, indent=2))
    ok = iso == 1.0 and grd == 1.0 and exp >= need_exp
    print("GATE PASSED" if ok else "GATE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
