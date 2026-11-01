"""Run the weekly pipeline on your laptop, in the same order as the Step Functions workflow:
collect -> ingest -> investigate -> summary. Uses the production handlers and ingest code;
only the plumbing differs (local folder instead of S3, a personal GitHub token instead of
the App, direct calls instead of Step Functions).

    python local/run_weekly.py                         # ownership + dependabot
    python local/run_weekly.py --collectors ownership,dependabot,guardduty
    python local/run_weekly.py --max-investigations 5  # fewer model calls
"""
from __future__ import annotations

import argparse
import json
import os
import time
import traceback
import uuid

import common  # noqa: F401  (sets sys.path)
from common import DATA_DIR, env, github_client, guard_local, llm_factory, load_env


def run(*, github, llm_for, app_dsn: str, ingest_dsn: str, collectors: list[str], max_investigations: int,
        aws_session=None, data_dir=DATA_DIR, log=print) -> dict:
    from audit_agent.config import Settings
    from audit_agent.db import Database
    from audit_agent.handlers import collect, investigate, notify
    from audit_agent.handlers.deps import Deps, set_deps
    from audit_agent.ingest import ingest

    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
    out_dir = data_dir / "runs" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    budget = _budget(github)
    if budget is not None:
        log(f"  GitHub budget: {budget['remaining']} of {budget['limit']} requests left this hour")
        if budget["remaining"] < MIN_GITHUB_BUDGET:
            raise SystemExit(f"Only {budget['remaining']} GitHub requests left this hour; the budget resets at "
                             f"{time.strftime('%H:%M', time.localtime(budget['reset']))}. Run again after that.")

    # 1. Collect
    deps = collect.CollectDeps(github=github, s3=None, bucket="local",
                               aws_session=aws_session or (lambda: __import__("boto3").Session()))
    results = []
    for name in collectors:
        t0 = time.monotonic()
        try:
            output = collect.run(name, deps)
            path = out_dir / f"{name}.json"
            path.write_text(json.dumps(output.to_json(), default=str))
            results.append({"collector": name, "status": "succeeded", "key": str(path),
                            "count": len(output.findings), "complete": output.complete})
            log(f"  collected {name}: {len(output.findings)} findings in {time.monotonic() - t0:.1f}s"
                + ("" if output.complete else " (incomplete)"))
        except Exception as exc:
            results.append({"collector": name, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
            log(f"  collector {name} FAILED: {type(exc).__name__}: {exc}")

    # 2. Ingest (as the ingest login)
    ingest_db = Database(dsn=ingest_dsn)
    summary = ingest(ingest_db.conn, run_id, results, lambda key: json.loads(open(key).read()),
                     max_investigations=max_investigations)
    # Local sign-in uses "dev:<team>" in place of Entra group ids.
    with ingest_db.conn.transaction():
        ingest_db.conn.execute("update teams set entra_group_id = 'dev:' || id where entra_group_id is null")
    ingest_db.close()
    log(f"  ingest: {summary['opened']} new, {summary['fixed']} fixed, {summary['reopened']} reopened; "
        f"{len(summary['investigate'])} to investigate")

    # 3. Investigate (as the app login, scoped per finding's team)
    app_db = Database(dsn=app_dsn)
    set_deps(Deps(settings=Settings.from_env(), db=app_db, verifier=None, llm_for=llm_for, github=github))
    investigations = []
    try:
        for i, item in enumerate(summary["investigate"], 1):
            try:
                res = investigate.handler(item, None)
            except Exception as exc:
                traceback.print_exc()
                res = {"status": "failed", "fingerprint": item["fingerprint"], "error": str(exc)}
            investigations.append(res)
            log(f"  investigated {i}/{len(summary['investigate'])} {item['fingerprint']}: {res['status']}")
    finally:
        set_deps(None)
        app_db.close()

    # 4. Summary (what Slack would receive)
    message = notify.format_message({"run_id": run_id, "ingest": summary, "investigations": investigations})
    log("\n" + message)
    calls = getattr(github, "calls", None)
    if calls is not None:
        left = (getattr(github, "limits", {}).get("core") or {}).get("remaining")
        log(f"\nGitHub: {calls} requests this run" + (f", {left} left this hour" if left is not None else ""))
    return {"run_id": run_id, "ingest": summary, "investigations": investigations, "github_calls": calls}


MIN_GITHUB_BUDGET = 300


def _budget(github) -> dict | None:
    if not hasattr(github, "rate_limit"):
        return None
    try:
        return github.rate_limit().get("core")
    except Exception:
        return None


def preflight(github) -> int:
    """Check the token before a real run: budget, and access to what the collectors need."""
    import httpx

    ok = True
    rl = github.rate_limit()
    for name, r in rl.items():
        reset = time.strftime("%H:%M", time.localtime(r["reset"]))
        print(f"  {name:12} {r['remaining']:>6} of {r['limit']} left (resets {reset})")
    checks = [
        ("org repos", f"/orgs/{github.org}/repos", {"per_page": 1}),
        ("org Dependabot alerts", f"/orgs/{github.org}/dependabot/alerts", {"state": "open", "per_page": 1}),
    ]
    for label, path, params in checks:
        try:
            next(iter(github.paginate(path, params)), None)
            print(f"  ok      {label}")
        except httpx.HTTPStatusError as exc:
            ok = False
            code = exc.response.status_code
            hint = {403: "token lacks permission (needs security_events scope, and org owner or security manager)",
                    404: "org not found or not visible to this token"}.get(code, exc.response.text[:120])
            print(f"  FAILED  {label}: HTTP {code}, {hint}")
    print(f"  ({github.calls} requests used by this check)")
    return 0 if ok else 1


def main() -> None:
    guard_local()
    load_env()
    p = argparse.ArgumentParser()
    p.add_argument("--collectors", default=os.environ.get("COLLECTORS", "ownership,dependabot"))
    p.add_argument("--max-investigations", type=int, default=int(os.environ.get("MAX_INVESTIGATIONS", "15")))
    p.add_argument("--check", action="store_true", help="check the GitHub token and rate-limit budget, then exit")
    a = p.parse_args()
    if a.check:
        raise SystemExit(preflight(github_client()))
    collectors = [c.strip() for c in a.collectors.split(",") if c.strip()]
    if "ownership" not in collectors:
        collectors.insert(0, "ownership")
    session = None
    if os.environ.get("AWS_PROFILE"):
        import boto3
        session = lambda: boto3.Session(profile_name=os.environ["AWS_PROFILE"])  # noqa: E731
    run(github=github_client(), llm_for=llm_factory(), app_dsn=env("AUDIT_DB_APP_DSN"),
        ingest_dsn=env("AUDIT_DB_INGEST_DSN"), collectors=collectors,
        max_investigations=a.max_investigations, aws_session=session)


if __name__ == "__main__":
    main()
