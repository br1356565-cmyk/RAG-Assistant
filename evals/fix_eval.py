"""Fix agent eval: deterministic manifest edits on tricky inputs, then the full flow (draft ->
lead approval -> PR) through the real LangGraph graph and Postgres checkpointer on the eval
world. No model is needed: the edit is code; the model only writes the PR description.

    python evals/fix_eval.py            # exit 1 if any case fails
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "local"))

import world  # noqa: E402
from fix_agent.manifest import ManifestError, bump, manifest_for  # noqa: E402

PKG = lambda deps, section="dependencies": json.dumps({"name": "x", section: deps}, indent=2) + "\n"  # noqa: E731

# (name, path, content, package, target, expected new spec | "error:<substring>")
EDIT_CASES = [
    ("caret kept", "package.json", PKG({"a": "^1.2.0"}), "a", "1.2.5", "^1.2.5"),
    ("tilde kept", "package.json", PKG({"a": "~1.2.0"}), "a", "1.2.5", "~1.2.5"),
    ("exact pin", "package.json", PKG({"a": "1.2.0"}), "a", "1.2.5", "1.2.5"),
    ("dev dependency", "package.json", PKG({"a": "^1.0.0"}, "devDependencies"), "a", "1.0.9", "^1.0.9"),
    ("only that package", "package.json", PKG({"a-b": "^1.0.0", "a": "^1.0.0"}), "a", "1.0.3", "^1.0.3"),
    ("already fixed", "package.json", PKG({"a": "^2.0.0"}), "a", "1.9.0", "error:already"),
    ("git url refused", "package.json", PKG({"a": "github:x/a#v1"}), "a", "1.0.0", "error:can't be bumped"),
    ("range refused", "package.json", PKG({"a": ">=1 <2"}), "a", "1.5.0", "error:can't be bumped"),
    ("transitive refused", "package.json", PKG({"b": "^1.0.0"}), "a", "1.0.0", "error:not a direct dependency"),
    ("pip pin", "requirements.txt", "a==1.0\nb==2.0\n", "a", "1.0.4", "a==1.0.4"),
    ("pip extras + comment", "requirements.txt", "Requests[socks]>=2.25.0  # http\n", "requests", "2.32.3",
     "Requests[socks]==2.32.3  # http"),
    ("pip name normalisation", "requirements-dev.txt", "Py_Yaml==5.0\n", "py-yaml", "5.4", "Py_Yaml==5.4"),
    ("pip upper bound refused", "requirements.txt", "a<2\n", "a", "2.1", "error:can't be bumped"),
    ("unsupported file", "go.mod", "module x\n", "a", "1", "error:support package.json"),
]

LOCKFILES = [("package-lock.json", "package.json"), ("web/yarn.lock", "web/package.json"),
             ("pnpm-lock.yaml", "package.json"), ("requirements.txt", "requirements.txt")]


def edit_cases() -> list[tuple[str, bool, str]]:
    out = []
    for name, path, content, pkg, target, want in EDIT_CASES:
        try:
            e = bump(path, content, pkg, target)
            changed = [l for l in e.diff.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---"))]
            ok = not want.startswith("error:") and e.new_spec == want and len(changed) == 2
            out.append((name, ok, f"{e.old_spec} -> {e.new_spec}, {len(changed)} changed lines"))
        except ManifestError as exc:
            ok = want.startswith("error:") and want[6:] in str(exc)
            out.append((name, ok, f"refused: {exc}"))
    for lock, manifest in LOCKFILES:
        got = manifest_for(lock)
        out.append((f"lockfile {lock}", got == manifest, got))
    return out


def flow_cases() -> list[tuple[str, bool, str]]:
    """Draft -> lead approves -> PR, for each Dependabot finding in the world."""
    import os

    from audit_agent.handlers import api
    from audit_agent.handlers.deps import Deps
    from audit_agent.config import Settings
    from fix_local import build_fix_client

    world.build()
    os.environ["AUDIT_DB_APP_DSN"] = f"host={world.HOST} port={world.PORT} user=audit_app_login dbname={world.DBNAME}"
    os.environ.pop("FIX_GITHUB_TOKEN", None)
    out_dir = pathlib.Path(tempfile.mkdtemp(prefix="fix-eval-"))
    client, _ = build_fix_client(world.EvalGitHub(), out=out_dir)
    db = world.app_db()
    deps = Deps(settings=Settings.from_env(), db=db, verifier=None, llm_for=lambda t: None,
                github=world.EvalGitHub(), fix_client=client)
    lead = {"growth": world.PERSONAS["growth_lead"],
            "uk": world.Scope(user_id="eval-uk-lead", team_ids=("uk_engineering",), role="team_lead")}
    expected = {  # finding -> (persona, lead, expected change or error substring)
        "a100000000000001": ("growth", "growth", "^2.3.1 -> ^2.3.4"),
        "a100000000000002": ("growth", "growth", "~1.0.2 -> ~1.0.5"),
        "b100000000000001": ("uk", "uk", "yaml-tiny==0.9.0 -> yaml-tiny==0.9.3"),
        "b100000000000002": ("uk", "uk", "error:could not read"),
    }
    results = []
    try:
        for fp, (persona, lead_key, want) in expected.items():
            scope = world.PERSONAS[persona]
            d = client.request_fix(scope, fp)
            if want.startswith("error:"):
                results.append((f"flow F-{fp[:6]}… refuses", d["status"] == "failed" and want[6:] in d.get("error", ""),
                                d.get("error", d["status"])))
                continue
            ok = d["status"] == "awaiting_approval" and d["change"] == want
            results.append((f"flow F-{fp[:6]}… draft", ok, d.get("change") or d.get("error", "")))
            status, _ = api.decide_fix(deps, scope, {"fix_request_id": d["fix_request_id"], "decision": "approved"})
            results.append((f"flow F-{fp[:6]}… member can't approve", status == 403, str(status)))
            status, body = api.decide_fix(deps, lead[lead_key], {"fix_request_id": d["fix_request_id"], "decision": "approved"})
            ok = status == 200 and body.get("status") == "opened"
            from urllib.parse import urlparse
            pr_dir = pathlib.Path(urlparse(body.get("pr_url", "file:///nowhere")).path)
            written = pr_dir / pathlib.Path(d["manifest"]).name
            content_ok = written.exists() and want.split(" -> ")[1] in written.read_text()
            results.append((f"flow F-{fp[:6]}… approved -> PR", ok and content_ok, body.get("pr_url") or str(body)))
        # someone else's team: the uk member cannot draft a fix for a growth finding
        try:
            client.request_fix(world.PERSONAS["uk"], "a100000000000001")
            results.append(("cross-team draft refused", False, "drafted"))
        except Exception as exc:  # noqa: BLE001
            results.append(("cross-team draft refused", "scope" in str(exc), str(exc)))
    finally:
        db.close()
    return results


def main() -> int:
    rows = edit_cases() + flow_cases()
    for name, ok, detail in rows:
        print(f"{'ok ' if ok else 'FAIL'} {name:<34} {detail}")
    passed = sum(ok for _, ok, _ in rows)
    print(f"\nfix agent: {passed}/{len(rows)} passed")
    print("GATE PASSED" if passed == len(rows) else "GATE FAILED")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
