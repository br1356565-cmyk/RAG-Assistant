"""Org-wide SAST: clone every repo the GitHub App can read and run Semgrep on it.

Runs as a weekly Fargate task in the official semgrep/semgrep image (Terraform passes this
file in an environment variable and runs it; nothing to build). Needs: git, semgrep, and
`pip install boto3 PyJWT cryptography` (done by the task command).

Output (S3, DATA_BUCKET):
  runs/<RUN_ID>/sast-raw/<repo>.json      {"repo", "results": [...]}   one per scanned repo
  runs/<RUN_ID>/sast-raw/_manifest.json   {"scanned": [...], "failed": {...}, "config", ...}
The `sast` collector turns these into findings. Code is never stored: each result keeps the
rule, path, line, message and a hash of the matched lines (a stable identity across runs
that survives the code moving), not the code itself, so a hard-coded secret Semgrep finds is
not copied anywhere.

Env: RUN_ID, DATA_BUCKET, AWS_REGION, GITHUB_APP_ID, GITHUB_INSTALLATION_ID,
     GITHUB_PRIVATE_KEY_SECRET, SEMGREP_CONFIG (default p/default), SCAN_CONCURRENCY (4),
     SCAN_MAX_REPOS (0 = all), SCAN_SKIP_FORKS (true), SCAN_REPO_TIMEOUT_S (900)
"""
from __future__ import annotations

import base64
import concurrent.futures as cf
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
SAFE_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def log(event: str, **kw) -> None:
    print(json.dumps({"event": event, **kw}), flush=True)


class GitHub:
    """GitHub App installation token, refreshed before it expires (tokens last 1 hour)."""

    def __init__(self, app_id: str, installation_id: str, private_key: str):
        self.app_id, self.installation_id, self.key = app_id, installation_id, private_key
        self._token, self._expires = "", 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if time.time() > self._expires - 600:
                import jwt  # PyJWT, installed by the task command

                now = int(time.time())
                app_jwt = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, self.key, algorithm="RS256")
                out = self._call("POST", f"/app/installations/{self.installation_id}/access_tokens", app_jwt)
                self._token, self._expires = out["token"], time.time() + 3300
            return self._token

    def _call(self, method: str, path: str, bearer: str | None = None):
        req = urllib.request.Request(API + path, method=method, headers={
            "Authorization": f"Bearer {bearer or self.token()}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "devops-audit-sast"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")

    def repos(self) -> list[dict]:
        out, page = [], 1
        while True:
            data = self._call("GET", f"/installation/repositories?per_page=100&page={page}")
            out += data.get("repositories") or []
            if len(data.get("repositories") or []) < 100:
                return out
            page += 1


def snippet_hash(root: pathlib.Path, path: str, start: int, end: int) -> str:
    """Hash of the matched lines, whitespace-normalized: same code, same identity."""
    try:
        lines = (root / path).read_text(errors="replace").splitlines()[max(start - 1, 0):max(end, start)]
    except OSError:
        return ""
    norm = "\n".join(" ".join(x.split()) for x in lines)
    return hashlib.sha256(norm.encode()).hexdigest()[:12]


def slim(result: dict, root: pathlib.Path) -> dict:
    extra = result.get("extra") or {}
    meta = extra.get("metadata") or {}
    start, end = (result.get("start") or {}).get("line", 0), (result.get("end") or {}).get("line", 0)
    return {
        "check_id": result.get("check_id"), "path": result.get("path"), "line": start, "end_line": end,
        "severity": extra.get("severity"), "message": (extra.get("message") or "")[:500],
        "snippet_sha": snippet_hash(root, result.get("path") or "", start, end),
        "cwe": meta.get("cwe"), "owasp": meta.get("owasp"), "confidence": meta.get("confidence"),
        "impact": meta.get("impact"), "category": meta.get("category"), "references": (meta.get("references") or [])[:3],
    }


def scan_repo(gh: GitHub, repo: dict, config: str, timeout_s: int) -> dict:
    name, full = repo["name"], repo["full_name"]
    work = pathlib.Path(tempfile.mkdtemp(prefix="sast-"))
    try:
        basic = base64.b64encode(f"x-access-token:{gh.token()}".encode()).decode()
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "1",
               # the token travels in an env-provided header, never in argv or the clone URL
               "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
               "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", f"https://github.com/{full}.git", str(work / "src")],
                       env=env, check=True, timeout=300, capture_output=True)
        proc = subprocess.run(
            ["semgrep", "scan", "--config", config, "--json", "--metrics=off", "--quiet", "--disable-version-check",
             "--timeout", "30", "--max-target-bytes", "1000000", "--jobs", "2", str(work / "src")],
            timeout=timeout_s, capture_output=True, text=True, cwd=str(work / "src"))
        if proc.returncode not in (0, 1):            # 1 = findings found
            raise RuntimeError(f"semgrep exit {proc.returncode}: {proc.stderr[-300:]}")
        data = json.loads(proc.stdout or "{}")
        root = work / "src"
        results = []
        for r in data.get("results") or []:
            # paths are reported relative to cwd or absolute depending on version
            p = str(r.get("path") or "")
            if p.startswith(str(root)):
                r["path"] = p[len(str(root)) + 1:]
            results.append(slim(r, root))
        return {"repo": name, "results": results, "errors": len(data.get("errors") or [])}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    import boto3

    run_id, bucket = os.environ["RUN_ID"], os.environ["DATA_BUCKET"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    config = os.environ.get("SEMGREP_CONFIG", "p/default")
    workers = max(1, int(os.environ.get("SCAN_CONCURRENCY", "4")))
    limit = int(os.environ.get("SCAN_MAX_REPOS", "0"))
    timeout_s = int(os.environ.get("SCAN_REPO_TIMEOUT_S", "900"))
    skip_forks = os.environ.get("SCAN_SKIP_FORKS", "true") == "true"
    s3 = boto3.client("s3", region_name=region)
    key = boto3.client("secretsmanager", region_name=region).get_secret_value(
        SecretId=os.environ["GITHUB_PRIVATE_KEY_SECRET"])["SecretString"]
    gh = GitHub(os.environ["GITHUB_APP_ID"], os.environ["GITHUB_INSTALLATION_ID"], key)

    repos = [r for r in gh.repos() if not r.get("archived") and not r.get("disabled") and r.get("size", 1) > 0
             and not (skip_forks and r.get("fork")) and SAFE_REPO.fullmatch(r.get("name") or "")]
    repos.sort(key=lambda r: r["name"])
    if limit:
        repos = repos[:limit]
    log("sast_start", run_id=run_id, repos=len(repos), config=config)
    prefix = f"runs/{run_id}/sast-raw"
    scanned, failed = [], {}
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(scan_repo, gh, r, config, timeout_s): r["name"] for r in repos}
        for fut in cf.as_completed(futs):
            name = futs[fut]
            try:
                out = fut.result()
            except (subprocess.SubprocessError, RuntimeError, OSError, ValueError, urllib.error.URLError) as exc:
                msg = exc.stderr.decode(errors="replace")[-200:] if isinstance(exc, subprocess.CalledProcessError) \
                    and exc.stderr else str(exc)[:200]
                failed[name] = msg.replace(gh._token, "***") if gh._token else msg
                log("sast_repo_failed", repo=name, error=failed[name])
                continue
            s3.put_object(Bucket=bucket, Key=f"{prefix}/{name}.json", Body=json.dumps(out).encode(),
                          ContentType="application/json")
            scanned.append(name)
            log("sast_repo", repo=name, results=len(out["results"]))
    manifest = {"run_id": run_id, "config": config, "scanned": sorted(scanned), "failed": failed,
                "seconds": round(time.time() - started)}
    s3.put_object(Bucket=bucket, Key=f"{prefix}/_manifest.json", Body=json.dumps(manifest).encode(),
                  ContentType="application/json")
    log("sast_done", scanned=len(scanned), failed=len(failed), seconds=manifest["seconds"])
    return 0 if scanned or not repos else 1


if __name__ == "__main__":
    sys.exit(main())
