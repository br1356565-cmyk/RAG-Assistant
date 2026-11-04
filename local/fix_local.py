"""The fix agent in-process for the local prototype (on AWS it runs on AgentCore Runtime and
is reached over A2A). Same graph, same approval checks, same content-hash binding.

Writes: with FIX_GITHUB_TOKEN set (a token that can push branches and open PRs on your demo
repos) approved fixes become real pull requests. Without it they are written to
local/out/fix-prs/ as a dry run, so the whole flow works with read-only GitHub access."""
from __future__ import annotations

import os
import pathlib
import threading

from common import ROOT, env

OUT = ROOT / "local" / "out" / "fix-prs"
MAX_BYTES = 200_000


class DryRunWriter:
    """Records what would be pushed instead of calling GitHub."""

    def __init__(self, out: pathlib.Path = OUT):
        self.out = out

    def default_branch(self, repo):
        return "main"

    def branch_sha(self, repo, branch):
        return "dry-run"

    def file_sha(self, repo, path, ref):
        return None

    def create_branch(self, repo, name, sha):
        self._branch = name

    def put_file(self, repo, path, content, branch, message, sha):
        target = self.out / repo / branch.replace("/", "_") / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self._written = target

    def open_pull(self, repo, head, base, title, body):
        (self._written.parent / "PULL_REQUEST.md").write_text(f"# {title}\n\n{head} -> {base}\n\n{body}\n")
        return self._written.parent.resolve().as_uri()


class LockedFixClient:
    """The local server handles chat jobs in threads; the fix service has one DB connection."""

    def __init__(self, client):
        self._client, self._lock = client, threading.Lock()

    def request_fix(self, scope, fingerprint):
        with self._lock:
            return self._client.request_fix(scope, fingerprint)

    def decide(self, scope, fix_request_id, decision):
        with self._lock:
            return self._client.decide(scope, fix_request_id, decision)


def build_fix_client(github, llm=None, model: str = "", out: pathlib.Path | None = None):
    from langgraph.checkpoint.postgres import PostgresSaver

    from audit_agent.db import Database
    from audit_agent.fix_client import LocalFixClient
    from audit_agent.github import GitHubToken, GitHubWriter
    from fix_agent.github_write import open_fix_pr
    from fix_agent.graph import FixDeps
    from fix_agent.service import FixService

    db = Database(dsn=env("AUDIT_DB_APP_DSN"))
    token = os.environ.get("FIX_GITHUB_TOKEN", "")
    writer = (GitHubWriter(GitHubToken(env("GITHUB_ORG", "forbesadvisor"), token,
                                       owner_type=env("GITHUB_OWNER_TYPE", "org"))) if token else DryRunWriter(out or OUT))

    def read_file(scope, repo, path):
        # The repo comes from the finding row read under the worker's team scope, so it is owned.
        text = github.read_file(repo, path)
        if text is None:
            raise RuntimeError(f"{repo}/{path} not found")
        return {"content": text[:MAX_BYTES], "truncated": len(text) > MAX_BYTES}

    deps = FixDeps(db=db, read_file=read_file, open_pr=lambda scope, fid: open_fix_pr(db, scope, fid, writer=writer),
                   llm=llm, model=model)
    saver = PostgresSaver(Database(dsn=env("AUDIT_DB_APP_DSN")).conn)
    return LockedFixClient(LocalFixClient(FixService(deps, saver))), ("github" if token else f"dry run to {out or OUT}")
