"""The one write action: open a pull request for an APPROVED fix request.

Checks, in this order, all enforced here regardless of what any model or caller says:
  1. the request is visible in the caller's scope (row-level security);
  2. a team lead approved it (status 'approved', approver recorded);
  3. the content being written is exactly the content that was approved (SHA-256);
  4. it was not opened before.
AgentCore Policy additionally allows this tool only for the fix agent's IAM role.
"""
from __future__ import annotations

import hashlib
import logging
import os
from functools import lru_cache

from audit_agent.db import Database, Scope

log = logging.getLogger(__name__)


class WriteRefused(Exception):
    pass


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


FIX_APP_VARS = ("FIX_GITHUB_APP_ID", "FIX_GITHUB_INSTALLATION_ID", "FIX_GITHUB_PRIVATE_KEY_SECRET")


def _check_writer_config() -> None:
    missing = [v for v in FIX_APP_VARS if not os.environ.get(v)]
    if missing:
        raise WriteRefused(
            "The fix-bot GitHub App is not set up, so no pull request can be opened. Set "
            "fix_github_app_id and fix_github_installation_id in Terraform and store the App's private "
            "key (DEPLOY-DEMO.md step 6b.4), then draft the fix again.")


@lru_cache(maxsize=1)
def _default_writer():
    from audit_agent.config import Settings, load_secret
    from audit_agent.github import GitHubApp, GitHubWriter

    s = Settings.from_env()
    app = GitHubApp(s.github_org, os.environ["FIX_GITHUB_APP_ID"], os.environ["FIX_GITHUB_INSTALLATION_ID"],
                    load_secret(os.environ["FIX_GITHUB_PRIVATE_KEY_SECRET"], s.aws_region),
                    owner_type=s.github_owner_type)
    return GitHubWriter(app)


def open_fix_pr(db: Database, scope: Scope, fix_request_id: str, claims: dict | None = None, writer=None) -> dict:
    with db.scoped(scope) as conn:
        row = conn.execute("select * from fix_requests where id = %s", (fix_request_id,)).fetchone()
    if not row:
        raise WriteRefused("fix request not found in scope")
    if row["pr_url"]:
        return {"pr_url": row["pr_url"], "status": "opened"}
    if row["status"] != "approved" or not row["approver"]:
        raise WriteRefused(f"fix request is {row['status']}, not approved")
    if not row["new_content"] or content_hash(row["new_content"]) != row["approved_sha256"]:
        raise WriteRefused("content changed after approval")

    if writer is None:
        _check_writer_config()
    w = writer or _default_writer()
    base = w.default_branch(row["repo"])
    branch = f"audit-fix/{row['fingerprint'][:8]}-{fix_request_id[:8]}"
    try:
        w.create_branch(row["repo"], branch, w.branch_sha(row["repo"], base))
        w.put_file(row["repo"], row["manifest_path"], row["new_content"], branch,
                   f"Security fix for F-{row['fingerprint']}", w.file_sha(row["repo"], row["manifest_path"], base))
        body = (f"{row['rationale'] or ''}\n\nFinding: F-{row['fingerprint']}\n"
                f"Drafted by the DevOps audit fix agent; approved by {row['approver']}.\n\n"
                "Please let CI regenerate or verify the lockfile before merging.")
        url = w.open_pull(row["repo"], branch, base, f"Security: fix F-{row['fingerprint'][:8]}", body)
    except Exception as exc:
        with db.scoped(scope) as conn:
            conn.execute("update fix_requests set status = 'failed', error = %s, updated_at = now() where id = %s",
                         (str(exc)[:500], fix_request_id))
        raise
    with db.scoped(scope) as conn:
        conn.execute("update fix_requests set status = 'opened', pr_url = %s, updated_at = now() where id = %s",
                     (url, fix_request_id))
    log.info("opened %s for fix request %s", url, fix_request_id)
    return {"pr_url": url, "status": "opened"}
