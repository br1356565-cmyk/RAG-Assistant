"""The drafter's one write: open a pull request in the infra repo for an APPROVED request.

Checked here, whatever any model or caller says:
  1. the request is visible in the caller's scope (row-level security);
  2. a lead approved it (status 'approved', approver recorded);
  3. the files being written are exactly the files that were approved (SHA-256 of their
     canonical JSON, stored at approval);
  4. every path is under teams/<team>/ and no PR was opened before.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

from audit_agent.db import Database, Scope

from .github_write import WriteRefused, _check_writer_config, _default_writer

log = logging.getLogger(__name__)


def files_hash(files: list[dict]) -> str:
    canonical = json.dumps([{"path": f["path"], "content": f["content"]} for f in files],
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def open_infra_pr(db: Database, scope: Scope, request_id: str, writer=None, repo: str | None = None) -> dict:
    repo = repo or os.environ.get("INFRA_REPO", "demo-infra-terraform")
    with db.scoped(scope) as conn:
        row = conn.execute("select * from infra_requests where id = %s", (request_id,)).fetchone()
    if not row:
        raise WriteRefused("infra request not found in scope")
    if row["pr_url"]:
        return {"pr_url": row["pr_url"], "status": "opened"}
    if row["status"] != "approved" or not row["approver"]:
        raise WriteRefused(f"infra request is {row['status']}, not approved")
    files = row["files"] or []
    if not files:
        raise WriteRefused("nothing to write: the approved draft has no files")
    if files_hash(files) != row["approved_sha256"]:
        raise WriteRefused("files changed after approval")
    base_dir = f"teams/{row['team_id']}/"
    if any(not f["path"].startswith(base_dir) or ".." in f["path"].split("/") for f in files):
        raise WriteRefused(f"files must be under {base_dir}")

    if writer is None:
        _check_writer_config()
    w = writer or _default_writer()
    base = w.default_branch(repo)
    branch = f"infra/{row['team_id']}-{request_id[:8]}"
    try:
        w.create_branch(repo, branch, w.branch_sha(repo, base))
        for f in files:
            w.put_file(repo, f["path"], f["content"], branch, f"{row['team_id']}: {f['path'].rsplit('/', 1)[-1]}",
                       w.file_sha(repo, f["path"], base))
        failing = [c["name"] for c in (row["checks"] or []) if not c.get("ok")]
        body = (f"**Request** ({row['requested_by']}): {row['request']}\n\n"
                f"**Decision:** {row['decision']}\n\n{row['reasoning'] or ''}\n\n"
                f"**Checks before review:** "
                + ("all passed" if not failing else "warnings: " + "; ".join(failing)) +
                f"\n\nDrafted by the DevOps audit Terraform drafter; approved by {row['approver']}. "
                "CI must pass fmt/validate/plan before merging.")
        title = f"infra({row['team_id']}): {row['request'][:60]}"
        url = w.open_pull(repo, branch, base, title, body)
    except Exception as exc:
        with db.scoped(scope) as conn:
            conn.execute("update infra_requests set status = 'failed', error = %s, updated_at = now() where id = %s",
                         (str(exc)[:500], request_id))
        raise
    with db.scoped(scope) as conn:
        conn.execute("update infra_requests set status = 'opened', pr_url = %s, updated_at = now() where id = %s",
                     (url, request_id))
    log.info("opened %s for infra request %s", url, request_id)
    return {"pr_url": url, "status": "opened"}
