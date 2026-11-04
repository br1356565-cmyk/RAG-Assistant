"""Repository evidence for investigations. Every repo is checked against the ownership
table first: a team's investigation can only read that team's repos."""
from __future__ import annotations

from pydantic import Field, field_validator

from .base import Args, ToolContext, ToolError, ToolResult, tool

MAX_FILE_CHARS = 12_000


def _check_repo(ctx: ToolContext, repo: str) -> None:
    if ctx.github is None:
        raise ToolError("Repository access is not available right now.")
    with ctx.db.scoped(ctx.scope) as conn:
        row = conn.execute("select team_id from repo_owners where repo = %s", (repo,)).fetchone()
    if not ctx.scope.is_admin and (not row or row["team_id"] not in ctx.scope.team_ids):
        raise ToolError("That repository is not owned by a team in your scope.")   # name not echoed back


class ReadFileArgs(Args):
    repo: str = Field(pattern=r"^[A-Za-z0-9._-]{1,100}$")
    path: str = Field(max_length=200, description="Path in the default branch, e.g. package.json or .github/CODEOWNERS")

    @field_validator("path")
    @classmethod
    def no_traversal(cls, v: str) -> str:
        if ".." in v.split("/") or v.startswith("/"):
            raise ValueError("relative paths only, no '..'")
        return v


@tool(
    "read_repo_file",
    "Read a file from one of your team's repos (default branch), e.g. a manifest, lockfile or "
    "CODEOWNERS. Large files are truncated.",
    ReadFileArgs, {"investigate", "chat"}, untrusted=True,
)
def read_repo_file(ctx: ToolContext, a: ReadFileArgs) -> ToolResult:
    _check_repo(ctx, a.repo)
    text = ctx.github.read_file(a.repo, a.path)
    if text is None:
        raise ToolError(f"{a.repo}/{a.path} not found.")
    truncated = len(text) > MAX_FILE_CHARS
    return ToolResult(
        {"repo": a.repo, "path": a.path, "truncated": truncated, "content": text[:MAX_FILE_CHARS]},
        sources={f"file:{a.repo}/{a.path}"},
    )


class SearchCodeArgs(Args):
    repo: str = Field(pattern=r"^[A-Za-z0-9._-]{1,100}$")
    query: str = Field(min_length=2, max_length=100, description="Identifier to look for, e.g. an imported function name")


@tool(
    "search_code",
    "Search one of your team's repos for an identifier, e.g. whether the vulnerable function is "
    "imported. An empty result is weak evidence, not proof of non-use.",
    SearchCodeArgs, {"investigate", "chat"}, untrusted=True,
)
def search_code(ctx: ToolContext, a: SearchCodeArgs) -> ToolResult:
    _check_repo(ctx, a.repo)
    hits = ctx.github.search_code(a.repo, a.query, limit=5)
    return ToolResult({"repo": a.repo, "query": a.query, "hits": hits},
                      sources={f"code:{a.repo}:{a.query}"})
