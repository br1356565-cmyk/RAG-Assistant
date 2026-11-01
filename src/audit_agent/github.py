"""Minimal GitHub client: org listings, Dependabot alerts, advisories, file reads, code search.

Rate limits (GitHub docs): 5,000 requests/hour for a personal token, shared by everything
acting as that user; a GitHub App installation gets 5,000/hour plus 50 per repo above 20,
up to 12,500 (15,000 on Enterprise Cloud). Code search is 10 requests/minute. Secondary
limits: 900 points/minute and 100 concurrent requests.

This client:
  * sends requests one at a time (no concurrency burst)
  * waits and retries when GitHub says so (retry-after, or a reset within max_wait),
    and fails fast with a clear message when the wait would be too long
  * spaces code-search calls at least 6.5 s apart (under 10/minute)
  * counts its own requests and remembers the latest x-ratelimit-* headers per resource
"""
from __future__ import annotations

import base64
import os
import time
from typing import Callable, Protocol

import httpx
import jwt

API = "https://api.github.com"
SEARCH_SPACING_S = 6.5
MAX_RETRIES = 3


class GitHubClient(Protocol):
    org: str

    def advisory(self, ghsa_id: str) -> dict | None: ...
    def read_file(self, repo: str, path: str) -> str | None: ...
    def search_code(self, repo: str, query: str, limit: int) -> list[dict]: ...


class RateLimited(RuntimeError):
    """GitHub asked us to wait longer than we're willing to."""


class GitHubApp:
    """`org` is the owner of the repos: an organization (owner_type="org") or a personal
    account (owner_type="user"). Personal accounts have no teams and no org-wide
    Dependabot endpoint, so listing goes through the installation and alerts are read
    repo by repo (one extra request per repo; fine for tens of repos)."""

    def __init__(self, org: str, app_id: str, installation_id: str, private_key_pem: str,
                 http: httpx.Client | None = None, max_wait_s: float | None = None,
                 sleep: Callable[[float], None] = time.sleep, owner_type: str = "org"):
        self.org = org
        self.owner_type = _owner_type(owner_type)
        self._app_id = app_id
        self._installation_id = installation_id
        self._key = private_key_pem
        self._token: str | None = None
        self._token_exp = 0.0
        self._init_common(http, max_wait_s, sleep)

    def _init_common(self, http, max_wait_s, sleep) -> None:
        self._http = http or httpx.Client(timeout=15.0, headers={"X-GitHub-Api-Version": "2022-11-28"})
        self.max_wait_s = float(max_wait_s if max_wait_s is not None else os.environ.get("GITHUB_MAX_RATE_WAIT_S", "90"))
        self._sleep = sleep
        self._last_search = 0.0
        self.calls = 0
        self.limits: dict[str, dict] = {}     # resource -> {"remaining", "limit", "reset"}

    # ── auth ──────────────────────────────────────────────────────────────
    def _installation_token(self) -> str:
        if self._token and time.time() < self._token_exp - 120:
            return self._token
        now = int(time.time())
        app_jwt = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self._app_id}, self._key, algorithm="RS256")
        r = self._http.post(
            f"{API}/app/installations/{self._installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        )
        r.raise_for_status()
        self._token = r.json()["token"]
        self._token_exp = time.time() + 3600
        return self._token

    # ── transport with rate-limit handling ────────────────────────────────
    def _request(self, url: str, params: dict | None = None, accept: str = "application/vnd.github+json") -> httpx.Response:
        for attempt in range(MAX_RETRIES + 1):
            r = self._http.get(url, params=params, headers={
                "Authorization": f"Bearer {self._installation_token()}", "Accept": accept})
            self.calls += 1
            self._remember(r)
            if r.status_code not in (403, 429) or not _is_rate_limited(r):
                return r
            wait = _wait_seconds(r, attempt)
            if attempt == MAX_RETRIES or wait > self.max_wait_s:
                resource = r.headers.get("x-ratelimit-resource", "core")
                reset = r.headers.get("x-ratelimit-reset")
                when = time.strftime("%H:%M UTC", time.gmtime(int(reset))) if reset else f"in ~{int(wait)}s"
                raise RateLimited(f"GitHub rate limit on '{resource}'; it resets {when}. "
                                  "Re-run after that, or lower MAX_INVESTIGATIONS.")
            self._sleep(wait)
        raise RateLimited("GitHub kept rate limiting")  # pragma: no cover

    def _remember(self, r: httpx.Response) -> None:
        h = r.headers
        if "x-ratelimit-remaining" in h:
            self.limits[h.get("x-ratelimit-resource", "core")] = {
                "remaining": int(h["x-ratelimit-remaining"]), "limit": int(h.get("x-ratelimit-limit", 0)),
                "reset": int(h.get("x-ratelimit-reset", 0)),
            }

    def _get(self, path: str, params: dict | None = None, accept: str = "application/vnd.github+json"):
        r = self._request(f"{API}{path}", params, accept)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def paginate(self, path: str, params: dict | None = None, key: str | None = None):
        """Follow Link: rel="next" headers (works for page- and cursor-based endpoints).
        `key` is for endpoints that wrap the list, e.g. {"repositories": [...]}."""
        url: str | None = f"{API}{path}"
        while url:
            r = self._request(url, params)
            if r.status_code == 404:
                return
            r.raise_for_status()
            body = r.json()
            yield from (body.get(key, []) if key else body)
            url = r.links.get("next", {}).get("url")
            params = None  # the next URL already carries them

    def rate_limit(self) -> dict:
        """Current budgets. GET /rate_limit doesn't count against the primary limit."""
        r = self._http.get(f"{API}/rate_limit", headers={
            "Authorization": f"Bearer {self._installation_token()}", "Accept": "application/vnd.github+json"})
        r.raise_for_status()
        res = r.json().get("resources", {})
        return {k: res[k] for k in ("core", "search", "code_search") if k in res}

    # ── endpoints ─────────────────────────────────────────────────────────
    # The three listing methods keep their original names; for a personal account they
    # return the same shapes from the per-installation / per-repo endpoints.
    def list_org_repos(self):
        if self.owner_type == "org":
            return self.paginate(f"/orgs/{self.org}/repos", {"type": "all", "per_page": 100})
        return self._user_repos()

    def _user_repos(self):
        repos = self.paginate("/installation/repositories", {"per_page": 100}, key="repositories")
        return (r for r in repos if (r.get("owner") or {}).get("login", self.org).lower() == self.org.lower())

    def team_admin_repos(self, team_slug: str) -> set[str]:
        if self.owner_type == "user":
            return set()                     # personal accounts have no teams
        return {r["name"] for r in self.paginate(f"/orgs/{self.org}/teams/{team_slug}/repos", {"per_page": 100})
                if (r.get("permissions") or {}).get("admin")}

    def org_dependabot_alerts(self, state: str = "open"):
        if self.owner_type == "org":
            return self.paginate(f"/orgs/{self.org}/dependabot/alerts", {"state": state, "per_page": 100})
        return self._user_dependabot_alerts(state)

    def _user_dependabot_alerts(self, state: str):
        # skipped: Dependabot alerts are switched off there (nothing to report).
        # unreadable: any other refusal; the collector marks its output incomplete so
        # findings in those repos aren't wrongly closed as fixed.
        self.skipped_repos: list[str] = []
        self.unreadable_repos: list[str] = []
        for repo in self.list_org_repos():
            if repo.get("archived") or repo.get("disabled"):
                continue
            name = repo["name"]
            path = f"/repos/{self.org}/{name}/dependabot/alerts"
            r = self._request(f"{API}{path}", {"state": state, "per_page": 100})
            if r.status_code in (403, 404):
                (self.skipped_repos if "disabled" in _message(r) else self.unreadable_repos).append(name)
                continue
            r.raise_for_status()
            for a in self._rest_of(r):
                a.setdefault("repository", {"name": name})   # the org endpoint includes this
                yield a

    def _rest_of(self, first: httpx.Response):
        r = first
        while True:
            yield from r.json()
            nxt = r.links.get("next", {}).get("url")
            if not nxt:
                return
            r = self._request(nxt)
            r.raise_for_status()

    def advisory(self, ghsa_id: str) -> dict | None:
        return self._get(f"/advisories/{ghsa_id}")

    def read_file(self, repo: str, path: str) -> str | None:
        data = self._get(f"/repos/{self.org}/{repo}/contents/{path}")
        if not data or isinstance(data, list) or data.get("type") != "file":
            return None
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return data.get("content")

    def search_code(self, repo: str, query: str, limit: int) -> list[dict]:
        gap = SEARCH_SPACING_S - (time.monotonic() - self._last_search)
        if self._last_search and gap > 0:
            self._sleep(gap)
        self._last_search = time.monotonic()
        data = self._get(
            "/search/code", params={"q": f"{query} repo:{self.org}/{repo}", "per_page": limit},
            accept="application/vnd.github.text-match+json",
        ) or {}
        out = []
        for item in data.get("items", [])[:limit]:
            out.append({
                "path": item.get("path"),
                "fragments": [m.get("fragment", "") for m in item.get("text_matches", [])][:3],
            })
        return out


class GitHubToken(GitHubApp):
    """Laptop/prototype use only: authenticates with a personal token (for example the output
    of `gh auth token`) instead of a GitHub App. Never wired into the Lambda handlers.

    Its 5,000 requests/hour are shared with everything else using your GitHub account.
    The token needs read access to the org's repos and teams, and to Dependabot alerts
    (classic scopes: repo, read:org, security_events; the user must be an org owner or
    security manager for the org-wide Dependabot endpoint)."""

    def __init__(self, org: str, token: str, http: httpx.Client | None = None,
                 max_wait_s: float | None = None, sleep: Callable[[float], None] = time.sleep,
                 owner_type: str = "org"):
        self.org = org
        self.owner_type = _owner_type(owner_type)
        self._static_token = token
        self._init_common(http, max_wait_s, sleep)

    def _installation_token(self) -> str:
        return self._static_token

    def _user_repos(self):
        # A personal token has no installation; list the account's own repos instead.
        return self.paginate("/user/repos", {"affiliation": "owner", "per_page": 100})


def _message(r: httpx.Response) -> str:
    try:
        return str(r.json().get("message") or "").lower()
    except ValueError:
        return ""


def _owner_type(value: str) -> str:
    if value not in ("org", "user"):
        raise ValueError(f"GITHUB_OWNER_TYPE must be 'org' or 'user', not {value!r}")
    return value


def _is_rate_limited(r: httpx.Response) -> bool:
    if r.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in r.headers:
        return True
    try:
        return "rate limit" in (r.json().get("message") or "").lower()
    except ValueError:
        return False


def _wait_seconds(r: httpx.Response, attempt: int) -> float:
    """GitHub's documented order: retry-after, then x-ratelimit-reset, else at least a minute
    with exponential backoff."""
    if "retry-after" in r.headers:
        return float(r.headers["retry-after"])
    if r.headers.get("x-ratelimit-remaining") == "0" and r.headers.get("x-ratelimit-reset"):
        return max(0.0, int(r.headers["x-ratelimit-reset"]) - time.time()) + 1
    return 60.0 * (2 ** attempt)
