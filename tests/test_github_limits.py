"""GitHub rate-limit behaviour, driven with mocked responses and a recorded sleep."""
import time

import httpx
import pytest

from audit_agent.github import GitHubToken, RateLimited


def client(responses, max_wait_s=90):
    """responses: list of httpx.Response factories consumed in order."""
    seq = list(responses)
    sleeps = []

    def handle(req):
        return seq.pop(0)(req) if callable(seq[0]) else seq.pop(0)

    gh = GitHubToken("forbesadvisor", "t", http=httpx.Client(transport=httpx.MockTransport(handle)),
                     max_wait_s=max_wait_s, sleep=sleeps.append)
    return gh, sleeps


ok = lambda: httpx.Response(200, json={"ghsa_id": "GHSA-x"},  # noqa: E731
                            headers={"x-ratelimit-remaining": "4999", "x-ratelimit-limit": "5000",
                                     "x-ratelimit-reset": "0", "x-ratelimit-resource": "core"})


def test_retry_after_is_honoured():
    gh, sleeps = client([httpx.Response(429, headers={"retry-after": "3"}, json={"message": "slow down"}), ok()])
    assert gh.advisory("GHSA-x") == {"ghsa_id": "GHSA-x"}
    assert sleeps == [3.0] and gh.calls == 2
    assert gh.limits["core"]["remaining"] == 4999


def test_short_primary_reset_waits_then_succeeds():
    reset = str(int(time.time()) + 20)
    gh, sleeps = client([httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset},
                                        json={"message": "API rate limit exceeded"}), ok()])
    assert gh.advisory("GHSA-x")
    assert 19 <= sleeps[0] <= 22


def test_long_primary_reset_fails_fast_with_a_clear_message():
    reset = str(int(time.time()) + 1800)
    gh, sleeps = client([httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset,
                                                      "x-ratelimit-resource": "core"},
                                        json={"message": "API rate limit exceeded"})])
    with pytest.raises(RateLimited, match="'core'; it resets"):
        gh.advisory("GHSA-x")
    assert sleeps == []


def test_secondary_limit_backs_off_a_minute():
    gh, sleeps = client([httpx.Response(403, json={"message": "You have exceeded a secondary rate limit"}), ok()])
    assert gh.advisory("GHSA-x")
    assert sleeps == [60.0]


def test_secondary_limit_beyond_max_wait_fails_fast():
    gh, sleeps = client([httpx.Response(403, json={"message": "You have exceeded a secondary rate limit"})],
                        max_wait_s=30)
    with pytest.raises(RateLimited):
        gh.advisory("GHSA-x")
    assert sleeps == []


def test_permission_403_is_not_mistaken_for_a_rate_limit():
    gh, sleeps = client([httpx.Response(403, json={"message": "Resource not accessible by personal access token"})])
    with pytest.raises(httpx.HTTPStatusError):
        gh.advisory("GHSA-x")
    assert sleeps == [] and gh.calls == 1


def test_gives_up_after_bounded_retries():
    gh, sleeps = client([httpx.Response(429, headers={"retry-after": "1"}, json={})] * 4)
    with pytest.raises(RateLimited):
        gh.advisory("GHSA-x")
    assert sleeps == [1.0, 1.0, 1.0] and gh.calls == 4


def test_code_search_is_spaced_under_ten_per_minute():
    search = lambda: httpx.Response(200, json={"items": []})  # noqa: E731
    gh, sleeps = client([search(), search()])
    gh.search_code("r", "q", 5)
    gh.search_code("r", "q", 5)
    assert len(sleeps) == 1 and 6.0 < sleeps[0] <= 6.5


def test_pagination_counts_every_request():
    pages = [httpx.Response(200, json=[{"n": 1}], headers={"link": '<https://api.github.com/x?page=2>; rel="next"'}),
             httpx.Response(200, json=[{"n": 2}])]
    gh, _ = client(pages)
    assert [x["n"] for x in gh.paginate("/x")] == [1, 2] and gh.calls == 2


def test_preflight_reports_budget_and_missing_permission(capsys):
    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "local"))
    import run_weekly

    def handle(req):
        if req.url.path == "/rate_limit":
            return httpx.Response(200, json={"resources": {
                "core": {"limit": 5000, "remaining": 4210, "reset": 2000000000},
                "code_search": {"limit": 10, "remaining": 10, "reset": 2000000000}}})
        if req.url.path.endswith("/dependabot/alerts"):
            return httpx.Response(403, json={"message": "Resource not accessible by personal access token"})
        return httpx.Response(200, json=[{"name": "repo"}])

    gh = GitHubToken("forbesadvisor", "t", http=httpx.Client(transport=httpx.MockTransport(handle)))
    assert run_weekly.preflight(gh) == 1
    out = capsys.readouterr().out
    assert "4210 of 5000 left" in out and "ok      org repos" in out
    assert "FAILED  org Dependabot alerts: HTTP 403" in out and "security_events" in out
