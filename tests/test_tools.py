import pytest

from audit_agent.tools import ToolContext, ToolError, tools_for
from audit_agent.tools.base import REGISTRY
from audit_agent.tools.findings import FindingArg, SearchArgs, TeamArg, get_finding, get_team_overview, search_findings
from audit_agent.tools.notes import ProposeArgs, propose_team_note
from audit_agent.tools.repo import ReadFileArgs, read_repo_file
from audit_agent.tools.submit import Investigation, submit_investigation

from conftest import ADMIN, G_CRIT, GHSA, GROWTH, ORPHAN, U_HIGH, UK, FakeGitHub


def ctx(db, scope, mode="chat"):
    return ToolContext(scope=scope, db=db, github=FakeGitHub(), mode=mode)


def test_tool_sets_per_mode():
    chat = {t.name for t in tools_for("chat")}
    inv = {t.name for t in tools_for("investigate")}
    assert "propose_team_note" in chat and "submit_investigation" not in chat
    assert {"read_repo_file", "search_code", "submit_investigation"} <= inv
    assert "propose_team_note" not in inv


def test_schemas_are_clean_and_strict():
    for t in REGISTRY.values():
        params = t.schema()["function"]["parameters"]
        assert "title" not in params
        assert params.get("additionalProperties") is False, t.name


def test_search_is_scoped_and_ordered(db):
    r = search_findings(ctx(db, GROWTH), SearchArgs())
    ids = [f["id"] for f in r.data["findings"]]
    assert ids == [f"F-{G_CRIT}", "F-a000000000000002"]      # critical before low
    assert r.finding_ids == {G_CRIT, "a000000000000002"}


def test_search_refuses_other_team(db):
    with pytest.raises(ToolError, match="outside your access"):
        search_findings(ctx(db, GROWTH), SearchArgs(team="uk_engineering"))


def test_unowned_only_for_admins(db):
    with pytest.raises(ToolError):
        search_findings(ctx(db, GROWTH), SearchArgs(team="unowned"))
    r = search_findings(ctx(db, ADMIN), SearchArgs(team="unowned"))
    assert [f["id"] for f in r.data["findings"]] == [f"F-{ORPHAN}"]


def test_admin_overview_covers_all_teams(db):
    r = get_team_overview(ctx(db, ADMIN), TeamArg())
    assert set(r.data["teams"]) == {"growth_engineering", "uk_engineering"}
    assert r.data["as_of"] is not None


def test_get_finding_same_error_for_missing_and_foreign(db):
    with pytest.raises(ToolError) as foreign:
        get_finding(ctx(db, GROWTH), FindingArg(id=f"F-{U_HIGH}"))
    with pytest.raises(ToolError) as missing:
        get_finding(ctx(db, GROWTH), FindingArg(id="F-ffffffffffffffff"))
    assert str(foreign.value).replace(U_HIGH, "X") == str(missing.value).replace("ffffffffffffffff", "X")


def test_get_finding_includes_active_notes(db):
    r = get_finding(ctx(db, UK), FindingArg(id=f"F-{U_HIGH}"))
    assert r.data["active_notes"][0]["kind"] == "accepted_risk"


def test_propose_note_is_saved_as_proposal(db):
    from datetime import date, timedelta
    r = propose_team_note(ctx(db, GROWTH), ProposeArgs(
        kind="accepted_risk", text="We accept this until the API migration lands",
        finding_id=f"F-{G_CRIT}", expires_at=date.today() + timedelta(days=30)))
    assert r.data["status"] == "proposed" and r.data["team"] == "growth_engineering"


def test_accepted_risk_needs_bounded_expiry(db):
    from datetime import date, timedelta
    with pytest.raises(ToolError, match="needs expires_at"):
        propose_team_note(ctx(db, GROWTH), ProposeArgs(kind="accepted_risk", text="forever and ever please"))
    with pytest.raises(ToolError, match="next 180 days"):
        propose_team_note(ctx(db, GROWTH), ProposeArgs(kind="accepted_risk", text="a very long time please",
                                                       expires_at=date.today() + timedelta(days=400)))


def test_repo_tools_only_reach_own_team_repos(db):
    c = ctx(db, GROWTH, "investigate")
    assert "example-http-lib" in read_repo_file(c, ReadFileArgs(repo="mktp-growth-api", path="package.json")).data["content"]
    with pytest.raises(ToolError, match="not owned"):
        read_repo_file(c, ReadFileArgs(repo="mktp-uk-site", path="package.json"))
    with pytest.raises(ToolError, match="not owned"):
        read_repo_file(c, ReadFileArgs(repo="orphan-repo", path="package.json"))


def test_path_traversal_rejected():
    with pytest.raises(Exception):
        ReadFileArgs(repo="mktp-growth-api", path="../../etc/passwd")


def test_submit_rejects_sources_not_retrieved(db):
    c = ctx(db, GROWTH, "investigate")
    report = Investigation.model_validate({
        "summary": "s", "confidence": "high",
        "impact": {"verdict": "likely", "reasoning": "runtime dependency"},
        "fix": {"action": "upgrade", "target_version": "2.3.4", "breaking_changes": "none_listed"},
        "sources": [{"kind": "advisory", "ref": GHSA}],
    })
    with pytest.raises(ToolError, match="not retrieved"):
        submit_investigation(c, report)
    c.retrieved_sources.add(f"advisory:{GHSA}")
    assert submit_investigation(c, report).data["fix"]["target_version"] == "2.3.4"
