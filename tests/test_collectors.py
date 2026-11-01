import httpx
import pytest

from audit_agent.collectors import dependabot, guardduty, ownership
from audit_agent.collectors.base import FindingRecord
from audit_agent.github import GitHubApp


class OrgGitHub:
    """Fake GitHub with an org of repos, team admin lists and Dependabot alerts."""
    org = "forbesadvisor"

    def __init__(self, repos=None, admins=None, alerts=None):
        self.repos = repos if repos is not None else [
            {"name": "mktp-uk-site"}, {"name": "mktp-growth-api"}, {"name": "exp-motors"},
            {"name": "de-pipeline"}, {"name": "ds-churn", "topics": []}, {"name": "random-tool"},
            {"name": "wp-platform"}, {"name": "old-thing", "archived": True},
            {"name": "notebooks", "topics": ["data-research"]},
        ]
        self.admins = admins if admins is not None else {
            "uk-engineering": {"mktp-uk-site", "mktp-growth-api"}, "growth-engineering": {"mktp-growth-api"}}
        self.alerts = alerts if alerts is not None else [alert("mktp-growth-api", "GHSA-2c3f-4g5h-6j7m", "critical")]

    def list_org_repos(self):
        return iter(self.repos)

    def team_admin_repos(self, slug):
        return self.admins.get(slug, set())

    def org_dependabot_alerts(self, state="open"):
        return iter(self.alerts)


def alert(repo, ghsa, sev, number=1, pkg="example-http-lib", manifest="package-lock.json", patched="2.3.4",
          scope="runtime"):
    return {"number": number, "html_url": f"https://github.com/x/{repo}/security/dependabot/{number}",
            "repository": {"name": repo},
            "dependency": {"package": {"ecosystem": "npm", "name": pkg}, "manifest_path": manifest, "scope": scope},
            "security_advisory": {"ghsa_id": ghsa, "cve_id": "CVE-2026-0001", "summary": "Crafted header crash",
                                  "severity": sev},
            "security_vulnerability": {"severity": sev, "vulnerable_version_range": "< 2.3.4",
                                       "first_patched_version": {"identifier": patched} if patched else None}}


def owners_by_repo(out):
    return {o["repo"]: o for o in out.owners}


def test_ownership_rules_precedence_and_unowned_queue():
    out = ownership.collect(OrgGitHub())
    o = owners_by_repo(out)
    assert "old-thing" not in o                                       # archived skipped
    assert o["mktp-growth-api"]["team_id"] == "uk_engineering"        # first matching rule wins
    assert o["mktp-uk-site"]["confidence"] == "confirmed"
    assert o["exp-motors"]["team_id"] == "expertise"
    assert o["de-pipeline"]["team_id"] == "de"
    assert o["ds-churn"]["team_id"] == "data_research" and o["ds-churn"]["confidence"] == "likely"
    assert o["notebooks"]["team_id"] == "data_research"               # by topic
    assert o["random-tool"]["team_id"] is None
    # override to a team that isn't configured -> unowned + warning, never silently dropped
    assert o["wp-platform"]["team_id"] is None and "unknown team india_cms" in o["wp-platform"]["source"]
    assert any("wp-platform" in w for w in out.warnings)
    unowned = {f.resource for f in out.findings}
    assert unowned == {"random-tool", "wp-platform"} and out.complete


def test_override_beats_rules():
    out = ownership.collect(OrgGitHub(repos=[{"name": "mktp-sem-tools"}, {"name": "forbes-filings"}],
                                      admins={"growth-engineering": {"mktp-sem-tools"}}))
    o = owners_by_repo(out)
    assert o["mktp-sem-tools"]["team_id"] == "uk_engineering" and o["mktp-sem-tools"]["source"] == "override"


def test_shipped_config_is_valid():
    cfg = ownership.load_config()
    assert cfg["aws_findings_team"] in {t["id"] for t in cfg["teams"]}


def test_dependabot_records_carry_fix_detail_and_stable_fingerprint():
    gh = OrgGitHub(alerts=[alert("r1", "GHSA-2c3f-4g5h-6j7m", "moderate", number=7)])
    f = dependabot.collect(gh).findings[0]
    assert f.severity == "medium" and f.details["first_patched"] == "2.3.4" and f.details["scope"] == "runtime"
    # alert numbers change if an alert is recreated; the fingerprint must not
    f2 = dependabot.collect(OrgGitHub(alerts=[alert("r1", "GHSA-2c3f-4g5h-6j7m", "moderate", number=99)])).findings[0]
    assert f.fingerprint == f2.fingerprint


def test_finding_record_rejects_bad_severity():
    with pytest.raises(ValueError):
        FindingRecord(source="x", resource="r", rule="y", title="t", severity="urgent")


class FakeGD:
    def __init__(self, fail=False):
        self.fail = fail

    def get_paginator(self, op):
        fail = self.fail

        class P:
            def paginate(self, **kw):
                if fail:
                    raise RuntimeError("AccessDenied")
                if op == "list_detectors":
                    return [{"DetectorIds": ["d1"]}]
                assert kw["FindingCriteria"]["Criterion"]["service.archived"] == {"Eq": ["false"]}
                return [{"FindingIds": ["f1", "f2"]}]
        return P()

    def get_findings(self, DetectorId, FindingIds):
        return {"Findings": [{"Id": i, "AccountId": "111", "Type": "Recon:EC2/PortProbeUnprotectedPort",
                              "Title": "Port probe", "Severity": 8.0 if i == "f1" else 2.0,
                              "Resource": {"ResourceType": "Instance", "InstanceDetails": {"InstanceId": "i-1"}},
                              "Service": {"Count": 3}} for i in FindingIds]}


class FakeSession:
    def __init__(self, failing_regions=()):
        self.failing = set(failing_regions)

    def client(self, name, region_name):
        return FakeGD(fail=region_name in self.failing)


def test_guardduty_collects_and_maps_severity():
    out = guardduty.collect(FakeSession(), ["us-east-1"], "platform_devops")
    assert out.complete and [f.severity for f in out.findings] == ["high", "low"]
    assert out.findings[0].team_hint == "platform_devops" and out.findings[0].resource == "111/i-1"


def test_guardduty_region_failure_marks_output_incomplete():
    out = guardduty.collect(FakeSession(failing_regions={"eu-west-2"}), ["us-east-1", "eu-west-2"], "platform_devops")
    assert not out.complete and len(out.findings) == 2 and "eu-west-2" in out.warnings[0]


def test_github_paginate_follows_link_headers():
    pages = {
        "/orgs/forbesadvisor/dependabot/alerts": (
            [{"number": 1}], '<https://api.github.com/orgs/forbesadvisor/dependabot/alerts?after=abc>; rel="next"'),
        "/orgs/forbesadvisor/dependabot/alerts?after=abc": ([{"number": 2}], None),
    }

    def handle(req):
        if req.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "t"})
        key = req.url.path + (f"?after={req.url.params['after']}" if "after" in req.url.params else "")
        body, link = pages[key]
        return httpx.Response(200, json=body, headers={"link": link} if link else {})

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    gh = GitHubApp("forbesadvisor", "1", "2", pem, http=httpx.Client(transport=httpx.MockTransport(handle)))
    assert [a["number"] for a in gh.org_dependabot_alerts()] == [1, 2]
