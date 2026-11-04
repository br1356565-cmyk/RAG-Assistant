"""The fix agent's behaviour on the seeded demo repos, as local/demo-repos/SCENARIOS.md
describes it. If the edit logic changes, this fails before the guide goes stale."""
import pathlib

import pytest

from fix_agent.manifest import ManifestError, bump, manifest_for

REPOS = pathlib.Path(__file__).resolve().parents[1] / "local" / "demo-repos"

# repo, manifest Dependabot reports, package, first patched, expected new spec or "refuse:<text>"
CASES = [
    ("demo-shop-web", "package-lock.json", "axios", "0.21.1", "0.21.1"),
    ("demo-shop-web", "package-lock.json", "lodash", "4.17.21", "4.17.21"),
    ("demo-shop-web", "package-lock.json", "minimist", "1.2.6", "refuse:not a direct dependency"),
    ("demo-shop-web", "package-lock.json", "qs", "6.7.3", "refuse:not a direct dependency"),
    ("demo-etl-jobs", "requirements.txt", "pyyaml", "5.4", "PyYAML==5.4"),
    ("demo-etl-jobs", "requirements.txt", "requests", "2.20.0", "requests==2.20.0"),
    ("demo-etl-jobs", "requirements.txt", "urllib3", "1.24.2", "urllib3==1.24.2"),
    ("demo-infra-terraform", "tools/render/requirements.txt", "jinja2", "2.11.3", "Jinja2==2.11.3"),
    ("demo-infra-terraform", "tools/golint/go.mod", "golang.org/x/text", "0.3.3", "refuse:support package.json"),
    ("demo-scratch", "requirements.txt", "requests", "2.20.0", "requests==2.20.0"),
]


@pytest.mark.parametrize("repo,reported,package,target,expected", CASES, ids=[f"{c[0]}:{c[2]}" for c in CASES])
def test_fix_agent_on_demo_repos(repo, reported, package, target, expected):
    path = manifest_for(reported)
    content = (REPOS / repo / path).read_text()
    if expected.startswith("refuse:"):
        with pytest.raises(ManifestError, match=expected[len("refuse:"):]):
            bump(path, content, package, target)
        return
    edit = bump(path, content, package, target)
    assert edit.new_spec.startswith(expected)
    changed = [l for l in edit.diff.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    assert len(changed) == 2                                      # exactly one line replaced


def test_demo_lockfile_pins_the_vulnerable_versions():
    import json
    pkgs = json.loads((REPOS / "demo-shop-web" / "package-lock.json").read_text())["packages"]
    assert pkgs["node_modules/axios"]["version"] == "0.21.0"
    assert pkgs["node_modules/lodash"]["version"] == "4.17.15"
    assert pkgs["node_modules/minimist"]["dev"] is True           # transitive, dev only
