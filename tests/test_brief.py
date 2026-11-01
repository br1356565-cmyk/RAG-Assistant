from audit_agent import brief

from conftest import ADMIN, G_CRIT, GROWTH, U_HIGH, UK


def test_team_brief_has_explained_top_items_and_only_own_team(db):
    b = brief.build(db, GROWTH)
    assert [t["id"] for t in b["teams"]] == ["growth_engineering"]
    t = b["teams"][0]
    assert t["top"][0]["id"] == f"F-{G_CRIT}" and t["top"][0]["severity"] == "critical"
    # no investigation yet: the fix falls back to the collector's patched-version detail
    assert t["top"][0]["fix"] == "Upgrade example-http-lib to 2.3.4 (package-lock.json)"
    assert t["this_week"] == {"opened": 4, "fixed": 9, "reopened": 0}
    assert all(i["id"] != f"F-{U_HIGH}" for i in t["top"])
    assert b["as_of"] is not None and "unowned_repos" not in b


def test_accepted_risks_are_left_out_of_the_top_list(db):
    t = brief.build(db, UK)["teams"][0]
    assert t["top"] == [] and t["accepted_risks"] == 1 and t["open_by_severity"] == {"high": 1}


def test_admin_brief_covers_every_team_and_the_unowned_queue(db):
    b = brief.build(db, ADMIN)
    assert {t["id"] for t in b["teams"]} == {"growth_engineering", "uk_engineering"}
    assert b["unowned_findings"] == 1 and b["unowned_repos"] == 0


def test_brief_uses_stored_investigation(db):
    import json, psycopg
    from conftest import DBNAME, _admin_dsn
    with psycopg.connect(_admin_dsn(DBNAME), autocommit=True) as c:
        c.execute("insert into investigations (fingerprint, team_id, evidence_hash, prompt_version, model, explanation) "
                  "values (%s, 'growth_engineering', 'h', 'v', 'm', %s)",
                  (G_CRIT, json.dumps({"summary": "Crafted header crashes the API.", "confidence": "high",
                                       "impact": {"verdict": "likely"}, "fix": {"action": "Upgrade to 2.3.4."}})))
    item = brief.build(db, GROWTH)["teams"][0]["top"][0]
    assert item["summary"] == "Crafted header crashes the API." and item["fix"] == "Upgrade to 2.3.4."
    assert item["impact"] == "likely" and item["investigated_on"]
