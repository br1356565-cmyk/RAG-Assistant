"""The weekly team brief: what changed, the top items to fix (with their stored
investigation), and hygiene counts. Built deterministically from the database under the
caller's scope; no model call. The same structure can render the Monday email later."""
from __future__ import annotations

from datetime import datetime, timezone

from .db import Database, Scope

SEV_RANK = "array_position(array['critical','high','medium','low','info'], f.severity)"


def build(db: Database, scope: Scope, top_n: int = 3) -> dict:
    now = datetime.now(timezone.utc)
    with db.scoped(scope) as conn:
        if scope.is_admin:
            teams = [r["id"] for r in conn.execute("select id from teams order by id").fetchall()]
        else:
            teams = list(scope.team_ids)
        names = {r["id"]: r["name"] for r in conn.execute("select id, name from teams").fetchall()}
        run = conn.execute("select finished_at from runs where status in ('succeeded','partial') "
                           "order by finished_at desc limit 1").fetchone()
        out: dict = {"as_of": run["finished_at"].isoformat() if run else None, "teams": []}

        for team in teams:
            sev = conn.execute(
                "select severity, count(*) n from findings where team_id = %s and status = 'open' "
                "and data_class = 'team' group by 1", (team,)).fetchall()
            src = conn.execute(
                "select source, count(*) n from findings where team_id = %s and status = 'open' "
                "and data_class = 'team' group by 1 order by 2 desc", (team,)).fetchall()
            week = conn.execute(
                "select counts from weekly_aggregates where team_id = %s order by week desc limit 1",
                (team,)).fetchone()
            accepted = conn.execute(
                "select count(*) n from team_notes where team_id = %s and kind = 'accepted_risk' "
                "and status = 'active' and (expires_at is null or expires_at >= current_date)", (team,)).fetchone()["n"]
            top = conn.execute(
                f"select f.fingerprint, f.title, f.resource, f.severity, f.source, f.first_seen, f.details, "
                f"       i.explanation, i.created_at as investigated_at "
                f"from findings f "
                f"left join lateral (select explanation, created_at from investigations i "
                f"  where i.fingerprint = f.fingerprint order by created_at desc limit 1) i on true "
                f"where f.team_id = %s and f.status = 'open' and f.data_class = 'team' "
                f"and not exists (select 1 from team_notes n where n.fingerprint = f.fingerprint "
                f"  and n.kind in ('accepted_risk','false_positive') and n.status = 'active' "
                f"  and (n.expires_at is null or n.expires_at >= current_date)) "
                f"order by {SEV_RANK}, f.first_seen limit %s", (team, top_n)).fetchall()
            counts = (week or {}).get("counts", {}) if week else {}
            out["teams"].append({
                "id": team,
                "name": names.get(team, team),
                "open_by_severity": {r["severity"]: r["n"] for r in sev},
                "open_by_source": {r["source"]: r["n"] for r in src},
                "this_week": {k: counts.get(k, 0) for k in ("opened", "fixed", "reopened")},
                "accepted_risks": accepted,
                "top": [_item(r, now) for r in top],
            })

        if scope.is_admin:
            out["unowned_repos"] = conn.execute(
                "select count(*) n from findings where source = 'ownership' and status = 'open'").fetchone()["n"]
            out["unowned_findings"] = conn.execute(
                "select count(*) n from findings where team_id is null and status = 'open' "
                "and source <> 'ownership'").fetchone()["n"]
    return out


def _item(r: dict, now: datetime) -> dict:
    exp = r["explanation"] or {}
    d = r["details"] or {}
    item = {
        "id": f"F-{r['fingerprint']}", "title": r["title"], "resource": r["resource"],
        "severity": r["severity"], "source": r["source"], "open_days": (now - r["first_seen"]).days,
        "url": d.get("_url"),
    }
    if exp:
        item.update({
            "summary": exp.get("summary"),
            "fix": (exp.get("fix") or {}).get("action"),
            "impact": (exp.get("impact") or {}).get("verdict"),
            "confidence": exp.get("confidence"),
            "investigated_on": r["investigated_at"].date().isoformat() if r["investigated_at"] else None,
        })
    elif d.get("first_patched"):
        item["fix"] = f"Upgrade {d.get('package')} to {d['first_patched']} ({d.get('manifest')})"
    return item
