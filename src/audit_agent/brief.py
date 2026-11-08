"""The weekly team brief: what changed, the top items to fix (with their stored
investigation), and hygiene counts. Built deterministically from the database under the
caller's scope; no model call. The same structure can render the Monday email later."""
from __future__ import annotations

from datetime import datetime, timezone

from .db import Database, Scope

SEV_RANK = "array_position(array['critical','high','medium','low','info'], f.severity)"
SEVERITIES = ("critical", "high", "medium", "low", "info")

# The latest fix request that covers a finding (one request can cover every finding for a
# package in a manifest), so the page can say "PR opened" instead of offering another draft.
FIX_JOIN = (
    "left join lateral (select x.id as fix_id, x.status as fix_status, x.pr_url as fix_pr, x.error as fix_error, "
    "  x.major_upgrade as fix_major, x.requested_by as fix_by, x.updated_at as fix_at from fix_requests x "
    "  where x.fingerprint = f.fingerprint or f.fingerprint = any (x.covers) "
    "  order by x.created_at desc, x.id desc limit 1) fx on true ")
INVESTIGATION_JOIN = (
    "left join lateral (select id, explanation, created_at, review_state(id, needs_review) as state "
    "  from investigations i where i.fingerprint = f.fingerprint "
    "  and review_state(i.id, i.needs_review) in ('auto','approved') "
    "  order by created_at desc, id desc limit 1) i on true ")


def build(db: Database, scope: Scope, top_n: int = 5) -> dict:
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
                f"       i.explanation, i.created_at as investigated_at, i.state as review, fx.*, "
                f"       (select r.fix_override from investigation_reviews r where r.investigation_id = i.id "
                f"        order by r.created_at desc, r.id desc limit 1) as fix_override "
                f"from findings f {INVESTIGATION_JOIN} {FIX_JOIN}"
                f"where f.team_id = %s and f.status = 'open' and f.data_class = 'team' "
                f"and not exists (select 1 from team_notes n where n.fingerprint = f.fingerprint "
                f"  and n.kind in ('accepted_risk','false_positive') and n.status = 'active' "
                f"  and (n.expires_at is null or n.expires_at >= current_date)) "
                f"order by {SEV_RANK}, f.first_seen limit %s", (team, top_n)).fetchall()
            awaiting = conn.execute(
                "select count(*) n from (select distinct on (i.fingerprint) review_state(i.id, i.needs_review) st "
                "from investigations i join findings f on f.fingerprint = i.fingerprint "
                "where f.team_id = %s and f.status = 'open' order by i.fingerprint, i.created_at desc, i.id desc) x "
                "where st in ('pending','disputed')", (team,)).fetchone()["n"]
            counts = (week or {}).get("counts", {}) if week else {}
            out["teams"].append({
                "id": team,
                "name": names.get(team, team),
                "open_by_severity": {r["severity"]: r["n"] for r in sev},
                "open_by_source": {r["source"]: r["n"] for r in src},
                "this_week": {k: counts.get(k, 0) for k in ("opened", "fixed", "reopened")},
                "accepted_risks": accepted,
                "awaiting_review": awaiting,
                "open_total": sum(r["n"] for r in sev),
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
            "fix": r.get("fix_override") or (exp.get("fix") or {}).get("action"),
            "reviewed": r.get("review") == "approved",
            "impact": (exp.get("impact") or {}).get("verdict"),
            "confidence": exp.get("confidence"),
            "investigated_on": r["investigated_at"].date().isoformat() if r["investigated_at"] else None,
        })
    elif d.get("first_patched"):
        item["fix"] = f"Upgrade {d.get('package')} to {d['first_patched']} ({d.get('manifest')})"
    if r.get("fix_id"):
        item["fix_request"] = {"id": str(r["fix_id"]), "status": r["fix_status"], "pr_url": r["fix_pr"],
                               "error": (r["fix_error"] or "")[:200] or None, "major_upgrade": r["fix_major"],
                               "requested_by": r["fix_by"], "updated_at": r["fix_at"].isoformat()}
    return item


def findings_page(db: Database, scope: Scope, q: dict) -> dict:
    """Every finding the caller can see, filtered and paged (the brief shows only the top few).
    Row-level security does the team filtering; these filters only narrow."""
    now = datetime.now(timezone.utc)
    where, params = ["f.data_class = 'team' or %s"], [scope.is_admin]
    status = q.get("status") or "open"
    if status in ("open", "fixed", "suppressed"):
        where.append("f.status = %s"); params.append(status)
    team = q.get("team")
    if team == "unowned" and scope.is_admin:
        where.append("f.team_id is null")
    elif team:
        where.append("f.team_id = %s"); params.append(str(team))
    sev = [x for x in str(q.get("severity") or "").split(",") if x in SEVERITIES]
    if sev:
        where.append("f.severity = any(%s)"); params.append(sev)
    if q.get("source"):
        where.append("f.source = %s"); params.append(str(q["source"])[:40])
    text = str(q.get("q") or "").strip()[:100]
    if text:
        where.append("(f.title ilike %s or f.resource ilike %s or f.rule ilike %s)"); params += [f"%{text}%"] * 3
    fix = q.get("fix")
    if fix == "none":
        where.append("fx.fix_id is null or fx.fix_status in ('rejected','failed')")
    elif fix == "in_progress":
        where.append("fx.fix_status in ('drafting','awaiting_approval','approved')")
    elif fix == "opened":
        where.append("fx.fix_status = 'opened'")
    try:
        page = max(1, min(int(q.get("page") or 1), 1000))
        size = max(10, min(int(q.get("size") or 50), 100))
    except ValueError:
        page, size = 1, 50
    clause = " and ".join(f"({w})" for w in where)
    base = f"from findings f {INVESTIGATION_JOIN} {FIX_JOIN} where {clause}"
    with db.scoped(scope) as conn:
        total = conn.execute(f"select count(*) n {base}", params).fetchone()["n"]
        rows = conn.execute(
            f"select f.fingerprint, f.team_id, f.title, f.resource, f.severity, f.source, f.status, f.first_seen, "
            f"f.details, i.explanation, i.created_at as investigated_at, i.state as review, fx.*, null as fix_override "
            f"{base} order by {SEV_RANK}, f.first_seen, f.fingerprint limit %s offset %s",
            params + [size, (page - 1) * size]).fetchall()
        sources = [r["source"] for r in conn.execute(
            "select distinct source from findings order by 1").fetchall()]
        teams = [r["id"] for r in conn.execute("select id from teams order by id").fetchall()] \
            if scope.is_admin else list(scope.team_ids)
    return {"total": total, "page": page, "size": size, "sources": sources, "teams": teams,
            "findings": [{**_item(r, now), "team": r["team_id"], "status": r["status"]} for r in rows]}
