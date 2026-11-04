"""Weekly ingest: collector outputs -> findings lifecycle, ownership, aggregates, and the
list of findings worth investigating.

Lifecycle rules
  * new fingerprint                         -> open   (event: opened)
  * seen again after being fixed            -> open   (event: reopened)
  * suppressed stays suppressed; last_seen still updates
  * missing from a COMPLETE collector run   -> fixed  (event: fixed)
  * a failed or incomplete collector never marks anything fixed
Everything happens in one transaction: a crash leaves the previous state untouched.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable

from .prompts import PROMPT_VERSION

SEV_RANK = "array_position(array['critical','high','medium','low','info'], f.severity)"


def _evidence(details: dict | None) -> dict:
    return {k: v for k, v in (details or {}).items() if not k.startswith("_")}


def _opened_at(details: dict | None, now: datetime) -> datetime:
    """When the source first raised it (e.g. Dependabot's created_at), so ages are real even
    on the first run. Falls back to now; never in the future."""
    raw = (details or {}).get("_created_at")
    if isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return min(ts, now)
        except ValueError:
            pass
    return now


def ingest(conn, run_id: str, results: list[dict], load: Callable[[str], dict], *,
           investigate_sources: tuple[str, ...] = ("dependabot",),
           investigate_severities: tuple[str, ...] = ("critical", "high"),
           max_investigations: int = 100, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    week = now.date() - timedelta(days=now.weekday())
    opened, fixed, reopened = Counter(), Counter(), Counter()
    changed: set[str] = set()
    warnings: list[str] = []

    with conn.transaction():
        conn.execute("insert into runs (run_id, started_at, status) values (%s, %s, 'running') "
                     "on conflict (run_id) do update set started_at = excluded.started_at, status = 'running'",
                     (run_id, now))
        outputs: dict[str, dict] = {}
        for r in results:
            name, status = str(r.get("collector")), r.get("status", "failed")
            conn.execute(
                "insert into run_collectors (run_id, collector, status, error) values (%s, %s, %s, %s) "
                "on conflict (run_id, collector) do update set status = excluded.status, error = excluded.error",
                (run_id, name, status, (str(r.get("error") or "")[:2000]) or None))
            if status == "succeeded":
                outputs[name] = load(r["key"])

        # 1. Ownership first, so this run's findings get today's owners.
        own = outputs.get("ownership")
        if own:
            for t in own.get("teams") or []:
                conn.execute("insert into teams (id, name, entra_group_id) values (%s, %s, %s) on conflict (id) "
                             "do update set name = excluded.name, entra_group_id = excluded.entra_group_id",
                             (t["id"], t["name"], t.get("entra_group_id")))
            repos = []
            for o in own.get("owners") or []:
                repos.append(o["repo"])
                conn.execute(
                    "insert into repo_owners (repo, team_id, source, confidence, updated_at) values (%s,%s,%s,%s,%s) "
                    "on conflict (repo) do update set team_id = excluded.team_id, source = excluded.source, "
                    "confidence = excluded.confidence, updated_at = excluded.updated_at",
                    (o["repo"], o["team_id"], o["source"], o["confidence"], now))
            conn.execute("delete from repo_owners where not (repo = any(%s))", (repos,))
            warnings += own.get("warnings") or []

        teams = {r["id"] for r in conn.execute("select id from teams").fetchall()}
        owners = {r["repo"]: r["team_id"] for r in conn.execute("select repo, team_id from repo_owners").fetchall()}

        # 2. Findings, per collector.
        for name, out in outputs.items():
            existing = {r["fingerprint"]: r for r in conn.execute(
                "select fingerprint, status, severity, title, details, team_id from findings where source = %s",
                (name,)).fetchall()}
            seen: set[str] = set()
            for f in out.get("findings") or []:
                if f["source"] != name:
                    warnings.append(f"{name}: skipped record with source {f['source']}")
                    continue
                fp = f["fingerprint"]
                seen.add(fp)
                team = f.get("team_hint") or (None if name == "ownership" else owners.get(f["resource"]))
                team = team if team in teams else None
                ex = existing.get(fp)
                if ex is None:
                    opened_at = _opened_at(f.get("details"), now)
                    conn.execute(
                        "insert into findings (fingerprint, team_id, source, resource, rule, title, severity, "
                        "data_class, details, first_seen, last_seen) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (fp, team, name, f["resource"], f["rule"], f["title"], f["severity"],
                         f.get("data_class", "team"), json.dumps(f.get("details") or {}), opened_at, now))
                    conn.execute("insert into finding_events (fingerprint, team_id, event, at) values (%s,%s,'opened',%s)",
                                 (fp, team, opened_at))
                    opened[team] += 1
                    changed.add(fp)
                    continue
                is_reopen = ex["status"] == "fixed"
                new_status = "suppressed" if ex["status"] == "suppressed" else "open"
                conn.execute(
                    "update findings set team_id = %s, title = %s, severity = %s, data_class = %s, details = %s, "
                    "last_seen = %s, status = %s where fingerprint = %s",
                    (team, f["title"], f["severity"], f.get("data_class", "team"),
                     json.dumps(f.get("details") or {}), now, new_status, fp))
                if is_reopen:
                    conn.execute("insert into finding_events (fingerprint, team_id, event, at) values (%s,%s,'reopened',%s)",
                                 (fp, team, now))
                    reopened[team] += 1
                if is_reopen or ex["severity"] != f["severity"] or ex["title"] != f["title"] \
                        or _evidence(ex["details"]) != _evidence(f.get("details")):
                    changed.add(fp)

            if out.get("complete"):
                gone = [fp for fp, r in existing.items() if r["status"] == "open" and fp not in seen]
                if gone:
                    conn.execute("update findings set status = 'fixed' where fingerprint = any(%s)", (gone,))
                    for fp in gone:
                        t = existing[fp]["team_id"]
                        conn.execute("insert into finding_events (fingerprint, team_id, event, at) "
                                     "values (%s,%s,'fixed',%s)", (fp, t, now))
                        fixed[t] += 1
            else:
                warnings.append(f"{name}: incomplete output, nothing marked fixed")

        # 3. Weekly aggregates (team-visible findings only).
        for team in sorted(teams):
            sev = conn.execute(
                "select severity, count(*) n from findings where team_id = %s and status = 'open' "
                "and data_class = 'team' group by 1", (team,)).fetchall()
            counts = {"open": {r["severity"]: r["n"] for r in sev},
                      "opened": opened[team], "fixed": fixed[team], "reopened": reopened[team]}
            conn.execute("insert into weekly_aggregates (team_id, week, counts) values (%s,%s,%s) "
                         "on conflict (team_id, week) do update set counts = excluded.counts",
                         (team, week, json.dumps(counts)))

        # 4. Expired chat sessions.
        conn.execute("delete from session_turns where expires_at < now()")
        conn.execute("delete from chat_jobs where created_at < now() - interval '2 days'")

        # 5. What to investigate: changed, or never investigated with the current prompt.
        queue = conn.execute(
            f"select f.fingerprint, f.team_id from findings f where f.status = 'open' and f.team_id is not null "
            f"and f.data_class = 'team' and f.source = any(%s) and f.severity = any(%s) "
            f"and (f.fingerprint = any(%s) or not exists (select 1 from investigations i where "
            f"i.fingerprint = f.fingerprint and i.team_id = f.team_id and i.prompt_version = %s) "
            f"or exists (select 1 from investigations i where i.fingerprint = f.fingerprint "
            f"  and i.id = (select max(j.id) from investigations j where j.fingerprint = f.fingerprint) "
            f"  and review_state(i.id, i.needs_review) in ('rejected','disputed'))) "
            f"order by {SEV_RANK}, f.first_seen limit %s",
            (list(investigate_sources), list(investigate_severities), sorted(changed), PROMPT_VERSION,
             max_investigations)).fetchall()

        failed = [r for r in results if r.get("status") != "succeeded"]
        status = "succeeded" if not failed else "partial"
        conn.execute("update runs set finished_at = %s, status = %s where run_id = %s",
                     (datetime.now(timezone.utc), status, run_id))

    return {
        "run_id": run_id, "status": status,
        "collectors": [{"collector": r.get("collector"), "status": r.get("status"),
                        "count": r.get("count"), "error": (str(r.get("error") or "")[:300]) or None}
                       for r in results],
        "opened": sum(opened.values()), "fixed": sum(fixed.values()), "reopened": sum(reopened.values()),
        "warnings": warnings[:30],
        "investigate": [{"fingerprint": f"F-{q['fingerprint']}", "team_id": q["team_id"], "run_id": run_id}
                        for q in queue],
    }
