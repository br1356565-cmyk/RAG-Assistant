"""The collector contract: every collector returns the same normalized shape.

Adding a report = writing one function that returns a CollectorOutput. Nothing downstream
(ingest, tools, agent, UI) changes.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class FindingRecord:
    source: str                    # collector name, e.g. "dependabot"
    resource: str                  # repo name, "<account>/<resource>", or username
    rule: str                      # advisory id, finding type, policy name
    title: str
    severity: str
    location: str = ""             # distinguishes several findings for one resource + rule
    team_hint: str | None = None   # for non-repo findings; repo findings use the ownership table
    data_class: str = "team"       # "admin_only" hides it from the team (e.g. user-level data)
    details: dict = field(default_factory=dict)  # keys starting with "_" don't count as evidence

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r} for {self.source}/{self.resource}")
        self.title = self.title[:300]

    @property
    def fingerprint(self) -> str:
        """Stable identity across runs. Never includes volatile ids such as alert numbers."""
        basis = f"{self.source}|{self.resource}|{self.rule}|{self.location}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_json(self) -> dict:
        return {**asdict(self), "fingerprint": self.fingerprint}


@dataclass
class CollectorOutput:
    collector: str
    complete: bool                 # True: these are ALL current findings; missing ones get marked fixed
    findings: list[FindingRecord] = field(default_factory=list)
    owners: list[dict] | None = None   # ownership collector only
    teams: list[dict] | None = None    # ownership collector only
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        seen: dict[str, dict] = {}
        for f in self.findings:            # last record wins if a source repeats a fingerprint
            seen[f.fingerprint] = f.to_json()
        return {"collector": self.collector, "complete": self.complete, "findings": list(seen.values()),
                "owners": self.owners, "teams": self.teams, "warnings": self.warnings}
