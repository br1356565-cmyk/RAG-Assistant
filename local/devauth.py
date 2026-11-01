"""Prototype-only sign-in: pick a persona instead of signing in with Entra ID.

Lives outside src/, so it is never packaged into the Lambdas. Tokens look like
"dev:<persona id>" and map to the claims Entra would send, so everything after
verification (team mapping, row-level security) is the production code path.
"""
from __future__ import annotations

import pathlib

import yaml

from audit_agent.auth import AuthError

PERSONAS_FILE = pathlib.Path(__file__).with_name("personas.yml")


def load_personas(path: pathlib.Path = PERSONAS_FILE) -> list[dict]:
    return yaml.safe_load(path.read_text())["personas"]


class DevVerifier:
    def __init__(self, personas: list[dict]):
        self.by_id = {p["id"]: p for p in personas}

    def verify(self, token: str) -> dict:
        if not token.startswith("dev:") or token[4:] not in self.by_id:
            raise AuthError("unknown persona")
        p = self.by_id[token[4:]]
        return {
            "oid": f"dev-{p['id']}",
            "name": p["label"],
            "groups": [f"dev:{t}" for t in p.get("teams", [])],
            "roles": p.get("roles", []),
        }
