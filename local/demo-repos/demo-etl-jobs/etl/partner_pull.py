"""Pulls daily files from a partner API with our API token."""
import os

import requests

PARTNER_URL = os.environ.get("PARTNER_URL", "https://partner.example.com/export")


def pull(day: str) -> bytes:
    # The partner redirects downloads to their CDN; the token header goes along.
    resp = requests.get(f"{PARTNER_URL}/{day}.csv",
                        headers={"Authorization": f"Bearer {os.environ['PARTNER_TOKEN']}"},
                        allow_redirects=True, timeout=30)
    resp.raise_for_status()
    return resp.content
