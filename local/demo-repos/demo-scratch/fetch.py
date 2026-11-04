# One-off script someone left behind.
import requests

print(requests.get("https://example.com", timeout=10).status_code)
