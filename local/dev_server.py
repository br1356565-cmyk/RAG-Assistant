"""Local web server for the prototype: serves web/ and stands in for CloudFront + the chat
function URL. Listens on 127.0.0.1 only.

    python local/dev_server.py            # http://127.0.0.1:8080

  /             the web app, in dev mode (persona picker instead of Entra sign-in)
  /api/chat       the production chat handler (starts a background job)
  /api/chat/job   progress steps and the answer for that job
  /api/brief      the weekly brief for the signed-in persona
  /api/reviews, /api/feedback, /api/findings/dispute, /api/fixes/...   human review (see handlers/api.py)

The fix agent runs in-process (local/fix_local.py): approved fixes are written to
local/out/fix-prs/ unless FIX_GITHUB_TOKEN is set.
"""
from __future__ import annotations

import dataclasses
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import common  # noqa: F401  (sets sys.path)
from common import ROOT, env, github_client, guard_local, llm_factory, load_env

WEB = ROOT / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "application/javascript; charset=utf-8")}
_lock = threading.Lock()  # one request at a time: the handler shares one DB connection


def make_handler(deps, personas):
    from audit_agent.handlers import chat
    from audit_agent.handlers.deps import set_deps

    config_js = "window.AUDIT_CONFIG = " + json.dumps({
        "devMode": True, "personas": [{"id": p["id"], "label": p["label"]} for p in personas]}) + ";\n"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quieter console
            if os.environ.get("DEV_SERVER_VERBOSE"):
                super().log_message(fmt, *args)

        def _send(self, status, body: bytes, ctype="application/json"):
            self.send_response(status)
            self.send_header("content-type", ctype)
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/config.js":
                return self._send(200, config_js.encode(), "application/javascript")
            if path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, (WEB / name).read_bytes(), ctype)
            if path.startswith("/api/"):
                return self._api("GET", path)
            self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            path = self.path.split("?")[0]
            if not path.startswith("/api/"):
                return self._send(404, b'{"error":"not found"}')
            return self._api("POST", path)

        def _api(self, method, path):
            """Every /api/ route goes through the production chat handler, as on AWS."""
            from urllib.parse import parse_qs, urlparse
            query = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            event = {"headers": dict(self.headers), "rawPath": path, "queryStringParameters": query,
                     "requestContext": {"http": {"method": method}}}
            if method == "POST":
                length = int(self.headers.get("content-length") or 0)
                event["body"] = self.rfile.read(length).decode()
            with _lock:
                set_deps(deps)
                resp = chat.handler(event, None)
            self._send(resp["statusCode"], resp["body"].encode())

    return Handler


def thread_dispatcher(deps, new_db):
    """Stands in for Lambda's asynchronous self-invoke: runs the job in a thread with its own
    database connection, so the page can poll progress while the agent works."""
    from audit_agent.handlers import chat

    def dispatch(payload: dict) -> None:
        job_deps = dataclasses.replace(deps, db=new_db(), dispatch=None)

        def work():
            try:
                chat.run_job(payload["_job"], None, deps=job_deps)
            finally:
                job_deps.db.close()
        threading.Thread(target=work, daemon=True).start()
    return dispatch


def serve(deps, personas, port: int = 8080) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(deps, personas))
    return server


def main() -> None:
    guard_local()
    load_env()
    from audit_agent.config import Settings
    from audit_agent.db import Database
    from audit_agent.handlers.deps import Deps
    from devauth import DevVerifier, load_personas

    personas = load_personas()
    deps = Deps(settings=Settings.from_env(), db=Database(dsn=env("AUDIT_DB_APP_DSN")),
                verifier=DevVerifier(personas), llm_for=llm_factory(), github=github_client())
    if os.environ.get("FIX_AGENT", "on") != "off":
        from fix_local import build_fix_client
        deps.fix_client, where = build_fix_client(deps.github, llm=deps.llm_for(()),
                                                  model=deps.settings.batch_model)
        print(f"Fix agent: in-process, approved fixes go to {where}")
    deps.dispatch = thread_dispatcher(deps, lambda: Database(dsn=env("AUDIT_DB_APP_DSN")))
    port = int(os.environ.get("DEV_SERVER_PORT", "8080"))
    server = serve(deps, personas, port)
    print(f"DevOps audit prototype: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
