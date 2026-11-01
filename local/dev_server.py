"""Local web server for the prototype: serves web/ and stands in for CloudFront + the chat
function URL. Listens on 127.0.0.1 only.

    python local/dev_server.py            # http://127.0.0.1:8080

  /             the web app, in dev mode (persona picker instead of Entra sign-in)
  /api/chat     the production chat handler
  /api/brief    the weekly brief for the signed-in persona
"""
from __future__ import annotations

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
    from audit_agent import brief
    from audit_agent.auth import AuthError, bearer_token, resolve_scope
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
            if path == "/api/brief":
                try:
                    with _lock:
                        claims = deps.verifier.verify(bearer_token(dict(self.headers)))
                        scope = resolve_scope(claims, deps.db)
                        data = brief.build(deps.db, scope, top_n=2 if scope.is_admin else 3)
                    return self._send(200, json.dumps(data, default=str).encode())
                except AuthError as exc:
                    return self._send(exc.status, json.dumps({"error": str(exc)}).encode())
            self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if self.path.split("?")[0] != "/api/chat":
                return self._send(404, b'{"error":"not found"}')
            length = int(self.headers.get("content-length") or 0)
            event = {"headers": dict(self.headers), "body": self.rfile.read(length).decode()}
            with _lock:
                set_deps(deps)
                resp = chat.handler(event, None)
            self._send(resp["statusCode"], resp["body"].encode())

    return Handler


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
    port = int(os.environ.get("DEV_SERVER_PORT", "8080"))
    server = serve(deps, personas, port)
    print(f"DevOps audit prototype: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
