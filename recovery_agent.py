#!/usr/bin/env python3
"""Authenticated, restricted recovery agent.

Only the service configuration restoration action is executable here.
Other recovery actions remain planned, not executed.
"""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HOST = "0.0.0.0"
PORT = 8090

BASE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = BASE_DIR / "recovery.token"
CONFIG_FILE = Path("/tmp/service.conf")

MAX_BODY = 1024


class RecoveryHandler(BaseHTTPRequestHandler):

    def send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {
                "ok": True,
                "service": "recovery-agent",
                "execution_enabled": True,
                "supported_actions": ["restore_service_config"],
            })
            return

        self.send_json(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        if self.path not in ("/recover", "/recover/config"):
            self.send_json(404, {"ok": False, "error": "Not found"})
            return

        try:
            token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            self.send_json(503, {"ok": False, "error": "Recovery token unavailable"})
            return

        supplied = self.headers.get("X-Recovery-Token", "")

        if not token or not hmac.compare_digest(supplied, token):
            self.send_json(403, {"ok": False, "error": "Authentication failed"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_BODY:
                self.send_json(413, {"ok": False, "error": "Invalid request size"})
                return

            raw = self.rfile.read(length) if length else b""

            if raw:
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("JSON object required")
                action = payload.get("action")
            else:
                # Backward compatibility with the existing detector.
                action = "restore_service_config"

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_json(400, {"ok": False, "error": "Invalid request"})
            return

        if action != "restore_service_config":
            self.send_json(400, {
                "ok": False,
                "error": "Unsupported recovery action",
            })
            return

        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            temporary = CONFIG_FILE.with_suffix(".recovery.tmp")
            temporary.write_text("mode=ok\n", encoding="utf-8")
            os.replace(temporary, CONFIG_FILE)
        except OSError as exc:
            self.send_json(500, {
                "ok": False,
                "error": f"Configuration restoration failed: {exc}",
            })
            return

        print("[RECOVERY] Service configuration restored.", flush=True)

        self.send_json(200, {
            "ok": True,
            "action": action,
            "target": "h2:8080",
            "message": "Service configuration restored",
        })

    def log_message(self, format_string, *args):
        print("[recovery-agent]", format_string % args, flush=True)


if __name__ == "__main__":
    HTTPServer((HOST, PORT), RecoveryHandler).serve_forever()
