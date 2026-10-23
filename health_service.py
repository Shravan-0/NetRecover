#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

CONFIG_FILE = Path("/tmp/service.conf")


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")
            return

        try:
            config = CONFIG_FILE.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            config = "mode=missing"

        if config == "mode=ok":
            self.send_response(200)
            body = b"OK\n"
        else:
            self.send_response(503)
            body = b"UNHEALTHY\n"

        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print("[health-service]", format_string % args)


if __name__ == "__main__":
    CONFIG_FILE.write_text("mode=ok\n", encoding="utf-8")
    server = HTTPServer(("0.0.0.0", 8080), HealthHandler)
    print("Health service listening on port 8080")
    server.serve_forever()
