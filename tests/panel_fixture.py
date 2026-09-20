"""Local deterministic XBoard fixture for disposable install/upgrade validation."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path.endswith("/config"):
            node = int(parse_qs(url.query)["node_id"][0])
            result = {"data": {"server_port": 33000 + node, "network": "tcp", "tls": 0}}
        elif url.path.endswith("/user"):
            result = {"users": [{"id": 1485, "uuid": "00000000-0000-0000-0000-000000000001"}]}
        else:
            result = {"data": {}}
        self.respond(result)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with Path("/root/panel-reports.jsonl").open("a") as output:
            output.write(
                json.dumps({"path": urlsplit(self.path).path, "body": json.loads(body or b"{}")}) + "\n"
            )
        self.respond({"data": True})

    def respond(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18081), Handler).serve_forever()
