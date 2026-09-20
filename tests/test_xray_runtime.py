"""Pinned official Xray binary checks; set XRAY_BINARY to enable locally."""

import importlib.util
import json
import os
import socket
import struct
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agent.access_parser import parse_line

BINARY = os.environ.get("XRAY_BINARY")
pytestmark = pytest.mark.skipif(not BINARY, reason="XRAY_BINARY required")
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sync_runtime", ROOT / "sync/xboard_sync.py")
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("multi", [False, True])
def test_generated_configs(tmp_path, enabled, multi):
    users = {
        "users": [{"id": 1, "uuid": "00000000-0000-0000-0000-000000000001", "password": "test-password"}]
    }
    builders = [("vless", sync.build_vless_inbound)]
    if multi:
        builders += [
            ("vmess", sync.build_vmess_inbound),
            ("trojan", sync.build_trojan_inbound),
            ("shadowsocks", sync.build_shadowsocks_inbound),
        ]
    inbounds = []
    for index, (protocol, builder) in enumerate(builders):
        inbound = builder(
            {"protocol": protocol, "server_port": 21000 + index, "cipher": "chacha20-ietf-poly1305"},
            users,
            node_id=str(index + 1),
        )
        sync.apply_audit_sniffing(inbound, {"AUDIT_ENABLED": str(enabled).lower()})
        inbounds.append(inbound)
    config = sync.build_xray_config(inbounds)
    config["log"].update(access=str(tmp_path / "access.log"), error=str(tmp_path / "error.log"))
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    result = subprocess.run(
        [BINARY, "run", "-test", "-config", str(path)], capture_output=True, text=True, timeout=20
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_real_vless_log_and_proxy_without_central(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "7")
            self.end_headers()
            self.wfile.write(b"healthy")

        def log_message(self, *args):
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    server_port = port()
    user_id = "00000000-0000-0000-0000-000000000001"
    server = {
        "log": {"access": str(tmp_path / "access.log"), "loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": server_port,
                "tag": "vless-test",
                "protocol": "vless",
                "settings": {"decryption": "none", "clients": [{"id": user_id, "email": "379:1485"}]},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        ],
        "dns": {"hosts": {"localhost": "127.0.0.1"}},
        "outbounds": [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIPv4",
                    "finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}],
                },
            }
        ],
    }
    processes = []
    try:
        for name, config in (("server", server),):
            path = tmp_path / (name + ".json")
            path.write_text(json.dumps(config))
            processes.append(
                subprocess.Popen([BINARY, "run", "-config", str(path)], stdout=None, stderr=None)
            )
        deadline = time.monotonic() + 10
        while True:
            try:
                connection = socket.create_connection(("127.0.0.1", server_port), timeout=1)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.1)
        with connection:
            connection.settimeout(10)
            destination = b"127.0.0.1"
            connection.sendall(
                b"\x00"
                + uuid.UUID(user_id).bytes
                + b"\x00\x01"
                + struct.pack("!H", http.server_port)
                + b"\x02"
                + bytes([len(destination)])
                + destination
            )
            connection.sendall(
                b"GET /private?token=secret HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            response = b""
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"healthy" in response:
                    break
            assert b"healthy" in response
        raw = (tmp_path / "access.log").read_text()
        events = [parse_line(line) for line in raw.splitlines()]
        events = [event for event in events if event]
        assert events, raw
        assert events[0]["user_id"] == 1485
        assert events[0]["node_id"] == 379
        assert events[0]["destination_ip"] == "127.0.0.1"
        assert "secret" not in json.dumps(events)
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=10)
        http.shutdown()
        http.server_close()
