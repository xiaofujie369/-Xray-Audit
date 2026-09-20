import argparse
import errno
import http.client
import ipaddress
import signal
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from agent.audit_agent import open_spool, sender
from agent.config import load
from agent.uploader import request


def check(target, timeout=5):
    start = time.monotonic()
    stamp = datetime.now(timezone.utc).isoformat()
    outcome = dict(
        target_id=target.get("id"), started_at=stamp, success=False, latency_ms=None, error_class=None
    )
    connection = None
    try:
        address = ipaddress.ip_address(target["address"])
        if not address.is_global:
            raise ValueError("non-public target")
        connection = socket.create_connection((str(address), target["port"]), timeout=timeout)
        protocol = target.get("protocol", "tcp")
        hostname = target.get("server_name") or str(address)
        if protocol in ("tls", "https"):
            connection = ssl.create_default_context().wrap_socket(connection, server_hostname=hostname)
        if protocol in ("http", "https"):
            path = target.get("path", "/")
            if not path.startswith("/") or any(c in path + hostname for c in ("\r", "\n")):
                raise ValueError("invalid HTTP target")
            connection.sendall(
                f"HEAD {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode("ascii")
            )
            response = http.client.HTTPResponse(connection)
            response.begin()
            if not 200 <= response.status < 400:
                outcome["error_class"] = "http_failure"
                return outcome
        outcome["success"] = True
        outcome["latency_ms"] = round((time.monotonic() - start) * 1000, 2)
    except (socket.timeout, TimeoutError):
        outcome["error_class"] = "timeout"
    except ssl.SSLError:
        outcome["error_class"] = "tls_failure"
    except socket.gaierror:
        outcome["error_class"] = "dns_failure"
    except OSError as error:
        outcome["error_class"] = (
            "connection_refused" if error.errno == errno.ECONNREFUSED else "network_unreachable"
        )
    except (ValueError, http.client.HTTPException):
        outcome["error_class"] = "unknown"
    finally:
        if connection:
            connection.close()
    return outcome


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/opt/xray-probe/config.json")
    config = load(parser.parse_args().config)
    spool = open_spool(config)
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    uploader = threading.Thread(target=sender, args=(config, stopped, "probes"), daemon=True)
    uploader.start()
    next_probe = 0
    while not stopped.is_set():
        try:
            if time.monotonic() >= next_probe:
                try:
                    remote = request(config, "/api/v1/probes/config")
                    with spool.db:
                        spool.set_state("probe_config", {"received_at": time.time(), "value": remote})
                except (OSError, ValueError):
                    cached = spool.state("probe_config")
                    if not cached or time.time() - cached["received_at"] > 86400:
                        raise
                    remote = cached["value"]
                next_probe = time.monotonic() + max(30, remote["interval"])
                controls = remote["controls"]
                control_ok = all(check(target)["success"] for target in controls) if controls else True
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = [
                        dict(result, control_ok=control_ok) for result in pool.map(check, remote["targets"])
                    ]
                if results:
                    spool.commit("results", results)
        except Exception:
            # Spool survives central outages. Never print request headers or raw errors.
            stopped.wait(10)
        stopped.wait(1)
    stopped.set()
    uploader.join(timeout=16)
    spool.close()


if __name__ == "__main__":
    main()
