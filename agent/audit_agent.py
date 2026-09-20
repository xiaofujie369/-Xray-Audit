"""Reader and uploader run independently: central latency cannot block ingestion."""

import argparse
import hashlib
import json
import logging
import os
import signal
import socket
import threading
import time
from pathlib import Path

from agent import VERSION
from agent.access_parser import parse_line
from agent.aggregator import Aggregator
from agent.config import load
from agent.host_health import metadata
from agent.spool import Spool
from agent.uploader import request, upload_one


def read_chunk(config, spool):
    path = Path(config.get("access_log", "/opt/xray/logs/access.log"))
    if not path.exists():
        return 0
    old = spool.state("cursor", {})
    if old.get("identity") and path.exists():
        current = path.stat()
        if [current.st_dev, current.st_ino] != old["identity"]:
            for rotated in path.parent.glob(path.name + ".*"):
                stat = rotated.stat()
                if [stat.st_dev, stat.st_ino] == old["identity"] and stat.st_size > old.get("offset", 0):
                    path = rotated
                    break
    aggregator = Aggregator(config.get("aggregation_seconds", 60), config.get("max_bucket_keys", 50000))
    lines, errors = 0, 0
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        identity = [stat.st_dev, stat.st_ino]
        offset = old.get("offset", 0)
        skipping = old.get("skipping_long_line", False)
        if identity != old.get("identity") or offset > stat.st_size:
            offset = 0
            skipping = False
        # Anchor also detects copytruncate followed by regrowth beyond the old offset.
        if offset and old.get("anchor"):
            stream.seek(max(0, offset - 128))
            if hashlib.sha256(stream.read(min(offset, 128))).hexdigest() != old["anchor"]:
                offset = 0
                skipping = False
        stream.seek(offset)
        for _ in range(min(config.get("read_lines", 10000), aggregator.max_keys)):
            start = stream.tell()
            raw = stream.readline(16385)
            if not raw:
                break
            if skipping or len(raw) > 16384:
                if not skipping:
                    errors += 1
                skipping = not raw.endswith(b"\n")
                continue
            if not raw.endswith(b"\n"):
                stream.seek(start)
                break
            lines += 1
            event = parse_line(raw.decode("utf-8", errors="replace"), config.get("single_node"))
            if event is None:
                errors += 1
            else:
                aggregator.add(event)
        offset = stream.tell()
        stream.seek(max(0, offset - 128))
        anchor = hashlib.sha256(stream.read(min(offset, 128))).hexdigest()
    spool.commit(
        "events",
        aggregator.rows(),
        dict(identity=identity, offset=offset, anchor=anchor, skipping_long_line=skipping),
        config.get("batch_max_events", 1000),
        config.get("batch_max_bytes", 1048576),
    )
    with spool.db:
        spool.set_state("parser_lines", spool.state("parser_lines", 0) + lines)
        spool.set_state("parser_errors", spool.state("parser_errors", 0) + errors)
        if lines > errors:
            spool.set_state("last_access_log_time", time.time())
    return lines


def open_spool(config):
    return Spool(
        config.get("spool", "/opt/xray-audit/spool.db"),
        config.get("spool_max_mb", 512),
        config.get("spool_retention_hours", 72),
        config.get("reserve_mb", 128),
    )


def collect_traffic(config, spool):
    inbox = Path(config.get("traffic_inbox", "/opt/xray-audit/traffic-inbox"))
    for path in sorted(inbox.glob("*.json"))[:10]:
        if path.stat().st_size > 4 * 1024 * 1024:
            continue
        marker = "traffic:" + path.name
        if not spool.state(marker):
            rows = json.loads(path.read_text())
            spool.commit("traffic", rows, marker=marker)
        path.unlink()
        with spool.db:
            spool.db.execute("DELETE FROM agent_state WHERE key=?", (marker,))


def sender(config, stopped, kind="agents"):
    spool = open_spool(config)
    heartbeat_at = 0
    try:
        while not stopped.is_set():
            try:
                if time.monotonic() >= heartbeat_at:
                    heartbeat_at = time.monotonic() + 60
                    request(
                        config,
                        f"/api/v1/{kind}/heartbeat",
                        dict(
                            spool.health(),
                            agent_version=VERSION,
                            hostname=socket.gethostname(),
                            **(metadata(config, spool) if kind == "agents" else {}),
                            parser_errors=spool.state("parser_errors", 0),
                            last_access_log_time=spool.state("last_access_log_time"),
                        ),
                    )
                busy = upload_one(config, spool, kind)
                stopped.wait(0.05 if busy else config.get("upload_interval", 10))
            except Exception:
                # Deliberately do not interpolate HTTP exceptions (may contain credentials).
                stopped.wait(15)
    finally:
        spool.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/opt/xray-audit/config.json")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()
    config = load(args.config)
    spool = open_spool(config)
    if args.status:
        print(json.dumps(spool.health(), indent=2))
        spool.close()
        return
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    worker = threading.Thread(target=sender, args=(config, stopped), daemon=True)
    worker.start()
    last_warning = 0
    try:
        while not stopped.is_set():
            try:
                lines = read_chunk(config, spool)
                collect_traffic(config, spool)
                # Read a minute of low-volume traffic together; high-volume reads flush
                # early at the bounded chunk size instead of growing memory indefinitely.
                limit = min(config.get("read_lines", 10000), config.get("max_bucket_keys", 50000))
                stopped.wait(0.05 if lines >= limit else config.get("aggregation_seconds", 60))
            except Exception:
                if time.monotonic() - last_warning > 300:
                    logging.warning("audit reader unavailable; proxy services remain independent")
                    last_warning = time.monotonic()
                stopped.wait(5)
    finally:
        stopped.set()
        worker.join(timeout=16)
        spool.close()


if __name__ == "__main__":
    main()
