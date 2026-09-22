"""Run against a disposable Compose project; never point at production data.

AUDIT_SMOKE_URL=http://127.0.0.1:18080 python tests/compose_smoke.py
Optional --faults stops/restarts only the explicitly named test project's DB/Redis.
"""

import argparse
import json
import os
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agent.spool import Spool
from agent.uploader import upload_one

BASE = os.environ.get("AUDIT_SMOKE_URL", "http://127.0.0.1:18080")
ADMIN_HEADERS = {}


def call(path, body=None, headers=None, expected=200, method=None):
    raw = json.dumps(body).encode() if body is not None else None
    request = Request(
        BASE + "/api/v1/" + path,
        data=raw,
        headers={"Content-Type": "application/json", **(ADMIN_HEADERS if headers is None else headers)},
        method=method,
    )
    try:
        with urlopen(request, timeout=40) as response:
            data = response.read()
            assert response.status == expected
            return json.loads(data) if data else None, response.headers
    except HTTPError as error:
        if error.code != expected:
            raise AssertionError(
                f"{path}: expected {expected}, got {error.code}: {error.read(500)!r}"
            ) from error
        return None, error.headers


def wait_for(function, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = function()
            if result:
                return result
        except (HTTPError, URLError, AssertionError):
            pass
        time.sleep(1)
    raise AssertionError("smoke-test condition timed out")


def credentials(kind, name, **options):
    token, _ = call("enrollment-tokens", {"kind": kind, **options})
    identity, _ = call(kind + "/enroll", {"token": token["token"], "name": name, "region": "test"})
    identity["headers"] = {"Authorization": "Bearer " + identity["token"], "X-Agent-ID": identity["id"]}
    call(kind + "/enroll", {"token": token["token"], "name": name}, expected=401)
    return identity


def batch(events):
    return {
        "batch_id": str(uuid.uuid4()),
        "sequence": 1,
        "schema_version": 2,
        "created_at": time.time(),
        "events": events,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--project", default="xboard-audit-validation")
    args = parser.parse_args()
    if not args.project.startswith("xboard-audit-validation"):
        raise SystemExit("fault tests require an explicitly disposable validation project")
    login, headers = call(
        "auth/login",
        {
            "email": os.environ.get("ADMIN_EMAIL", "test@example.test"),
            "password": os.environ.get("ADMIN_PASSWORD", "local-test-password-12345678"),
        },
    )
    ADMIN_HEADERS.update(
        {"Cookie": headers.get("Set-Cookie").split(";", 1)[0], "X-CSRF-Token": login["csrf_token"]}
    )
    first = credentials("agents", "smoke-vps-" + uuid.uuid4().hex[:8])
    second = credentials("agents", "smoke-vps-2-" + uuid.uuid4().hex[:8])
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=30)
    event = dict(
        bucket_start=stamp.isoformat(),
        bucket_seconds=60,
        node_id=379,
        user_id=1485,
        source_ip="1.2.3.4",
        destination_domain="example.com",
        destination_port=443,
        network="tcp",
        decision="accepted",
        connections=10,
        first_seen=stamp.isoformat(),
        last_seen=stamp.isoformat(),
    )
    payload = batch([event])
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(call, "agents/events/batch", payload, first["headers"]) for _ in range(8)]
        for future in futures:
            assert future.result()[0]["accepted"]
    rows, _ = call("events?vps_id=" + first["vps_id"])
    assert len(rows["items"]) == 1, "concurrent duplicate ingest created extra rows"
    call("agents/events/batch", batch([event]), second["headers"])
    found, _ = call("entities/users/1485")
    assert found["distinct_vps"] >= 2
    target, _ = call("probe-targets", {"vps_id": first["vps_id"], "address": "8.8.8.8", "port": 443})
    call("agents/heartbeat", {"xray_running": True}, first["headers"])
    call("settings", {"control_targets": [{"address": "1.1.1.1", "port": 443}]}, method="PATCH")
    probes = [
        credentials("probes", "smoke-cn-" + str(i), mainland=True, independence_group="smoke-net-" + str(i))
        for i in range(2)
    ]
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    outside = credentials("probes", "smoke-outside", mainland=False, independence_group="outside-network")
    config, _ = call("probes/config", headers=outside["headers"])
    revision = config["control_revision"]
    call("probes/results/batch", batch([
        {"target_id": target["id"], "started_at": (start + timedelta(seconds=i * 300)).isoformat(),
         "success": True, "control_ok": True, "control_revision": revision} for i in range(2)
    ]), outside["headers"])
    for probe in probes:
        evidence = [
            {
                "target_id": target["id"],
                "started_at": (start + timedelta(seconds=i * 300)).isoformat(),
                "success": False,
                "control_ok": True,
                "control_revision": revision,
                "error_class": "timeout",
            }
            for i in range(2)
        ]
        call("probes/results/batch", batch(evidence), probe["headers"])
    incident = wait_for(
        lambda: next(
            (
                x
                for x in call("block-events?vps_id=" + first["vps_id"])[0]["items"]
                if x["state"] == "confirmed"
            ),
            None,
        )
    )
    wait_for(lambda: call("correlation/users?event_id=" + incident["id"])[0]["items"], seconds=120)
    wait_for(lambda: call("block-events/" + incident["id"] + "/investigation")[0]["status"] == "ready", seconds=120)
    for probe in probes:
        evidence = [
            {
                "target_id": target["id"],
                "started_at": (start + timedelta(seconds=540 + i * 10)).isoformat(),
                "success": True,
                "control_ok": True,
                "control_revision": revision,
                "latency_ms": 12.0,
            }
            for i in range(2)
        ]
        call("probes/results/batch", batch(evidence), probe["headers"])
    wait_for(lambda: call("block-events/" + incident["id"])[0]["state"] == "recovered")
    if args.faults:
        compose = ["docker", "compose", "-p", args.project, "-f", "audit-server/docker-compose.yml"]
        with tempfile.TemporaryDirectory() as temporary:
            spool = Spool(Path(temporary) / "spool.db", reserve_mb=0)
            config = {"server": BASE, "id": first["id"], "token": first["token"]}
            spool.commit("events", [event])
            subprocess.run(compose + ["stop", "postgres"], check=True)
            try:
                upload_one(config, spool)
                assert spool.health()["spool_rows"] == 1, "outage must retain unacknowledged batch"
            finally:
                subprocess.run(compose + ["up", "-d", "postgres"], check=True)
            wait_for(lambda: call("system/health")[0]["database"])
            with spool.db:
                spool.db.execute("UPDATE pending_batches SET next_try=0")
            upload_one(config, spool)
            assert spool.health()["spool_rows"] == 0
            spool.close()
        subprocess.run(compose + ["stop", "redis"], check=True)
        try:
            assert call("agents/events/batch", batch([event]), first["headers"])[0]["accepted"]
        finally:
            subprocess.run(compose + ["up", "-d", "redis"], check=True)
    print(
        "PASS: real PostgreSQL enrollment, concurrent idempotency, multi-VPS search, Celery consensus/correlation/recovery"
        + (", database outage spool recovery and Redis-independent ingest" if args.faults else "")
    )


if __name__ == "__main__":
    main()
