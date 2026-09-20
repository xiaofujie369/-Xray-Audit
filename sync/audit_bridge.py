"""Best-effort local handoff only. XBoard owns and resets Stats API counters."""

import json
import os
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def publish(traffic, interval_start, interval_end, directory="/opt/xray-audit/traffic-inbox"):
    path = Path(directory)
    if not path.is_dir():
        return
    if shutil.disk_usage(path).free < 128 * 1024 * 1024:
        return
    # Fixed, bounded inbox; no network and no SQLite lock in the report process.
    entries = list(path.glob("*.json"))
    if len(entries) >= 120:
        return
    rows = []
    for node, users in traffic.items():
        for user, (up, down) in users.items():
            if up or down:
                rows.append(
                    dict(
                        node_id=int(node),
                        user_id=int(user),
                        uplink_bytes=up,
                        downlink_bytes=down,
                        interval_start=interval_start,
                        interval_end=interval_end,
                    )
                )
    if not rows:
        return
    body = json.dumps(rows).encode()
    if len(body) > 4 * 1024 * 1024:
        return
    temp = path / (uuid.uuid4().hex + ".tmp")
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    if os.name == "posix":
        import grp

        try:
            os.fchown(fd, -1, grp.getgrnam("xray-audit").gr_gid)
            os.fchmod(fd, 0o640)
        except KeyError:
            pass
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
    os.replace(temp, temp.with_suffix(".json"))


def copy_interval(traffic, state_path="/opt/xray-sync/audit_interval.json"):
    """Failures in this optional copy must never change panel reporting."""
    try:
        path = Path(state_path)
        end = time.time()
        start = json.loads(path.read_text())["end"] if path.exists() else end - 60
        publish(
            traffic,
            datetime.fromtimestamp(start, timezone.utc).isoformat(),
            datetime.fromtimestamp(end, timezone.utc).isoformat(),
        )
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps({"end": end}))
        temp.replace(path)
    except Exception:
        pass
