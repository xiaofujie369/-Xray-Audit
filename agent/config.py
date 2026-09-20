import json
import os
from pathlib import Path
from urllib.parse import urlsplit


def load(path="/opt/xray-audit/config.json"):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    aliases = {
        "AUDIT_SERVER": "server",
        "AUDIT_AGENT_ID": "id",
        "AUDIT_AGENT_TOKEN": "token",
        "AUDIT_PUBLIC_IPV4": "public_ipv4",
        "AUDIT_PUBLIC_IPV6": "public_ipv6",
    }
    for env, key in aliases.items():
        if os.environ.get(env):
            config[key] = os.environ[env]
    for key in (
        "aggregation_seconds",
        "max_bucket_keys",
        "upload_interval",
        "batch_max_events",
        "batch_max_bytes",
        "spool_max_mb",
        "spool_retention_hours",
    ):
        value = os.environ.get("AUDIT_" + key.upper())
        if value:
            config[key] = int(value)
    parsed = urlsplit(config["server"])
    if not parsed.hostname or parsed.scheme not in ("https", "http"):
        raise ValueError("invalid central URL")
    if parsed.scheme != "https" and not config.get("unsafe_development", False):
        raise ValueError("HTTPS required")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid central URL")
    bounds = {
        "aggregation_seconds": (1, 3600),
        "max_bucket_keys": (1, 50000),
        "batch_max_events": (1, 1000),
        "batch_max_bytes": (4096, 1048576),
        "spool_max_mb": (1, 65536),
        "spool_retention_hours": (1, 2160),
        "reserve_mb": (16, 65536),
        "upload_interval": (1, 3600),
        "read_lines": (1, 10000),
    }
    for key, (low, high) in bounds.items():
        if key in config and (type(config[key]) is not int or not low <= config[key] <= high):
            raise ValueError("invalid audit limit: " + key)
    return config


def save(path, config):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    temp = path.with_suffix(".tmp")
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(config, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
        if previous is not None and hasattr(os, "fchown"):
            os.fchown(stream.fileno(), previous.st_uid, previous.st_gid)
    os.replace(temp, path)
    path.chmod(0o600)
