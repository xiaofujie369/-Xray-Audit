"""Bounded local metadata collection; Docker access stays outside the audit user."""

import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen


def metadata(config, spool):
    result = {}
    path = Path(config.get("runtime_metadata", "/opt/xray-audit/runtime.json"))
    try:
        if path.stat().st_size <= 8192 and time.time() - path.stat().st_mtime < 900:
            result.update(json.loads(path.read_text()))
    except (OSError, ValueError):
        pass
    cache = spool.state("public_ips", {})
    if time.time() - cache.get("checked_at", 0) >= 21600:
        addresses = {}
        try:
            interfaces = json.loads(
                subprocess.check_output(["ip", "-j", "address", "show", "scope", "global"], timeout=3)
            )
            for interface in interfaces:
                for entry in interface.get("addr_info", []):
                    address = ipaddress.ip_address(entry["local"])
                    if address.is_global and not entry.get("temporary", False):
                        addresses.setdefault("public_ipv" + str(address.version), str(address))
        except (OSError, ValueError, subprocess.SubprocessError, KeyError):
            pass
        # Operators can opt into an HTTPS public-IP endpoint for NAT hosts.
        endpoint = config.get("public_ip_endpoint")
        if endpoint and urlsplit(endpoint).scheme == "https":
            try:
                with urlopen(endpoint, timeout=3) as response:
                    address = ipaddress.ip_address(response.read(100).decode().strip())
                if address.is_global:
                    addresses["public_ipv" + str(address.version)] = str(address)
            except (OSError, ValueError):
                pass
        cache = {"checked_at": time.time(), "addresses": addresses or cache.get("addresses", {})}
        with spool.db:
            spool.set_state("public_ips", cache)
    result.update(cache.get("addresses", {}))
    result.update({key: config[key] for key in ("public_ipv4", "public_ipv6") if config.get(key)})
    return result


def main():
    """Root-only timer. Never expose the Docker socket to the network-facing agent."""
    root = Path("/opt/xray-audit")
    if not root.is_dir():
        return
    running, version = False, "unknown"
    try:
        running = (
            subprocess.check_output(
                ["docker", "inspect", "--format", "{{.State.Running}}", "xray-core"],
                timeout=3,
                stderr=subprocess.DEVNULL,
            ).strip()
            == b"true"
        )
        if running:
            version = (
                subprocess.check_output(
                    ["docker", "exec", "xray-core", "xray", "version"], timeout=3, stderr=subprocess.DEVNULL
                )
                .decode()
                .splitlines()[0]
                .split()[1][:40]
            )
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    import grp

    path = root / "runtime.json"
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as output:
        os.fchown(output.fileno(), -1, grp.getgrnam("xray-audit").gr_gid)
        json.dump({"xray_running": running, "xray_version": version}, output)
    temporary.replace(path)


if __name__ == "__main__":
    main()
