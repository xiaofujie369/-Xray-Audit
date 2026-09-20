#!/usr/bin/env python3
import json
import hashlib
import ipaddress
import shutil
import re
import subprocess
import sys
import time
from pathlib import Path

import requests

ENV_PATH = "/opt/xray-sync/.env"
STATE_PATH = "/opt/xray-sync/report_state.json"
DEFAULT_ACCESS_LOG = "/opt/xray/logs/access.log"


def redact_secrets(value):
    return re.sub(r"(?i)(token=)[^&\s'\")]+", r"\1***", str(value))


def load_env():
    env = {}
    p = Path(ENV_PATH)
    if not p.exists():
        raise RuntimeError(f"配置文件不存在: {ENV_PATH}")

    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def normalize_node_type(t):
    t = str(t).strip().lower()
    aliases = {
        "ss": "shadowsocks",
        "shadow": "shadowsocks",
        "shadowsocks2022": "shadowsocks",
        "v2ray": "vmess",
    }
    return aliases.get(t, t)


def parse_bool(v, default=False):
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)

    s = str(v).strip().lower()
    if s in ["1", "true", "yes", "y", "on", "enable", "enabled"]:
        return True
    if s in ["0", "false", "no", "n", "off", "disable", "disabled"]:
        return False
    return default


def parse_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default


def get_nodes(env):
    nodes = []

    if env.get("NODES"):
        for item in env["NODES"].split(","):
            item = item.strip()
            if not item:
                continue
            if ":" not in item:
                raise RuntimeError(f"NODES format error: {item}; expected node_id:protocol")
            node_id, node_type = item.split(":", 1)
            node_id = node_id.strip()
            node_type = normalize_node_type(node_type.strip())
            if not node_id or not node_type:
                raise RuntimeError(f"NODES format error: {item}; node_id and protocol are required")
            nodes.append((node_id, node_type))
    else:
        nodes.append((env["NODE_ID"], normalize_node_type(env.get("NODE_TYPE", "vless"))))

    if not nodes:
        raise RuntimeError("NODES cannot be empty; expected node_id:protocol")

    return nodes


def run_statsquery():
    cmd = [
        "docker",
        "exec",
        "xray-core",
        "xray",
        "api",
        "statsquery",
        "--server=127.0.0.1:10085",
        "-pattern",
        "user>>>",
        "-reset"
    ]

    p = subprocess.run(cmd, text=True, capture_output=True)

    if p.returncode != 0:
        raise RuntimeError(f"statsquery failed: {p.stderr.strip() or p.stdout.strip()}")

    out = p.stdout.strip()
    if not out:
        return {}

    try:
        return json.loads(out)
    except Exception:
        raise RuntimeError(f"statsquery 返回不是 JSON: {out[:500]}")


def parse_traffic(stats_json):
    """
    Xray 返回：
    {
      "stat": [
        {"name": "user>>>1485>>>traffic>>>uplink", "value": "123"},
        {"name": "user>>>1485>>>traffic>>>downlink", "value": "456"}
      ]
    }

    XBoard 需要：
    {
      "1485": [123, 456]
    }
    """
    stat_list = stats_json.get("stat") or stats_json.get("stats") or []

    traffic = {}

    for item in stat_list:
        name = item.get("name", "")
        value = int(item.get("value", 0) or 0)

        m = re.match(r"^user>>>(.+?)>>>traffic>>>(uplink|downlink)$", name)
        if not m:
            continue

        user_id_raw = m.group(1)
        direction = m.group(2)

        # 我们在 xray_sync.py 里把 email 设置成 XBoard 用户 id，例如 "1485"
        try:
            uid = int(user_id_raw)
        except Exception:
            continue

        if uid not in traffic:
            traffic[uid] = [0, 0]

        if direction == "uplink":
            traffic[uid][0] += value
        elif direction == "downlink":
            traffic[uid][1] += value

    # 删除 0 流量
    traffic = {
        uid: arr for uid, arr in traffic.items()
        if arr[0] > 0 or arr[1] > 0
    }

    return traffic


def split_user_key(user_key):
    if ":" in user_key:
        node_id, user_id_raw = user_key.split(":", 1)
    else:
        node_id = None
        user_id_raw = user_key

    try:
        uid = int(user_id_raw)
    except Exception:
        return None, None

    return node_id, uid


def add_traffic(traffic, uid, direction, value):
    if uid not in traffic:
        traffic[uid] = [0, 0]

    if direction == "uplink":
        traffic[uid][0] += value
    elif direction == "downlink":
        traffic[uid][1] += value


def strip_zero_traffic(traffic):
    return {
        uid: arr for uid, arr in traffic.items()
        if arr[0] > 0 or arr[1] > 0
    }


def parse_traffic_by_node(stats_json):
    stat_list = stats_json.get("stat") or stats_json.get("stats") or []

    scoped = {}
    legacy = {}

    for item in stat_list:
        name = item.get("name", "")
        value = int(item.get("value", 0) or 0)

        m = re.match(r"^user>>>(.+?)>>>traffic>>>(uplink|downlink)$", name)
        if not m:
            continue

        user_key = m.group(1)
        direction = m.group(2)

        node_id, uid = split_user_key(user_key)
        if uid is None:
            continue

        if node_id:
            target = scoped.setdefault(node_id, {})
        else:
            target = legacy

        add_traffic(target, uid, direction, value)

    scoped = {
        node_id: strip_zero_traffic(traffic)
        for node_id, traffic in scoped.items()
    }
    scoped = {node_id: traffic for node_id, traffic in scoped.items() if traffic}

    return scoped, strip_zero_traffic(legacy)


def extract_user_key_from_access_line(line):
    patterns = [
        r"email:\s*([^\s\]]+)",
        r"\[([0-9]+(?::[0-9]+)?)\]",
    ]
    for pattern in patterns:
        m = re.search(pattern, line)
        if m:
            return m.group(1)
    return None


def extract_ip_from_access_line(line):
    # Only the source endpoint immediately before the decision is a client IP.
    match = re.search(r"(?:^|\s)(?:tcp:|udp:)?(\S+)\s+(?:accepted|rejected)\s", line)
    if not match:
        return None
    host, separator, port = match[1].rpartition(":")
    if not separator or not port.isdecimal():
        return None
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        return str(getattr(address, "ipv4_mapped", None) or address)
    except ValueError:
        return None


def parse_alive_from_access_lines(lines):
    scoped = {}
    legacy = {}

    for line in lines:
        user_key = extract_user_key_from_access_line(line)
        ip = extract_ip_from_access_line(line)
        if not user_key or not ip:
            continue

        node_id, uid = split_user_key(user_key)
        if uid is None:
            continue

        if node_id:
            target = scoped.setdefault(node_id, {})
        else:
            target = legacy

        target.setdefault(uid, set()).add(ip)

    def freeze(data):
        return {
            uid: sorted(ips)
            for uid, ips in data.items()
            if ips
        }

    scoped = {
        node_id: freeze(alive)
        for node_id, alive in scoped.items()
    }
    scoped = {node_id: alive for node_id, alive in scoped.items() if alive}

    return scoped, freeze(legacy)


def load_state(path):
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def save_state(path, state):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, ensure_ascii=False, indent=2))


def read_access_log_since(env):
    access_log = env.get("XRAY_ACCESS_LOG", DEFAULT_ACCESS_LOG)
    state_path = env.get("REPORT_STATE", STATE_PATH)
    log_path = Path(access_log)

    if not log_path.exists():
        return {}, {}

    state = load_state(state_path)
    log_state = state.get("access_log", {})

    stat = log_path.stat()
    size = stat.st_size
    identity = [stat.st_dev, stat.st_ino]
    offset = int(log_state.get("offset", 0) or 0)
    if offset < 0 or offset > size or log_state.get("identity", identity) != identity:
        offset = 0

    skipping = log_state.get("skipping_long_line", False) if offset else False
    with log_path.open("rb") as f:
        if offset and log_state.get("anchor"):
            f.seek(max(0, offset - 128))
            if hashlib.sha256(f.read(min(offset, 128))).hexdigest() != log_state["anchor"]:
                offset, skipping = 0, False
        f.seek(offset)
        lines = []
        for _ in range(100000):
            position = f.tell()
            if position - offset >= 8 * 1024 * 1024:
                break
            raw = f.readline(16385)
            if not raw:
                break
            if skipping or len(raw) > 16384:
                skipping = not raw.endswith(b"\n")
                continue
            if not raw.endswith(b"\n"):
                f.seek(position)
                break
            lines.append(raw.decode("utf-8", errors="ignore"))
        new_offset = f.tell()
        f.seek(max(0, new_offset - 128))
        anchor = hashlib.sha256(f.read(min(new_offset, 128))).hexdigest()

    state["access_log"] = {
        "path": str(log_path),
        "offset": new_offset,
        "size": size,
        "identity": identity,
        "anchor": anchor,
        "skipping_long_line": skipping,
    }
    save_state(state_path, state)

    return parse_alive_from_access_lines(lines)


def report_state_path(env):
    return env.get("REPORT_STATE", STATE_PATH)


def configured_node_ids(nodes):
    return {node_id for node_id, _node_type in nodes}


def refresh_online_cache(env, scoped_alive, nodes, now=None):
    ttl = max(0, parse_int(env.get("REPORT_ONLINE_TTL", "180"), default=180))
    now = int(time.time() if now is None else now)
    state_path = report_state_path(env)
    state = load_state(state_path)
    online_state = state.setdefault("online", {})
    node_state = online_state.setdefault("nodes", {})
    active = {}
    configured = configured_node_ids(nodes)

    for node_id in list(node_state.keys()):
        if node_id not in configured:
            del node_state[node_id]

    for node_id, alive in scoped_alive.items():
        users = node_state.setdefault(node_id, {})
        for uid, ips in alive.items():
            users[str(uid)] = {
                "last_seen": now,
                "ips": sorted(set(ips)),
            }

    for node_id in configured:
        users = node_state.get(node_id, {})
        kept = {}
        for uid_raw, item in users.items():
            try:
                last_seen = int(item.get("last_seen", 0) or 0)
                uid = int(uid_raw)
            except Exception:
                continue

            if now - last_seen > ttl:
                continue

            ips = item.get("ips") or []
            if ips:
                kept[str(uid)] = {"last_seen": last_seen, "ips": sorted(set(ips))}
                active.setdefault(node_id, {})[uid] = sorted(set(ips))

        if kept:
            node_state[node_id] = kept
        else:
            node_state.pop(node_id, None)

    online_state["ttl"] = ttl
    save_state(state_path, state)
    return active


def merge_legacy_map(scoped, legacy, nodes, label):
    if not legacy:
        return

    if len(nodes) != 1:
        print(f"[report] skipped legacy unscoped {label} because multiple NODES are configured")
        return

    node_id = nodes[0][0]
    target = scoped.setdefault(node_id, {})
    for uid, values in legacy.items():
        if uid not in target:
            target[uid] = values
        elif isinstance(values, list) and values and isinstance(values[0], int):
            target[uid][0] += values[0]
            target[uid][1] += values[1]
        else:
            target[uid] = sorted(set(target[uid]) | set(values))


def include_alive_users_in_traffic(scoped_traffic, scoped_alive):
    for node_id, alive in scoped_alive.items():
        traffic = scoped_traffic.setdefault(node_id, {})
        for uid in alive:
            traffic.setdefault(uid, [0, 0])


def to_panel_int(value):
    try:
        return int(value)
    except Exception:
        return value


def payload_with_string_keys(data):
    return {str(k): v for k, v in data.items()}


def alive_to_online(alive):
    return {
        uid: len(set(ips))
        for uid, ips in alive.items()
        if ips
    }


def read_cpu_snapshot(path="/proc/stat"):
    try:
        line = Path(path).read_text().splitlines()[0]
    except Exception:
        return None

    parts = line.split()
    if not parts or parts[0] != "cpu":
        return None

    values = []
    for item in parts[1:]:
        try:
            values.append(int(item))
        except Exception:
            values.append(0)

    if len(values) < 4:
        return None

    idle = values[3] + (values[4] if len(values) > 4 else 0)
    total = sum(values)
    return total, idle


def collect_cpu_percent():
    first = read_cpu_snapshot()
    if not first:
        return 0.0

    time.sleep(0.1)

    second = read_cpu_snapshot()
    if not second:
        return 0.0

    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return 0.0

    return round(max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100)), 2)


def collect_memory_status(path="/proc/meminfo"):
    try:
        lines = Path(path).read_text().splitlines()
    except Exception:
        return (0, 0), (0, 0)

    values = {}
    for line in lines:
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if not parts:
            continue
        try:
            values[key] = int(parts[0]) * 1024
        except Exception:
            continue

    mem_total = values.get("MemTotal", 0)
    mem_available = values.get("MemAvailable", values.get("MemFree", 0))
    swap_total = values.get("SwapTotal", 0)
    swap_free = values.get("SwapFree", 0)

    mem_used = max(0, mem_total - mem_available)
    swap_used = max(0, swap_total - swap_free)
    return (mem_total, mem_used), (swap_total, swap_used)


def collect_disk_status(path="/"):
    try:
        usage = shutil.disk_usage(path)
        return usage.total, usage.used
    except Exception:
        return 0, 0


def collect_status():
    mem, swap = collect_memory_status()
    disk = collect_disk_status()
    return {
        "cpu": collect_cpu_percent(),
        "mem": {"total": mem[0], "used": mem[1]},
        "swap": {"total": swap[0], "used": swap[1]},
        "disk": {"total": disk[0], "used": disk[1]},
    }


def build_v2_report_payload(env, node_id, node_type, traffic, alive, status):
    payload = {
        "token": env["PANEL_TOKEN"],
        "node_id": to_panel_int(node_id),
        "node_type": node_type,
        "status": status,
    }

    if traffic:
        payload["traffic"] = payload_with_string_keys(traffic)

    if alive:
        payload["alive"] = payload_with_string_keys(alive)
        online = alive_to_online(alive)
        if online:
            payload["online"] = payload_with_string_keys(online)

    if parse_bool(env.get("REPORT_KERNEL_STATUS", "true"), default=True):
        payload["metrics"] = {"kernel_status": True}

    return payload


def post_report_v2(env, node_id, node_type, traffic, alive, status):
    panel = env["PANEL_URL"].rstrip("/")
    url = f"{panel}/api/v2/server/report"
    payload = build_v2_report_payload(env, node_id, node_type, traffic, alive, status)

    r = requests.post(url, json=payload, timeout=25)

    try:
        resp = r.json()
    except Exception:
        resp = r.text[:500]

    if r.status_code >= 400:
        raise RuntimeError(f"v2 report failed HTTP {r.status_code}")

    print(
        f"[report] posted v2 report for node {node_id}:{node_type}: "
        f"traffic={len(traffic)}, alive={len(alive)}, online={len(alive_to_online(alive))}, status=1"
    )


def post_traffic(env, node_id, node_type, traffic):
    if not traffic:
        print(f"[report] node {node_id}:{node_type} has no traffic to push")
        return

    panel = env["PANEL_URL"].rstrip("/")
    token = env["PANEL_TOKEN"]

    url = f"{panel}/api/v1/server/UniProxy/push?node_id={node_id}&node_type={node_type}&token={token}"

    r = requests.post(url, json=traffic, timeout=25)

    try:
        resp = r.json()
    except Exception:
        resp = r.text[:500]

    if r.status_code >= 400:
        raise RuntimeError(f"push failed HTTP {r.status_code}")

    print(f"[report] pushed traffic for {len(traffic)} users on node {node_id}:{node_type}")


def post_alive(env, node_id, node_type, alive):
    if not alive:
        print(f"[report] node {node_id}:{node_type} has no alive users to push")
        return

    panel = env["PANEL_URL"].rstrip("/")
    token = env["PANEL_TOKEN"]

    url = f"{panel}/api/v1/server/UniProxy/alive?node_id={node_id}&node_type={node_type}&token={token}"

    r = requests.post(url, json=alive, timeout=25)

    try:
        resp = r.json()
    except Exception:
        resp = r.text[:500]

    if r.status_code >= 400:
        raise RuntimeError(f"alive failed HTTP {r.status_code}")

    print(f"[report] pushed alive devices for {len(alive)} users on node {node_id}:{node_type}")


def post_status_legacy(env, node_id, node_type, status):
    panel = env["PANEL_URL"].rstrip("/")
    token = env["PANEL_TOKEN"]

    url = f"{panel}/api/v1/server/UniProxy/status?node_id={node_id}&node_type={node_type}&token={token}"

    r = requests.post(url, json=status, timeout=25)

    try:
        resp = r.json()
    except Exception:
        resp = r.text[:500]

    if r.status_code >= 400:
        raise RuntimeError(f"legacy status failed HTTP {r.status_code}")

    print(f"[report] pushed legacy status for node {node_id}:{node_type}")


def post_node_report(env, node_id, node_type, traffic, alive, status):
    if parse_bool(env.get("REPORT_USE_V2_REPORT", "true"), default=True):
        try:
            post_report_v2(env, node_id, node_type, traffic, alive, status)
            return
        except Exception as e:
            if not parse_bool(env.get("REPORT_V2_FALLBACK", "true"), default=True):
                raise
            print(f"[report] v2 report failed for node {node_id}:{node_type}, using legacy fallback: {redact_secrets(e)}")

    post_traffic(env, node_id, node_type, traffic)
    post_alive(env, node_id, node_type, alive)
    post_status_legacy(env, node_id, node_type, status)


def main():
    env = load_env()
    nodes = get_nodes(env)
    stats = run_statsquery()
    scoped_traffic, legacy_traffic = parse_traffic_by_node(stats)
    scoped_alive, legacy_alive = read_access_log_since(env)

    merge_legacy_map(scoped_traffic, legacy_traffic, nodes, "traffic")
    # Optional local copy: no network and no second Stats API reset.
    if Path("/opt/xray-audit/traffic-inbox").is_dir():
        try:
            from audit_bridge import copy_interval
            copy_interval(scoped_traffic)
        except Exception:
            pass
    merge_legacy_map(scoped_alive, legacy_alive, nodes, "alive users")
    active_alive = refresh_online_cache(env, scoped_alive, nodes)
    include_alive_users_in_traffic(scoped_traffic, active_alive)

    status = collect_status()

    for node_id, node_type in nodes:
        post_node_report(
            env,
            node_id,
            node_type,
            scoped_traffic.get(node_id, {}),
            active_alive.get(node_id, {}),
            status,
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[report] ERROR: {redact_secrets(e)}", file=sys.stderr)
        sys.exit(1)
