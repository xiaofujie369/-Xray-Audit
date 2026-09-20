#!/usr/bin/env python3
import sys
import json
import copy
import ipaddress
import time
import hashlib
import glob
import os
import re
import shutil
import subprocess
from pathlib import Path

import requests

ENV_PATH = "/opt/xray-sync/.env"
HOST_CERT_DIR = "/opt/xray/config/certs"
CONTAINER_CERT_DIR = "/etc/xray/certs"


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


def get_nodes(env):
    """
    推荐格式：
    NODES=3047:vless,8881:shadowsocks,8882:trojan,8883:vmess

    兼容旧格式：
    NODE_ID=3047
    NODE_TYPE=vless
    """
    nodes = []

    if env.get("NODES"):
        for item in env["NODES"].split(","):
            item = item.strip()
            if not item:
                continue
            if ":" not in item:
                raise RuntimeError(f"NODES 格式错误: {item}，正确格式是 节点ID:协议")
            node_id, node_type = item.split(":", 1)
            node_id = node_id.strip()
            node_type = normalize_node_type(node_type.strip())
            if not node_id or not node_type:
                raise RuntimeError(f"NODES 格式错误: {item}，节点ID和协议不能为空")
            nodes.append((node_id, node_type))
    else:
        nodes.append((env["NODE_ID"], normalize_node_type(env.get("NODE_TYPE", "vless"))))

    if not nodes:
        raise RuntimeError("NODES 不能为空，正确格式是 节点ID:协议")

    return nodes


def normalize_node_type(t):
    t = str(t).strip().lower()
    aliases = {
        "ss": "shadowsocks",
        "shadow": "shadowsocks",
        "shadowsocks2022": "shadowsocks",
        "v2ray": "vmess",
    }
    return aliases.get(t, t)


def stats_email(user_id, node_id=None):
    user_id = str(user_id)
    if node_id not in [None, ""]:
        return f"{node_id}:{user_id}"
    return user_id


def redact_secrets(text):
    return re.sub(r"([?&]token=)[^&\s]+", r"\1***", str(text))


def get_json(url):
    last_error = None
    for attempt in range(1, 4):
        try:
            r = requests.get(url, timeout=25)
            try:
                data = r.json()
            except Exception:
                raise RuntimeError(f"接口返回不是 JSON: HTTP {r.status_code}, {r.text[:500]}")

            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}: {json.dumps(data, ensure_ascii=False)[:800]}")

            return data
        except Exception as e:
            last_error = redact_secrets(e)
            if attempt < 3:
                print(f"[sync] API 请求失败，准备重试 {attempt}/3: {redact_secrets(e)}", flush=True)
                time.sleep(2)

    raise RuntimeError(f"API 请求失败: {last_error}")


def pick(d, *keys, default=None):
    if not isinstance(d, dict):
        return default
    for k in keys:
        if k in d and d[k] not in [None, ""]:
            return d[k]
    return default


def is_present(v):
    return v not in [None, "", [], {}]


def get_path(d, path, default=None):
    d = parse_json_maybe(d)
    if not isinstance(d, dict):
        return default

    if path in d:
        return d[path]

    cur = d
    for part in str(path).split("."):
        cur = parse_json_maybe(cur)
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]

    return cur


def pick_path(d, *paths, default=None):
    for path in paths:
        v = get_path(d, path, default=None)
        if is_present(v):
            return v
    return default


def as_dict(v):
    v = parse_json_maybe(v)
    return v if isinstance(v, dict) else {}


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


def compact_list(v):
    v = parse_json_maybe(v)
    if isinstance(v, list):
        return [str(x).strip() for x in v if is_present(x)]
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return []
        if "," in s:
            return [x.strip() for x in s.split(",") if x.strip()]
        return [s]
    if is_present(v):
        return [str(v)]
    return []


def first_list_value(v):
    items = compact_list(v)
    return items[0] if items else None


def parse_json_maybe(v):
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return v
        if s.startswith("{") or s.startswith("["):
            try:
                return json.loads(s)
            except Exception:
                return v
    return v


def unwrap_config(resp):
    if isinstance(resp, dict) and isinstance(resp.get("data"), dict):
        return resp["data"]
    return resp


def get_users_list(user_resp):
    if isinstance(user_resp, dict):
        if isinstance(user_resp.get("users"), list):
            return user_resp["users"]
        if isinstance(user_resp.get("data"), list):
            return user_resp["data"]
        if isinstance(user_resp.get("data"), dict):
            d = user_resp["data"]
            if isinstance(d.get("users"), list):
                return d["users"]

    if isinstance(user_resp, list):
        return user_resp

    return []


def get_server_port(server, default=443):
    return int(pick(server, "server_port", "port", "listen_port", default=default))


def get_listen_ip(server):
    return str(pick(server, "listen_ip", "listen", default="0.0.0.0"))


def get_network(server):
    return str(pick(server, "network", default="tcp") or "tcp").lower()


def get_network_settings(server):
    ns = pick_path(server, "networkSettings", "network_settings", "protocol_settings.network_settings", "protocolSettings.network_settings", default={})
    ns = parse_json_maybe(ns)
    return ns if isinstance(ns, dict) else {}


def get_tls_settings(server):
    ts = pick_path(server, "tls_settings", "tlsSettings", "tls", "protocol_settings.tls_settings", "protocolSettings.tls_settings", "protocol_settings.tls", "protocolSettings.tls", default={})
    ts = parse_json_maybe(ts)
    return ts if isinstance(ts, dict) else {}


def normalize_short_ids(v):
    v = parse_json_maybe(v)

    if v is None or v == "":
        return [""]

    if isinstance(v, list):
        return [str(x) for x in v]

    if isinstance(v, str):
        if "," in v:
            return [x.strip() for x in v.split(",") if x.strip()]
        return [v]

    return [str(v)]


def normalize_lookup_key(k):
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def iter_config_dicts(v, max_depth=5):
    if max_depth < 0:
        return

    v = parse_json_maybe(v)

    if isinstance(v, dict):
        yield v
        for child in v.values():
            yield from iter_config_dicts(child, max_depth=max_depth - 1)
    elif isinstance(v, list):
        for child in v:
            yield from iter_config_dicts(child, max_depth=max_depth - 1)


def pick_from_configs(configs, keys, default=None):
    wanted = {normalize_lookup_key(k) for k in keys}
    for cfg in configs:
        for item in iter_config_dicts(cfg):
            for k, v in item.items():
                if normalize_lookup_key(k) in wanted and v not in [None, ""]:
                    return v
    return default


def safe_cert_filename(name):
    raw = str(name or "node-unknown").strip()
    raw = raw.replace("*", "wildcard")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    safe = re.sub(r"\.+", ".", safe)
    safe = safe.strip("._-")
    if not safe:
        safe = "node-unknown"
    if safe in [".", ".."]:
        safe = "node-unknown"
    return safe[:128]


def cert_paths_for_name(name):
    base = Path(HOST_CERT_DIR).resolve()
    cert_path = (base / f"{name}.crt").resolve()
    key_path = (base / f"{name}.key").resolve()

    for path in [cert_path, key_path]:
        if base != path.parent and base not in path.parents:
            raise RuntimeError(f"Refusing unsafe certificate path: {path}")

    return cert_path, key_path


def normalize_pem_text(value):
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    return text + "\n"


def normalize_multiline_secret(value):
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    return text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n").strip()


def normalize_ech_config_list(value):
    text = normalize_multiline_secret(value)
    if not text:
        return None

    match = re.search(r"-----BEGIN ECH CONFIGS-----\s*(.*?)\s*-----END ECH CONFIGS-----", text, re.S)
    if match:
        return re.sub(r"\s+", "", match.group(1))

    return re.sub(r"\s+", "", text) if text.startswith("AF") or "\n" in text else text


def is_certificate_pem(text):
    return (
        isinstance(text, str)
        and "-----BEGIN CERTIFICATE-----" in text
        and "-----END CERTIFICATE-----" in text
    )


def is_private_key_pem(text):
    return (
        isinstance(text, str)
        and re.search(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", text) is not None
        and re.search(r"-----END [A-Z0-9 ]*PRIVATE KEY-----", text) is not None
    )


def ensure_cert_dir():
    Path(HOST_CERT_DIR).mkdir(parents=True, exist_ok=True)
    os.chmod(HOST_CERT_DIR, 0o755)


def write_text_if_changed(path, text, mode=0o644):
    path = Path(path)
    old_text = path.read_text(errors="ignore") if path.exists() else None
    if old_text == text:
        os.chmod(path, mode)
        return False

    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)
    os.chmod(path, mode)
    return True


def copy_file_if_changed(src, dst, mode=0o644):
    src = Path(src)
    dst = Path(dst)
    new_data = src.read_bytes()
    if dst.exists() and dst.read_bytes() == new_data:
        os.chmod(dst, mode)
        return False

    tmp = dst.with_name(f".{dst.name}.tmp")
    tmp.write_bytes(new_data)
    os.chmod(tmp, mode)
    tmp.replace(dst)
    os.chmod(dst, mode)
    return True


def container_cert_pair(name):
    return {
        "certificateFile": f"{CONTAINER_CERT_DIR}/{name}.crt",
        "keyFile": f"{CONTAINER_CERT_DIR}/{name}.key"
    }


SERVER_NAME_KEYS = [
    "server_name",
    "serverName",
    "sni",
    "cert_domain",
    "certDomain",
    "domain",
    "host",
]

CERT_CONTENT_KEYS = [
    "cert",
    "crt",
    "certificate",
    "public_key",
    "publicKey",
    "public",
    "certificate_content",
    "certificateContent",
    "cert_content",
    "certContent",
    "tls_certificate",
    "tlsCertificate",
]

KEY_CONTENT_KEYS = [
    "key",
    "private",
    "private_key",
    "privateKey",
    "private_key_content",
    "privateKeyContent",
    "key_content",
    "keyContent",
    "tls_key",
    "tlsKey",
]

CERT_FILE_KEYS = [
    "cert_file",
    "certFile",
    "certificate_file",
    "certificateFile",
    "cert_path",
    "certPath",
    "certificate_path",
    "certificatePath",
]

KEY_FILE_KEYS = [
    "key_file",
    "keyFile",
    "private_key_file",
    "privateKeyFile",
    "key_path",
    "keyPath",
    "private_key_path",
    "privateKeyPath",
]


KNOWN_TLS_FINGERPRINTS = {
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "unsafe",
}


def normalize_tls_fingerprint(value):
    if not is_present(value):
        return None

    fp = str(value).strip()
    low = fp.lower()
    if low in KNOWN_TLS_FINGERPRINTS:
        return low
    return fp


def get_tls_fingerprint(server, tls_settings):
    utls = pick_path(
        server,
        "utls",
        "uTLS",
        "tls_utls",
        "tlsUTLS",
        "protocol_settings.utls",
        "protocolSettings.utls",
        default=None,
    )
    if not is_present(utls):
        utls = pick(tls_settings, "utls", "uTLS", default=None)

    utls = parse_json_maybe(utls)
    if isinstance(utls, dict):
        enabled = parse_bool(pick(utls, "enabled", "enable", default=None), default=None)
        if enabled is False:
            return None

        fp = pick(utls, "fingerprint", "fp", "client_fingerprint", "clientFingerprint", default=None)
        if is_present(fp):
            return normalize_tls_fingerprint(fp)

        if enabled is True:
            return "chrome"

    elif is_present(utls):
        return normalize_tls_fingerprint(utls)

    fp = pick_from_configs(
        [tls_settings, server],
        ["fingerprint", "fp", "client_fingerprint", "clientFingerprint", "tls_fingerprint", "tlsFingerprint"],
    )
    return normalize_tls_fingerprint(fp)


def get_ech_settings(tls_settings):
    ech = pick(tls_settings, "ech", "ech_settings", "echSettings", default=None)
    ech = parse_json_maybe(ech)
    if isinstance(ech, dict):
        enabled = parse_bool(pick(ech, "enabled", "enable", default=None), default=None)
        if enabled is False:
            return {}
        return ech
    return {}


def add_if_present(dst, key, value):
    if is_present(value):
        dst[key] = value


def add_bool_if_true(dst, key, value):
    if parse_bool(value, default=False):
        dst[key] = True


def add_common_tls_options(dst, server, tls_settings):
    fp = get_tls_fingerprint(server, tls_settings)
    if fp:
        dst["fingerprint"] = fp

    add_bool_if_true(dst, "rejectUnknownSni", pick(tls_settings, "reject_unknown_sni", "rejectUnknownSni", default=None))
    add_bool_if_true(dst, "disableSystemRoot", pick(tls_settings, "disable_system_root", "disableSystemRoot", default=None))
    add_bool_if_true(
        dst,
        "enableSessionResumption",
        pick(tls_settings, "enable_session_resumption", "enableSessionResumption", default=None),
    )

    optional_string_fields = {
        "verifyPeerCertByName": ["verify_peer_cert_by_name", "verifyPeerCertByName"],
        "minVersion": ["min_version", "minVersion"],
        "maxVersion": ["max_version", "maxVersion"],
        "cipherSuites": ["cipher_suites", "cipherSuites"],
        "pinnedPeerCertSha256": ["pinned_peer_cert_sha256", "pinnedPeerCertSha256"],
        "masterKeyLog": ["master_key_log", "masterKeyLog"],
    }
    for out_key, in_keys in optional_string_fields.items():
        add_if_present(dst, out_key, pick(tls_settings, *in_keys, default=None))

    alpn = compact_list(pick(tls_settings, "alpn", "ALPN", default=None))
    if alpn:
        dst["alpn"] = alpn

    curves = compact_list(pick(tls_settings, "curve_preferences", "curvePreferences", default=None))
    if curves:
        dst["curvePreferences"] = curves

    ech = get_ech_settings(tls_settings)
    ech_key = pick(ech, "key", "server_key", "serverKey", "echServerKeys", default=None)
    if not is_present(ech_key):
        ech_key = pick(tls_settings, "ech_server_keys", "echServerKeys", default=None)
    ech_key = normalize_multiline_secret(ech_key)
    if ech_key:
        dst["echServerKeys"] = ech_key

    ech_config = pick(ech, "config", "config_list", "configList", "echConfigList", default=None)
    if not is_present(ech_config):
        ech_config = pick(tls_settings, "ech_config_list", "echConfigList", default=None)
    ech_config = normalize_ech_config_list(ech_config)
    if ech_config:
        dst["echConfigList"] = ech_config


def resolve_tls_certificate(server, tls_settings, server_name):
    cert_config = pick(server, "cert_config", "certConfig", default={})
    cert_config = parse_json_maybe(cert_config)
    cert_sources = [cert_config, tls_settings, server]

    node_id = pick(server, "id", "node_id", "nodeId", "NodeID", "server_id", "serverId")
    safe_name = safe_cert_filename(server_name or f"node-{node_id or 'unknown'}")
    cert_path, key_path = cert_paths_for_name(safe_name)

    ensure_cert_dir()

    cert_file = pick_from_configs(cert_sources, CERT_FILE_KEYS)
    key_file = pick_from_configs(cert_sources, KEY_FILE_KEYS)

    if cert_file and key_file:
        cert_file_s = str(cert_file)
        key_file_s = str(key_file)

        if os.path.exists(cert_file_s) and os.path.exists(key_file_s):
            cert_changed = copy_file_if_changed(cert_file_s, cert_path)
            key_changed = copy_file_if_changed(key_file_s, key_path)
            if cert_changed or key_changed:
                print(f"[sync] TLS certificate files installed for {safe_name}", flush=True)
            else:
                print(f"[sync] TLS certificate files already current for {safe_name}", flush=True)
            return container_cert_pair(safe_name)

        print(f"[sync] TLS certificate uses panel-provided paths for {safe_name}", flush=True)
        return {
            "certificateFile": cert_file_s,
            "keyFile": key_file_s
        }

    cert_content = normalize_pem_text(pick_from_configs(cert_sources, CERT_CONTENT_KEYS))
    key_content = normalize_pem_text(pick_from_configs(cert_sources, KEY_CONTENT_KEYS))

    if cert_content or key_content:
        if is_certificate_pem(cert_content) and is_private_key_pem(key_content):
            cert_changed = write_text_if_changed(cert_path, cert_content)
            key_changed = write_text_if_changed(key_path, key_content)
            if cert_changed or key_changed:
                print(f"[sync] TLS certificate content written for {safe_name}", flush=True)
            else:
                print(f"[sync] TLS certificate content already current for {safe_name}", flush=True)
            return container_cert_pair(safe_name)

        print(f"[sync] TLS certificate content from panel is incomplete or invalid for {safe_name}", flush=True)

    if cert_path.exists() and key_path.exists():
        os.chmod(cert_path, 0o644)
        os.chmod(key_path, 0o644)
        print(f"[sync] TLS using existing local certificate fallback for {safe_name}", flush=True)
        return container_cert_pair(safe_name)

    candidates = []

    if node_id:
        candidates += glob.glob(f"/etc/xboard-node/instances/*/node-{node_id}/certs/cert.pem")

    candidates += glob.glob("/etc/xboard-node/instances/*/node-*/certs/cert.pem")

    for c in candidates:
        k = os.path.join(os.path.dirname(c), "key.pem")
        if os.path.exists(c) and os.path.exists(k):
            cert_changed = copy_file_if_changed(c, cert_path)
            key_changed = copy_file_if_changed(k, key_path)
            if cert_changed or key_changed:
                print(f"[sync] TLS certificate copied from xboard-node fallback for {safe_name}", flush=True)
            else:
                print(f"[sync] TLS xboard-node fallback certificate already current for {safe_name}", flush=True)
            return container_cert_pair(safe_name)

    print(f"[sync] TLS enabled but no certificate is available for {safe_name}", flush=True)
    return None


def build_stream_settings(server):
    """
    统一处理 Xray streamSettings:
    - tcp
    - ws
    - grpc
    - httpupgrade
    - reality
    - tls
    """
    network = get_network(server)
    ns = get_network_settings(server)
    ts = get_tls_settings(server)

    tls_mode = pick(server, "tls", default=0)
    try:
        tls_mode = int(tls_mode)
    except Exception:
        tls_mode = 0

    stream = {
        "network": network
    }

    # -------- transport settings --------
    if network == "ws":
        path = pick(ns, "path", default="/")
        host = pick_path(ns, "headers.Host", "header.request.headers.Host", "host", "Host", default=None)

        ws_settings = {
            "path": str(path)
        }

        if host:
            ws_settings["headers"] = {
                "Host": str(first_list_value(host) or host)
            }

        stream["wsSettings"] = ws_settings

    elif network == "grpc":
        service_name = pick(ns, "serviceName", "service_name", default="")
        stream["grpcSettings"] = {
            "serviceName": str(service_name)
        }

    elif network == "httpupgrade":
        path = pick(ns, "path", default="/")
        host = pick_path(ns, "headers.Host", "host", "Host", default=None)

        httpupgrade_settings = {
            "path": str(path)
        }

        if host:
            httpupgrade_settings["host"] = str(host)

        stream["httpupgradeSettings"] = httpupgrade_settings

    elif network == "tcp":
        header = as_dict(pick(ns, "header", default={}))
        if header and pick(header, "type", default="none") != "none":
            stream["tcpSettings"] = {"header": header}

    elif network in ["h2", "http"]:
        stream["network"] = "http"
        http_settings = {}
        path = pick(ns, "path", default=None)
        host = compact_list(pick(ns, "host", "Host", default=None))
        add_if_present(http_settings, "path", path)
        if host:
            http_settings["host"] = host
        if http_settings:
            stream["httpSettings"] = http_settings

    elif network == "xhttp":
        xhttp_settings = {}
        for key in ["path", "mode", "host"]:
            add_if_present(xhttp_settings, key, pick(ns, key, default=None))
        headers = as_dict(pick(ns, "headers", default={}))
        if headers:
            xhttp_settings["headers"] = headers
        extra = pick(ns, "extra", default=None)
        extra = parse_json_maybe(extra)
        if is_present(extra):
            xhttp_settings["extra"] = extra
        if xhttp_settings:
            stream["xhttpSettings"] = xhttp_settings

    elif network in ["kcp", "mkcp"]:
        stream["network"] = "kcp"
        if ns:
            stream["kcpSettings"] = ns

    else:
        # Xray 可能支持更多 network，但这里不主动生成未知结构
        stream["network"] = network

    # -------- security settings --------
    # XBoard 常见：
    # tls = 0 无
    # tls = 1 TLS
    # tls = 2 Reality
    #
    # Reality 字段：
    # tls_settings.server_name
    # tls_settings.server_port
    # tls_settings.private_key
    # tls_settings.short_id

    private_key = pick(ts, "private_key", "privateKey")
    short_id = pick(ts, "short_id", "shortId", "short_ids", "shortIds")
    server_name = pick(ts, "server_name", "serverName", "sni")
    reality_port = pick(ts, "server_port", "serverPort", default="443")
    if not server_name:
        cert_config = parse_json_maybe(pick(server, "cert_config", "certConfig", default={}))
        server_name = pick_from_configs([cert_config, server], SERVER_NAME_KEYS)

    private_key_is_pem = isinstance(private_key, str) and "BEGIN" in private_key
    if tls_mode == 2 or (private_key and not private_key_is_pem and tls_mode != 1):
        if not server_name:
            raise RuntimeError("Reality 缺少 tls_settings.server_name")
        if not private_key:
            raise RuntimeError("Reality 缺少 tls_settings.private_key")
        if short_id is None:
            raise RuntimeError("Reality 缺少 tls_settings.short_id")

        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": False,
            "dest": f"{server_name}:{reality_port}",
            "xver": 0,
            "serverNames": [
                str(server_name)
            ],
            "privateKey": str(private_key),
            "shortIds": normalize_short_ids(short_id)
        }
        for out_key, in_keys in {
            "minClientVer": ["min_client_ver", "minClientVer"],
            "maxClientVer": ["max_client_ver", "maxClientVer"],
            "mldsa65Seed": ["mldsa65_seed", "mldsa65Seed"],
        }.items():
            add_if_present(stream["realitySettings"], out_key, pick(ts, *in_keys, default=None))

        max_time_diff = pick(ts, "max_time_diff", "maxTimeDiff", default=None)
        if is_present(max_time_diff):
            stream["realitySettings"]["maxTimeDiff"] = int(max_time_diff)

        for key in ["limitFallbackUpload", "limitFallbackDownload"]:
            value = as_dict(pick(ts, key, key[0].lower() + key[1:], default={}))
            if value:
                stream["realitySettings"][key] = value

    elif tls_mode == 1:
        stream["security"] = "tls"
        tls_settings = {
            "serverName": str(server_name or "")
        }
        add_common_tls_options(tls_settings, server, ts)

        cert_pair = resolve_tls_certificate(server, ts, server_name)
        if cert_pair:
            tls_settings["certificates"] = [cert_pair]

        stream["tlsSettings"] = tls_settings

    else:
        stream["security"] = "none"

    return stream



def ensure_list(v):
    v = parse_json_maybe(v)

    if v is None or v == "":
        return []

    if isinstance(v, list):
        return v

    if isinstance(v, dict):
        return [v]

    return []


def ensure_str_list(v):
    v = parse_json_maybe(v)

    if v is None or v == "":
        return []

    if isinstance(v, list):
        items = v
    else:
        items = re.split(r"[\r\n]+", str(v))

    result = []
    for item in items:
        item = str(item).strip()
        if item:
            result.append(item)

    return result


def extract_custom_outbounds(server):
    """
    Read per-node custom outbounds from XBoard.
    Supported field names:
    - custom_outbounds
    - customOutbounds
    - outbounds
    """
    if not isinstance(server, dict):
        return []

    for key in ["custom_outbounds", "customOutbounds", "outbounds"]:
        val = server.get(key)
        items = ensure_list(val)
        if not items:
            continue

        valid = []
        for item in items:
            if isinstance(item, dict) and item.get("tag") and item.get("protocol"):
                valid.append(item)

        if valid:
            return valid

    return []


def safe_tag_part(value):
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip())
    return value.strip("-") or "node"


def scoped_custom_outbound_tag(node_id, tag):
    return f"node-{safe_tag_part(node_id)}-{safe_tag_part(tag)}"


def scope_custom_outbounds(outbounds, node_id):
    scoped = []
    tag_map = {}

    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue

        old_tag = str(outbound.get("tag", "")).strip()
        if not old_tag:
            continue

        new_tag = scoped_custom_outbound_tag(node_id, old_tag)
        item = copy.deepcopy(outbound)
        item["tag"] = new_tag
        scoped.append(item)
        tag_map[old_tag] = new_tag

    return scoped, tag_map


def as_string_list(value):
    value = parse_json_maybe(value)
    if value in [None, ""]:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value).strip()] if str(value).strip() else []


def route_applies_to_inbound(route, inbound_tag):
    if not inbound_tag:
        return True
    if "inboundTag" not in route:
        return True
    return inbound_tag in as_string_list(route.get("inboundTag"))


def allowed_outbound_tags(outbound_tag_map=None):
    return {"direct", "block"} | set((outbound_tag_map or {}).values())


def is_allowed_outbound_tag(tag, outbound_tag_map=None):
    return tag in allowed_outbound_tags(outbound_tag_map)


def rewrite_route_for_node(route, inbound_tag=None, outbound_tag_map=None):
    if not isinstance(route, dict):
        return None

    rr = copy.deepcopy(route)

    if inbound_tag and not route_applies_to_inbound(rr, inbound_tag):
        return None

    if inbound_tag:
        rr["inboundTag"] = [inbound_tag]

    outbound_tag_map = outbound_tag_map or {}
    outbound = rr.get("outboundTag")
    if outbound in outbound_tag_map:
        rr["outboundTag"] = outbound_tag_map[outbound]

    if not is_allowed_outbound_tag(rr.get("outboundTag"), outbound_tag_map):
        return None

    return rr


def is_ip_matcher(item):
    item = str(item).strip()
    if item.startswith("geoip:"):
        return True

    try:
        ipaddress.ip_network(item, strict=False)
        return True
    except Exception:
        return False


def is_wildcard_matcher(item):
    item = str(item).strip().lower()
    return item in ["*", "*.*", "0.0.0.0/0", "::/0"]


def is_route_comment(item):
    item = str(item).strip()
    return (
        not item
        or item.startswith("#")
        or item.startswith("//")
        or item.startswith(";")
    )


def normalize_domain_matcher(item):
    item = item.strip()
    if not item:
        return None

    lower = item.lower()
    if is_wildcard_matcher(lower):
        return None
    if lower.startswith(("geosite:", "regexp:", "domain:", "full:", "keyword:")):
        return item

    if item.startswith("*."):
        item = item[2:]
    if item.startswith("."):
        item = item[1:]
    if not item:
        return None

    return f"domain:{item}"


def split_route_match(match_items):
    domains = []
    ips = []
    wildcard = False

    for item in ensure_str_list(match_items):
        if is_route_comment(item):
            continue

        if is_wildcard_matcher(item):
            wildcard = True
            continue

        if is_ip_matcher(item):
            ips.append(item)
            continue

        domain = normalize_domain_matcher(item)
        if domain:
            domains.append(domain)

    return domains, ips, wildcard


def parse_dns_action_value(value):
    if value in [None, ""]:
        return []

    text = str(value).strip()
    text = re.sub(r"^\s*DNS\s*[:：]\s*", "", text, flags=re.I)
    servers = []
    for item in re.split(r"[,，;\s]+", text):
        item = item.strip()
        if not item:
            continue
        servers.append(item)

    return servers


def compile_panel_route(route, inbound_tag=None, allow_default_dns=False, outbound_tag_map=None):
    if not isinstance(route, dict):
        return [], []

    domains, ips, wildcard = split_route_match(route.get("match"))
    action = str(route.get("action", "block")).strip().lower()
    action_value = route.get("action_value")

    routing_rules = []
    dns_servers = []

    if action == "dns":
        if not domains and not allow_default_dns:
            return [], []
        for address in parse_dns_action_value(action_value):
            if domains:
                dns_servers.append({
                    "address": address,
                    "domains": domains
                })
            elif wildcard:
                dns_servers.append(address)
        return [], dns_servers

    if action == "direct":
        outbound = "direct"
    elif action == "proxy":
        if action_value in [None, ""]:
            return [], []
        outbound = str(action_value).strip()
        outbound = (outbound_tag_map or {}).get(outbound, outbound)
        if not is_allowed_outbound_tag(outbound, outbound_tag_map):
            return [], []
    else:
        outbound = "block"

    def scoped_rule(rule):
        if inbound_tag:
            rule["inboundTag"] = [inbound_tag]
        return rule

    if domains:
        routing_rules.append(scoped_rule({
            "type": "field",
            "domain": domains,
            "outboundTag": outbound
        }))

    if ips:
        routing_rules.append(scoped_rule({
            "type": "field",
            "ip": ips,
            "outboundTag": outbound
        }))

    return routing_rules, []


def extract_panel_routes(
    server,
    inbound_tag=None,
    include_dns=True,
    allow_default_dns=False,
    outbound_tag_map=None,
):
    if not isinstance(server, dict):
        return [], []

    routing_rules = []
    dns_servers = []

    for key in ["routes", "route_rules", "routeRules"]:
        items = ensure_list(server.get(key))
        for item in items:
            rules, dns = compile_panel_route(
                item,
                inbound_tag=inbound_tag,
                allow_default_dns=allow_default_dns,
                outbound_tag_map=outbound_tag_map,
            )
            routing_rules.extend(rules)
            if include_dns:
                dns_servers.extend(dns)

    return routing_rules, dns_servers


def extract_custom_routes(server, inbound_tag=None, outbound_tag_map=None):
    """
    Read per-node custom routes from XBoard.
    Supported field names:
    - custom_routes
    - customRoutes
    """
    if not isinstance(server, dict):
        return []

    routes = []

    for key in ["custom_routes", "customRoutes"]:
        val = server.get(key)
        items = ensure_list(val)
        if not items:
            continue

        for item in items:
            if isinstance(item, dict) and item.get("type") == "field" and item.get("outboundTag"):
                rr = rewrite_route_for_node(
                    item,
                    inbound_tag=inbound_tag,
                    outbound_tag_map=outbound_tag_map,
                )
                if rr:
                    routes.append(rr)

    return routes


def dedupe_dns_servers(entries):
    grouped = {}
    order = []
    defaults = []
    default_seen = set()

    for entry in entries:
        if isinstance(entry, str):
            address = entry.strip()
            if address and address not in default_seen:
                defaults.append(address)
                default_seen.add(address)
            continue

        if not isinstance(entry, dict):
            continue

        address = str(entry.get("address", "")).strip()
        if not address:
            continue

        if address not in grouped:
            grouped[address] = {
                "address": address,
                "domains": []
            }
            order.append(address)

        for domain in ensure_str_list(entry.get("domains")):
            if domain not in grouped[address]["domains"]:
                grouped[address]["domains"].append(domain)

    domain_servers = [
        grouped[address]
        for address in order
        if grouped[address]["domains"]
    ]

    return domain_servers + defaults


def dedupe_outbounds(outbounds):
    seen = set()
    result = []

    for ob in outbounds:
        if not isinstance(ob, dict):
            continue

        tag = ob.get("tag")
        if not tag:
            continue

        if tag in seen:
            continue

        seen.add(tag)
        result.append(ob)

    return result



def get_vless_flow(server):
    flow = pick_from_configs([server], ["flow", "flow_control", "flowControl"])
    if not is_present(flow):
        return None

    flow = str(flow).strip()
    if flow.lower() in ["none", "null", "false", "off"]:
        return None
    return flow


def get_vless_decryption(server):
    encryption = as_dict(pick_path(
        server,
        "encryption",
        "vless_encryption",
        "vlessEncryption",
        "protocol_settings.encryption",
        "protocolSettings.encryption",
        default={},
    ))
    enabled = parse_bool(pick(encryption, "enabled", "enable", default=None), default=None)

    if enabled is False:
        return "none"

    decryption = pick_path(
        server,
        "decryption",
        "vless_decryption",
        "vlessDecryption",
        "protocol_settings.decryption",
        "protocolSettings.decryption",
        default=None,
    )
    if not is_present(decryption):
        decryption = pick(
            encryption,
            "decryption",
            "server_decryption",
            "serverDecryption",
            default=None,
        )

    return str(decryption).strip() if is_present(decryption) else "none"


def build_vless_clients(user_resp, flow, node_id=None):
    users = get_users_list(user_resp)
    clients = []

    for u in users:
        if not isinstance(u, dict):
            continue

        uuid = pick(u, "uuid", "id", "user_uuid")
        if not uuid:
            continue

        user_id = pick(u, "id", "email", "user_id", default=f"user-{len(clients)+1}")

        client = {
            "id": str(uuid),
            "email": stats_email(user_id, node_id)
        }

        if flow:
            client["flow"] = str(flow)

        clients.append(client)

    if not clients:
        raise RuntimeError("没有解析到 VLESS 用户。user 接口里没有 users[].uuid。")

    return clients


def build_vless_inbound(config_resp, user_resp, node_id=None):
    server = unwrap_config(config_resp)
    if not isinstance(server, dict):
        raise RuntimeError("config 接口格式不正确，不是 JSON 对象。")

    protocol = str(pick(server, "protocol", default="vless")).lower()
    if protocol != "vless":
        raise RuntimeError(f"当前节点不是 vless，面板返回 protocol={protocol}")

    port = get_server_port(server, 443)
    listen = get_listen_ip(server)
    flow = get_vless_flow(server)

    clients = build_vless_clients(user_resp, flow, node_id=node_id)

    return {
        "tag": f"vless-{port}",
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": clients,
            "decryption": get_vless_decryption(server)
        },
        "streamSettings": build_stream_settings(server),
        "sniffing": {
            "enabled": True,
            "destOverride": [
                "http",
                "tls",
                "quic"
            ]
        }
    }


def build_vmess_clients(user_resp, node_id=None):
    users = get_users_list(user_resp)
    clients = []

    for u in users:
        if not isinstance(u, dict):
            continue

        uuid = pick(u, "uuid", "id", "user_uuid")
        if not uuid:
            continue

        user_id = pick(u, "id", "email", "user_id", default=f"user-{len(clients)+1}")

        clients.append({
            "id": str(uuid),
            "email": stats_email(user_id, node_id),
            "alterId": 0,
            "security": "auto"
        })

    if not clients:
        raise RuntimeError("没有解析到 VMess 用户。user 接口里没有 users[].uuid。")

    return clients


def build_vmess_inbound(config_resp, user_resp, node_id=None):
    server = unwrap_config(config_resp)
    if not isinstance(server, dict):
        raise RuntimeError("config 接口格式不正确，不是 JSON 对象。")

    protocol = str(pick(server, "protocol", default="vmess")).lower()
    if protocol not in ["vmess", "v2ray"]:
        raise RuntimeError(f"当前节点不是 vmess，面板返回 protocol={protocol}")

    port = get_server_port(server, 443)
    listen = get_listen_ip(server)

    return {
        "tag": f"vmess-{port}",
        "listen": listen,
        "port": port,
        "protocol": "vmess",
        "settings": {
            "clients": build_vmess_clients(user_resp, node_id=node_id)
        },
        "streamSettings": build_stream_settings(server),
        "sniffing": {
            "enabled": True,
            "destOverride": [
                "http",
                "tls",
                "quic"
            ]
        }
    }


def build_trojan_clients(user_resp, node_id=None):
    users = get_users_list(user_resp)
    clients = []

    for u in users:
        if not isinstance(u, dict):
            continue

        password = pick(u, "password", "passwd", "uuid", "id")
        if not password:
            continue

        user_id = pick(u, "id", "email", "user_id", default=f"user-{len(clients)+1}")

        clients.append({
            "password": str(password),
            "email": stats_email(user_id, node_id)
        })

    if not clients:
        raise RuntimeError("没有解析到 Trojan 用户。")

    return clients


def build_trojan_inbound(config_resp, user_resp, node_id=None):
    server = unwrap_config(config_resp)
    if not isinstance(server, dict):
        raise RuntimeError("config 接口格式不正确，不是 JSON 对象。")

    protocol = str(pick(server, "protocol", default="trojan")).lower()
    if protocol != "trojan":
        raise RuntimeError(f"当前节点不是 trojan，面板返回 protocol={protocol}")

    port = get_server_port(server, 443)
    listen = get_listen_ip(server)

    return {
        "tag": f"trojan-{port}",
        "listen": listen,
        "port": port,
        "protocol": "trojan",
        "settings": {
            "clients": build_trojan_clients(user_resp, node_id=node_id)
        },
        "streamSettings": build_stream_settings(server),
        "sniffing": {
            "enabled": True,
            "destOverride": [
                "http",
                "tls",
                "quic"
            ]
        }
    }


def build_ss_clients(user_resp, method, node_id=None):
    users = get_users_list(user_resp)
    clients = []

    for u in users:
        if not isinstance(u, dict):
            continue

        user_id = pick(u, "id", "email", "user_id", default=f"user-{len(clients)+1}")

        # XBoard SS 用户常见返回是 id + uuid。
        # 普通 Shadowsocks 可用 uuid/password；
        # Shadowsocks 2022 多用户时，用户 password 通常也使用 uuid。
        password = pick(u, "password", "passwd", "uuid", "id")
        if not password:
            continue

        client = {
            "email": stats_email(user_id, node_id),
            "password": str(password)
        }

        if not str(method).startswith("2022-"):
            client["method"] = str(method)

        clients.append(client)

    if not clients:
        raise RuntimeError("没有解析到 Shadowsocks 用户。需要确认 user 接口字段。")

    return clients


def build_shadowsocks_inbound(config_resp, user_resp, node_id=None):
    server = unwrap_config(config_resp)
    if not isinstance(server, dict):
        raise RuntimeError("config 接口格式不正确，不是 JSON 对象。")

    protocol = str(pick(server, "protocol", default="shadowsocks")).lower()
    if protocol not in ["shadowsocks", "ss"]:
        raise RuntimeError(f"当前节点不是 shadowsocks，面板返回 protocol={protocol}")

    listen = get_listen_ip(server)
    port = get_server_port(server, 8388)

    method = pick(
        server,
        "cipher",
        "method",
        "server_method",
        default="aes-128-gcm"
    )

    server_key = pick(server, "server_key", "password", "passwd")
    clients = build_ss_clients(user_resp, method, node_id=node_id)

    settings = {
        "method": str(method),
        "clients": clients,
        "network": "tcp,udp"
    }

    # Shadowsocks 2022 需要服务端主密码，也就是 XBoard 下发的 server_key。
    if str(method).startswith("2022-"):
        if not server_key:
            raise RuntimeError("Shadowsocks 2022 缺少 server_key，无法生成配置。")
        settings["password"] = str(server_key)

    return {
        "tag": f"shadowsocks-{port}",
        "listen": listen,
        "port": port,
        "protocol": "shadowsocks",
        "settings": settings,
        "sniffing": {
            "enabled": True,
            "destOverride": [
                "http",
                "tls",
                "quic"
            ]
        }
    }


def build_xray_config(inbounds, custom_outbounds=None, custom_routes=None, custom_dns_servers=None):
    custom_outbounds = custom_outbounds or []
    custom_routes = custom_routes or []
    custom_dns_servers = custom_dns_servers or []
    dns_servers = dedupe_dns_servers(custom_dns_servers + ["1.1.1.1", "8.8.8.8"])

    outbounds = dedupe_outbounds(
        [
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {}
            }
        ] + custom_outbounds
    )

    routing_rules = [
        {
            "type": "field",
            "inboundTag": [
                "api"
            ],
            "outboundTag": "api"
        },
        {
            "type": "field",
            "ip": [
                "geoip:private"
            ],
            "outboundTag": "block"
        },
        {
            "type": "field",
            "protocol": [
                "bittorrent"
            ],
            "outboundTag": "block"
        }
    ] + custom_routes

    return {
        "log": {
            "access": "/var/log/xray/access.log",
            "error": "/var/log/xray/error.log",
            "loglevel": "warning"
        },
        "api": {
            "tag": "api",
            "services": [
                "StatsService"
            ]
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True
            }
        },
        "dns": {
            "servers": dns_servers,
            "queryStrategy": "UseIPv4"
        },
        "inbounds": [
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                }
            }
        ] + inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": routing_rules
        }
    }

def sha256_text(s):
    return hashlib.sha256(s.encode()).hexdigest()


def ensure_xray_log_files(log_dir="/opt/xray/logs"):
    p = Path(log_dir)
    p.mkdir(parents=True, exist_ok=True)

    access_log = p / "access.log"
    error_log = p / "error.log"

    access_log.touch(exist_ok=True)
    error_log.touch(exist_ok=True)

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        import grp
        try:
            gid = grp.getgrnam("xray-audit").gr_gid
        except KeyError:
            gid = 0
        # Official pinned container runs as UID 65532; audit receives read-only
        # group access without making client metadata readable to every user.
        for item in (p, access_log, error_log):
            os.chown(item, 65532, gid)
    p.chmod(0o750)
    access_log.chmod(0o640)
    error_log.chmod(0o640)


def validate_xray_config(config):
    if not isinstance(config, dict):
        raise RuntimeError("生成的 Xray 配置不是 JSON 对象")
    if not isinstance(config.get("inbounds"), list):
        raise RuntimeError("生成的 Xray 配置缺少 inbounds 数组")
    if not isinstance(config.get("outbounds"), list):
        raise RuntimeError("生成的 Xray 配置缺少 outbounds 数组")

    seen_ports = {}
    for inbound in config["inbounds"]:
        if not isinstance(inbound, dict):
            raise RuntimeError("生成的 Xray inbound 不是 JSON 对象")
        port = inbound.get("port")
        tag = inbound.get("tag", "unknown")
        if port is None:
            continue
        if port in seen_ports:
            raise RuntimeError(f"生成的 Xray 配置端口冲突: {seen_ports[port]} 和 {tag} 都使用 {port}")
        seen_ports[port] = tag


def backup_config(config_path, keep=3):
    config_path = Path(config_path)
    if not config_path.exists():
        return None

    backup_dir = config_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"{config_path.name}.{time.strftime('%Y%m%d-%H%M%S')}.{time.time_ns()}"
    shutil.copy2(config_path, backup)

    backups = sorted(
        backup_dir.glob(f"{config_path.name}.*"),
        key=lambda p: p.name,
        reverse=True
    )
    for old in backups[int(keep):]:
        old.unlink(missing_ok=True)

    return backup


def restore_config(backup_path, config_path):
    if not backup_path:
        return False
    backup_path = Path(backup_path)
    if not backup_path.exists():
        return False
    shutil.copy2(backup_path, config_path)
    return True


def write_config_atomically(config_path, text):
    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    parsed = json.loads(text)
    validate_xray_config(parsed)

    tmp = config_path.with_name(f".{config_path.name}.tmp")
    tmp.write_text(text)
    json.loads(tmp.read_text())
    tmp.replace(config_path)


def run_xray_config_test(container, config_path, text, container_config_dir="/etc/xray"):
    config_path = Path(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = config_path.with_name(f".{config_path.stem}.test{config_path.suffix or '.json'}")
    tmp.write_text(text)

    container_tmp = f"{container_config_dir.rstrip('/')}/{tmp.name}"
    try:
        result = subprocess.run(
            ["docker", "exec", container, "xray", "run", "-test", "-config", container_tmp],
            capture_output=True,
            text=True,
            timeout=30
        )
    finally:
        tmp.unlink(missing_ok=True)

    if result.returncode != 0:
        output = (result.stdout or "") + (result.stderr or "")
        output = output.strip()[-4000:]
        raise RuntimeError(f"Xray 配置预检测失败，未替换正式 config.json:\n{output}")

    print("[sync] Xray 配置预检测通过", flush=True)


def ensure_container_running(container, retries=10, delay=0.5):
    last_output = ""
    for _ in range(retries):
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            capture_output=True,
            text=True
        )
        last_output = ((result.stdout or "") + (result.stderr or "")).strip()
        if result.returncode == 0 and result.stdout.strip() == "true":
            return
        time.sleep(delay)

    logs = subprocess.run(
        ["docker", "logs", container, "--tail=80"],
        capture_output=True,
        text=True
    )
    log_text = ((logs.stdout or "") + (logs.stderr or "")).strip()[-4000:]
    raise RuntimeError(f"{container} 重启后未保持 running。inspect={last_output}\n{log_text}")


def restart_xray(container):
    subprocess.run(["docker", "restart", container], check=True)
    ensure_container_running(container)


def fetch_node(
    panel,
    token,
    node_id,
    node_type,
    enable_panel_routes=True,
    enable_panel_dns_routes=True,
    enable_panel_default_dns=False,
):
    node_type = normalize_node_type(node_type)

    config_url = f"{panel}/api/v1/server/UniProxy/config?node_id={node_id}&node_type={node_type}&token={token}"
    user_url = f"{panel}/api/v1/server/UniProxy/user?node_id={node_id}&node_type={node_type}&token={token}"

    config_resp = get_json(config_url)
    user_resp = get_json(user_url)

    server = unwrap_config(config_resp)

    if node_type == "vless":
        inbound = build_vless_inbound(config_resp, user_resp, node_id=node_id)
    elif node_type == "vmess":
        inbound = build_vmess_inbound(config_resp, user_resp, node_id=node_id)
    elif node_type == "trojan":
        inbound = build_trojan_inbound(config_resp, user_resp, node_id=node_id)
    elif node_type == "shadowsocks":
        inbound = build_shadowsocks_inbound(config_resp, user_resp, node_id=node_id)
    else:
        raise RuntimeError(
            f"暂不支持协议: {node_type}。"
            f"官方 xray-core 不支持 AnyTLS/Hysteria2/TUIC，请用 sing-box。"
        )

    custom_outbounds, outbound_tag_map = scope_custom_outbounds(
        extract_custom_outbounds(server),
        node_id,
    )
    custom_routes = extract_custom_routes(
        server,
        inbound_tag=inbound.get("tag"),
        outbound_tag_map=outbound_tag_map,
    )
    panel_routes = []
    panel_dns_servers = []
    if enable_panel_routes:
        panel_routes, panel_dns_servers = extract_panel_routes(
            server,
            inbound_tag=inbound.get("tag"),
            include_dns=enable_panel_dns_routes,
            allow_default_dns=enable_panel_default_dns,
            outbound_tag_map=outbound_tag_map,
        )
    custom_routes.extend(panel_routes)

    if custom_outbounds:
        print(f"[sync] 节点 {node_id}:{node_type} 下发 custom outbounds: {len(custom_outbounds)}", flush=True)

    if custom_routes:
        print(f"[sync] 节点 {node_id}:{node_type} 下发 custom routes: {len(custom_routes)}", flush=True)

    if panel_dns_servers:
        print(f"[sync] 节点 {node_id}:{node_type} 下发 DNS routes: {len(panel_dns_servers)}", flush=True)

    print(f"[sync] 已生成节点 {node_id}:{node_type} -> {inbound['tag']}:{inbound['port']}", flush=True)

    return {
        "inbound": inbound,
        "custom_outbounds": custom_outbounds,
        "custom_routes": custom_routes,
        "custom_dns_servers": panel_dns_servers
    }

def apply_audit_sniffing(inbound, env):
    """Explicit audit config only; retain legacy config byte-for-byte when disabled."""
    if not parse_bool(env.get("AUDIT_ENABLED", "false")):
        return
    if inbound.get("protocol") not in {"vless", "vmess", "trojan", "shadowsocks"}:
        return
    protocols = [name for name in ("http", "tls") if parse_bool(env.get("AUDIT_SNIFF_" + name.upper(), "true"))]
    inbound["sniffing"] = {"enabled": parse_bool(env.get("AUDIT_SNIFFING_ENABLED", "true")), "destOverride": protocols}


def sync_once():
    env = load_env()

    panel = env["PANEL_URL"].rstrip("/")
    token = env["PANEL_TOKEN"]
    nodes = get_nodes(env)

    config_path = Path(env.get("XRAY_CONFIG", "/opt/xray/config/config.json"))
    container = env.get("XRAY_CONTAINER", "xray-core")
    container_config_dir = env.get("XRAY_CONTAINER_CONFIG_DIR", "/etc/xray")
    prestart_test = parse_bool(env.get("XRAY_PRESTART_TEST", "true"), default=True)
    enable_panel_routes = parse_bool(env.get("XRAY_ENABLE_PANEL_ROUTES", "true"), default=True)
    enable_panel_dns_routes = parse_bool(env.get("XRAY_ENABLE_PANEL_DNS_ROUTES", "true"), default=True)
    enable_panel_default_dns = parse_bool(env.get("XRAY_ENABLE_PANEL_DEFAULT_DNS", "false"), default=False)
    backup_keep = int(env.get("XRAY_CONFIG_BACKUPS", "3"))
    ensure_xray_log_files(env.get("XRAY_LOG_DIR", "/opt/xray/logs"))

    inbounds = []
    custom_outbounds = []
    custom_routes = []
    custom_dns_servers = []

    for node_id, node_type in nodes:
        node_data = fetch_node(
            panel,
            token,
            node_id,
            node_type,
            enable_panel_routes=enable_panel_routes,
            enable_panel_dns_routes=enable_panel_dns_routes,
            enable_panel_default_dns=enable_panel_default_dns,
        )
        inbound = node_data["inbound"]
        apply_audit_sniffing(inbound, env)

        inbounds.append(inbound)
        custom_outbounds.extend(node_data.get("custom_outbounds", []))
        custom_routes.extend(node_data.get("custom_routes", []))
        custom_dns_servers.extend(node_data.get("custom_dns_servers", []))

    # 防止端口重复
    seen_ports = {}
    for inbound in inbounds:
        p = inbound["port"]
        if p in seen_ports:
            raise RuntimeError(f"端口冲突：{seen_ports[p]} 和 {inbound['tag']} 都使用端口 {p}")
        seen_ports[p] = inbound["tag"]

    xray_config = build_xray_config(
        inbounds,
        custom_outbounds=custom_outbounds,
        custom_routes=custom_routes,
        custom_dns_servers=custom_dns_servers
    )

    new_text = json.dumps(xray_config, ensure_ascii=False, indent=2)
    old_text = config_path.read_text(errors="ignore") if config_path.exists() else ""

    if sha256_text(new_text) != sha256_text(old_text):
        validate_xray_config(xray_config)
        if prestart_test:
            run_xray_config_test(container, config_path, new_text, container_config_dir=container_config_dir)
        backup = backup_config(config_path, keep=backup_keep)
        write_config_atomically(config_path, new_text)

        print("[sync] 配置有变化，已写入 /opt/xray/config/config.json，正在重启 xray-core", flush=True)
        try:
            restart_xray(container)
        except Exception:
            if restore_config(backup, config_path):
                print("[sync] ERROR: xray-core 重启失败，已恢复上一份配置", file=sys.stderr, flush=True)
                try:
                    restart_xray(container)
                except Exception as rollback_error:
                    print(f"[sync] ERROR: 旧配置恢复后重启仍失败: {rollback_error}", file=sys.stderr, flush=True)
            raise
    else:
        ensure_container_running(container, retries=1, delay=0)
        print("[sync] 配置无变化，xray-core 正在运行", flush=True)


def loop():
    env = load_env()
    interval = int(env.get("SYNC_INTERVAL", "60"))

    while True:
        try:
            sync_once()
        except Exception as e:
            print(f"[sync] ERROR: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "once":
        sync_once()
    else:
        loop()
