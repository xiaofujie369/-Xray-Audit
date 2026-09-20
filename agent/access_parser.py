"""Parse metadata only; never retain the original access line."""

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

LINE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:from\s+)?(?P<src>\S+)\s+(?P<decision>accepted|rejected)\s+"
    r"(?:(?P<network>tcp|udp):)?(?P<dest>\S+)(?P<tail>.*)$"
)
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_ip(value):
    address = ipaddress.ip_address(value)
    return str(getattr(address, "ipv4_mapped", None) or address)


def normalize_domain(value):
    if "://" in value:
        value = urlsplit(value).hostname or ""
    value = value.rstrip(".").lower().encode("idna").decode("ascii")
    if not value or len(value) > 253 or not all(LABEL.fullmatch(x) for x in value.split(".")):
        raise ValueError("invalid domain")
    # An invalid dotted IPv4 address must not silently become a domain.
    if all(x.isdigit() for x in value.split(".")):
        raise ValueError("invalid numeric host")
    return value


def endpoint(value):
    value = re.sub(r"^(tcp|udp):", "", value)
    if "://" in value:
        parsed = urlsplit(value)
        return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("invalid endpoint")
    return host.strip("[]"), int(port)


def parse_line(line, single_node=None, log_timezone=timezone.utc):
    """Unknown/invalid lines return None. Xray container must log in UTC."""
    if len(line) > 16384:
        return None
    match = LINE.match(line.strip())
    if not match:
        return None
    try:
        values = match.groupdict()
        source, _ = endpoint(values["src"])
        source = normalize_ip(source)
        host, port = endpoint(values["dest"])
        try:
            destination_ip, domain = normalize_ip(host), None
        except ValueError:
            domain, destination_ip = normalize_domain(host), None
        stamp = datetime.fromisoformat(values["date"].replace("/", "-") + "T" + values["time"])
        stamp = stamp.replace(tzinfo=log_timezone).astimezone(timezone.utc).isoformat()
        email = re.search(r"email:\s*(\d+(?::\d+)?)(?=\s|\]|$)", values["tail"])
        if email is None:
            email = re.search(r"\[(\d+(?::\d+)?)\]", values["tail"])
        node, user = None, None
        if email:
            parts = email[1].split(":")
            user = int(parts[-1])
            node = int(parts[0]) if len(parts) == 2 else single_node
        tags = re.search(r"\[([^\[\]]{1,128}?)\s*(?:->|>>|==>)\s*([^\[\]]{1,128}?)\]", values["tail"])
        return {
            "event_time": stamp,
            "node_id": node,
            "user_id": user,
            "source_ip": source,
            "destination_domain": domain,
            "destination_ip": destination_ip,
            "destination_port": port,
            "network": values["network"] or "tcp",
            "decision": values["decision"],
            "inbound_tag": tags[1].strip() if tags else None,
            "outbound_tag": tags[2].strip() if tags else None,
        }
    except (ValueError, UnicodeError, OverflowError):
        return None
