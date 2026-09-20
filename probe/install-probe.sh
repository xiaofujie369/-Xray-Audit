#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" = 0 ] || exit 1
getent group xray-probe >/dev/null || groupadd --system xray-probe
id xray-probe >/dev/null 2>&1 || useradd --system --gid xray-probe --home-dir /opt/xray-probe --shell /usr/sbin/nologin xray-probe
install -d -m 700 /opt/xray-probe
install -d -m 755 /opt/xray-probe/code
cp -a "$ROOT/agent" "$ROOT/probe" /opt/xray-probe/code/
export PYTHONPATH=/opt/xray-probe/code
python3 -m agent.manage enroll --kind probes --config /opt/xray-probe/config.json "$@"
chown xray-probe:xray-probe /opt/xray-probe /opt/xray-probe/config.json
install -m 644 "$ROOT/systemd/xboard-probe.service" /etc/systemd/system/xboard-probe.service
systemctl daemon-reload
systemctl enable --now xboard-probe
