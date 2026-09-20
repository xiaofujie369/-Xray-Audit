#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
[ -d "$ROOT/agent" ] || { echo 'Download/extract the complete release before running this installer.'; exit 1; }
getent group xray-audit >/dev/null || groupadd --system xray-audit
id xray-audit >/dev/null 2>&1 || useradd --system --gid xray-audit --home-dir /opt/xray-audit --shell /usr/sbin/nologin xray-audit
chgrp xray-audit /opt/xray/logs /opt/xray/logs/access.log /opt/xray/logs/error.log
chmod 750 /opt/xray/logs
chmod 640 /opt/xray/logs/access.log /opt/xray/logs/error.log
install -d -m 700 /opt/xray-audit /opt/xray-audit/traffic-inbox
install -d -m 755 /opt/xray-audit/code
cp -a "$ROOT/agent" /opt/xray-audit/code/
install -m 644 "$ROOT/sync/audit_bridge.py" /opt/xray-sync/audit_bridge.py
install -m 644 "$ROOT/systemd/xboard-audit.service" /etc/systemd/system/xboard-audit.service
install -m 644 "$ROOT/systemd/xboard-audit-health.service" /etc/systemd/system/xboard-audit-health.service
install -m 644 "$ROOT/systemd/xboard-audit-health.timer" /etc/systemd/system/xboard-audit-health.timer
install -m 644 "$ROOT/systemd/xray-audit.logrotate" /etc/logrotate.d/xray-audit
export PYTHONPATH=/opt/xray-audit/code
if [ ! -f /opt/xray-audit/config.json ] || [ "$#" -gt 0 ]; then
  python3 -m agent.manage enroll "$@"
fi
python3 -m agent.manage test
chown xray-audit:xray-audit /opt/xray-audit /opt/xray-audit/traffic-inbox /opt/xray-audit/config.json
find /opt/xray-audit -maxdepth 1 -name 'spool.db*' -exec chown xray-audit:xray-audit '{}' \;
systemctl daemon-reload
systemctl enable --now xboard-audit
systemctl enable --now xboard-audit-health.timer
echo 'Audit enabled. Xray was not restarted.'
