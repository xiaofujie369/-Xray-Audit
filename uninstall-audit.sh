#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" = 0 ] || exit 1
systemctl disable --now xboard-audit 2>/dev/null || true
systemctl disable --now xboard-audit-health.timer 2>/dev/null || true
rm -f /etc/systemd/system/xboard-audit.service
rm -f /etc/systemd/system/xboard-audit-health.service /etc/systemd/system/xboard-audit-health.timer
systemctl daemon-reload
echo 'Agent stopped. Credentials, code and spool retained in /opt/xray-audit.'
read -r -p 'Delete audit spool and credentials permanently? Type DELETE: ' answer
if [ "$answer" = DELETE ]; then
  rm -rf -- /opt/xray-audit
fi
