#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
test -s /opt/xray-probe/config.json
test -d /opt/xray-probe/code
stage=$(mktemp -d /opt/xray-probe/code-next.XXXXXX)
cp -a "$ROOT/agent" "$ROOT/probe" "$stage/"
chmod 755 "$stage"
backup="/opt/xray-probe/code-backup-$(date -u +%Y%m%dT%H%M%S)-$$"
systemctl stop xboard-probe
mv /opt/xray-probe/code "$backup"
mv "$stage" /opt/xray-probe/code
install -m 644 "$ROOT/systemd/xboard-probe.service" /etc/systemd/system/xboard-probe.service
systemctl daemon-reload
if ! systemctl restart xboard-probe; then
  mv /opt/xray-probe/code "$stage"
  mv "$backup" /opt/xray-probe/code
  systemctl restart xboard-probe
  echo "Probe update failed; previous code restored. Failed files: $stage" >&2
  exit 1
fi
echo "Probe updated. Credentials and SQLite spool preserved. Previous code: $backup"
