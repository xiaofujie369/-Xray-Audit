#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$(id -u)" = 0 ] || exit 1
SOURCE="${1:?Usage: restore-agent.sh /backup/directory}"
test -f "$SOURCE/sync.env"
read -r -p 'Restore saved identity/configuration? Type RESTORE: ' answer
[ "$answer" = RESTORE ] || exit 1
systemctl stop xboard-audit 2>/dev/null || true
install -m 600 "$SOURCE/sync.env" /opt/xray-sync/.env
if [ -f "$SOURCE/audit-config.json" ]; then
  install -d -m 700 /opt/xray-audit
  install -m 600 "$SOURCE/audit-config.json" /opt/xray-audit/config.json
fi
if [ -f "$SOURCE/spool.db" ]; then
  python3 - "$SOURCE/spool.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as source:
    if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
        raise SystemExit('Invalid backup database')
    with sqlite3.connect('/opt/xray-audit/spool.db') as destination:
        source.backup(destination)
PY
fi
chown xray-audit:xray-audit /opt/xray-audit/config.json
find /opt/xray-audit -maxdepth 1 -name 'spool.db*' -exec chown xray-audit:xray-audit '{}' \;
systemctl start xboard-audit
echo 'Audit restored. Xray was not restarted. Apply panel configuration separately after review.'
