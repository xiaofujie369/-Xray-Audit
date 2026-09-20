#!/usr/bin/env bash
set -euo pipefail
umask 077
DEST="${1:?Usage: backup-agent.sh /new/backup-directory [--spool]}"
[ ! -e "$DEST" ] || exit 1
mkdir -p -- "$DEST"
cp -a /opt/xray-sync/.env "$DEST/sync.env"
[ ! -f /opt/xray-audit/config.json ] || cp -a /opt/xray-audit/config.json "$DEST/audit-config.json"
if [ "${2:-}" = --spool ]; then
  python3 - "$DEST/spool.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect('/opt/xray-audit/spool.db') as source:
    with sqlite3.connect(sys.argv[1]) as target:
        source.backup(target)
PY
fi
echo 'Backup complete; spool is included only with --spool.'
