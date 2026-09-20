#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$SOURCE/sync/xboard_sync.py" ]; then
  echo 'Run update.sh from an extracted release or your new repository checkout.'
  exit 1
fi
SYNC=/opt/xray-sync
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$SYNC/backup/update-$STAMP"
STAGE="$(mktemp -d)"
SUCCESS=false
CHANGED=false
MUTATED=false
AUDIT_ACTIVE=false
AUDIT_CHANGED=false
systemctl is-active --quiet xboard-audit && AUDIT_ACTIVE=true
if [ -d /opt/xray-audit/code/agent ] && ! diff -qr --exclude=__pycache__ "$SOURCE/agent" /opt/xray-audit/code/agent >/dev/null; then AUDIT_CHANGED=true; fi
if [ -f /opt/xray-audit/config.json ] && ! cmp -s "$SOURCE/systemd/xboard-audit.service" /etc/systemd/system/xboard-audit.service; then AUDIT_CHANGED=true; fi
cleanup() {
  if [ "$SUCCESS" != true ] && [ "$MUTATED" = true ]; then
    echo 'Update failed; restoring previous scripts.'
    cp -a "$BACKUP/sync/." "$SYNC/"
    if [ -d "$BACKUP/audit-code" ]; then cp -a "$BACKUP/audit-code/." /opt/xray-audit/code/; fi
    if [ -d "$BACKUP/units" ]; then cp -a "$BACKUP/units/." /etc/systemd/system/; systemctl daemon-reload; fi
    cp -a "$SYNC/manage.sh" /usr/local/bin/xbr
    cp -a "$SYNC/manage.sh" /usr/local/bin/xray-sync
  fi
  if [ "$CHANGED" = true ]; then systemctl start xboard-sync xboard-report; fi
  if [ "$AUDIT_ACTIVE" = true ] && [ "$AUDIT_CHANGED" = true ]; then systemctl start xboard-audit; fi
  rm -rf -- "$STAGE"
}
trap cleanup EXIT
cp -a "$SOURCE/sync" "$STAGE/"
python3 -m compileall -q "$STAGE/sync"
python3 -m compileall -q "$SOURCE/agent"
bash -n "$STAGE/sync/manage.sh"
docker exec xray-core xray run -test -config /etc/xray/config.json
install -d -m 700 "$BACKUP/sync"
find "$SYNC" -maxdepth 1 -type f -exec cp -a '{}' "$BACKUP/sync/" \;
if [ -d /opt/xray-audit ]; then
  if [ "$AUDIT_ACTIVE" = true ] && [ "$AUDIT_CHANGED" = true ]; then systemctl stop xboard-audit; fi
  [ ! -d /opt/xray-audit/code ] || cp -a /opt/xray-audit/code "$BACKUP/audit-code"
  [ ! -f /opt/xray-audit/config.json ] || cp -a /opt/xray-audit/config.json "$BACKUP/audit-config.json"
  install -d -m 700 "$BACKUP/units"
  find /etc/systemd/system -maxdepth 1 -name 'xboard-audit*' -type f -exec cp -a '{}' "$BACKUP/units/" \;
  if [ -f /opt/xray-audit/spool.db ]; then
    python3 - "$BACKUP/spool.db" <<'PY'
import sqlite3
import sys
with sqlite3.connect('/opt/xray-audit/spool.db') as source:
    with sqlite3.connect(sys.argv[1]) as destination:
        source.backup(destination)
PY
  fi
fi
if ! cmp -s "$SOURCE/sync/xboard_sync.py" "$SYNC/xboard_sync.py" || ! cmp -s "$SOURCE/sync/xboard_report.py" "$SYNC/xboard_report.py"; then
  CHANGED=true
  systemctl stop xboard-sync xboard-report
fi
MUTATED=true
cp -a "$STAGE/sync/." "$SYNC/"
install -m 755 "$SYNC/manage.sh" /usr/local/bin/xbr
install -m 755 "$SYNC/manage.sh" /usr/local/bin/xray-sync
if [ "$AUDIT_CHANGED" = true ]; then
  cp -a "$SOURCE/agent" /opt/xray-audit/code/
  install -m 644 "$SOURCE/systemd/xboard-audit.service" /etc/systemd/system/xboard-audit.service
  install -m 644 "$SOURCE/systemd/xboard-audit-health.service" /etc/systemd/system/xboard-audit-health.service
  install -m 644 "$SOURCE/systemd/xboard-audit-health.timer" /etc/systemd/system/xboard-audit-health.timer
  systemctl daemon-reload
  runuser -u xray-audit -- env PYTHONPATH=/opt/xray-audit/code python3 -m agent.manage status
fi
if [ "$SOURCE" != "$SYNC/release" ]; then
  install -d -m 755 "$SYNC/release"
  cp -a "$SOURCE/agent" "$SOURCE/sync" "$SOURCE/systemd" "$SYNC/release/"
  cp "$SOURCE"/*.sh "$SYNC/release/"
fi
if [ "$CHANGED" = true ]; then systemctl start xboard-sync xboard-report; fi
if [ "$AUDIT_ACTIVE" = true ] && [ "$AUDIT_CHANGED" = true ]; then systemctl start xboard-audit; systemctl enable --now xboard-audit-health.timer; fi
SUCCESS=true
echo "Update complete. Identity, configuration and spool preserved. Backup: $BACKUP"
