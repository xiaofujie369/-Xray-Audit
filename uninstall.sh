#!/usr/bin/env bash
set -e

echo "This will remove xboard-sync, xboard-report and xray-core container."
read -rp "Are you sure? [y/N]: " CONFIRM

if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "Cancelled."
  exit 0
fi

systemctl stop xboard-sync 2>/dev/null || true
systemctl disable --now xboard-audit 2>/dev/null || true
systemctl disable --now xboard-audit-health.timer 2>/dev/null || true
rm -f /etc/systemd/system/xboard-audit.service
rm -f /etc/systemd/system/xboard-audit-health.service /etc/systemd/system/xboard-audit-health.timer
systemctl stop xboard-report 2>/dev/null || true
systemctl disable xboard-sync 2>/dev/null || true
systemctl disable xboard-report 2>/dev/null || true

rm -f /etc/systemd/system/xboard-sync.service
rm -f /etc/systemd/system/xboard-report.service
rm -f /usr/local/bin/xray-sync
rm -f /usr/local/bin/xbr
systemctl daemon-reload

docker rm -f xray-core 2>/dev/null || true

echo "默认保留配置目录:"
echo "  /opt/xray"
echo "  /opt/xray-sync"
echo "  /opt/xray-audit (forensic spool retained)"
echo
echo "如需彻底删除，请手动执行:"
echo "  rm -rf /opt/xray /opt/xray-sync"
