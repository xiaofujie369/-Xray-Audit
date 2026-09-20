# Upgrade, rollback and removal

Use an extracted release or local checkout from the repository you control. `bash update.sh` validates staged Python/shell files and the running Xray configuration, backs up sync files, audit config/code and a consistent SQLite snapshot, then updates code. Identity and live spool are preserved. Existing proxy configuration is not rewritten by the update script. Changed sync/report scripts restart those services; an Audit-only update does not restart Xray.

Failure restores backed-up sync code and aliases before restarting services. Keep `/opt/xray-sync/backup/update-*` until verification is complete. The rollback backup contains credentials: keep mode 0700 and do not upload it to Git.

Agent backup: `sudo bash backup-agent.sh /secure/new-directory`; add `--spool` for a consistent spool snapshot. Spool is deliberately excluded by default. Restore with `sudo bash restore-agent.sh /secure/backup-directory`; it requires explicit confirmation. Without a spool backup, a copied cursor must not skip old data, so a new reader starts from available log data.

`sudo bash uninstall-audit.sh` removes only the audit service and leaves forensic data by default. Enter `DELETE` only when permanent removal is intended. Whole-project `uninstall.sh` stops Audit as well as existing services but retains `/opt/xray-audit` data. Central `docker compose down` retains its named volumes.

Release verification must include: empty PostgreSQL migration, repeated migration, upgrade with preexisting identity and spool, legacy single-node and multi-node sync/report tests, real pinned-Xray configuration tests, central outage/recovery, and a fresh Linux installation. See `audit-validation.md` for the checks actually executed for this checkout.
