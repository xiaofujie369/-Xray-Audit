# Troubleshooting

* **No data:** check `xbr` 29, Agent credentials, readable access log, parser counts, cursor and spool. Agent is off until enrollment. Missing user/email remains null; it is not guessed.
* **Spool increases:** test central with `xbr` 28. Check TLS trust, revoked identity, central `/readyz`, PostgreSQL space, and API status. Failed uploads must stay queued. Repeated 422 requires data/schema investigation, not deleting the spool.
* **No domain:** standard Xray access logs do not always include the sniffed SNI or a domain. Keep the observed destination; do not infer a resolved IP or browser URL.
* **No traffic bytes:** only xboard-report resets Stats API. Confirm its local traffic inbox handoff, permissions and capacity. Connection counts and user traffic intervals are different datasets.
* **No confirmation:** verify mainland flags, independent network groups, controls and timestamps. Two credentials from one group count once. Refused/TLS/HTTP failures do not count as timeout evidence. Old/offline probes cannot confirm a current event.
* **Worker stalled:** inspect `audit-worker` and `audit-scheduler`, Redis and PostgreSQL job queue. Jobs persist in PostgreSQL and resume after Redis recovers.
* **Browser cannot stay logged in:** production requires HTTPS and Secure cookies. Check reverse proxy and system clock. Do not disable TLS verification to work around a certificate error.
* **Disk pressure:** tune detailed event retention, spool capacity, logrotate and backups. Spool evictions indicate a real coverage gap. On PostgreSQL monitor table/index sizes and vacuum; retention is bounded in batches.
* **Outdated Agent:** central supports schemas 1 and 2. Compare the version shown in VPS health against the release being deployed. Update code while retaining `config.json` and `spool.db`.

Application errors intentionally omit credentials and raw connection lines. Collect status counters, versions and sanitized configuration rather than complete access histories for support.
