# Central deployment

Use Linux, Docker Engine with Compose v2, and a host with a public HTTPS domain. Download the complete project, not an individual script. Keep PostgreSQL and Redis private.

```sh
cd audit-server
cp .env.example .env
chmod 600 .env
# Edit .env before continuing.
bash install-central.sh
```

Set `APP_SECRET` to at least 32 random characters, a unique `ADMIN_EMAIL`, and `ADMIN_PASSWORD` to at least 14 characters. Use a generated PostgreSQL password and put the same URL-encoded password in `DATABASE_URL`. The first boot creates the initial administrator; subsequent boots do not overwrite its password. Do not reuse example test values.

Compose creates PostgreSQL 16, Redis 7, migration job, API, Celery worker, Celery scheduler and Web. Database and Redis have no host ports. Web binds only `127.0.0.1:8080`; override `AUDIT_WEB_PORT` if needed. Configure Caddy using `Caddyfile.example`, or terminate HTTPS with an existing trusted reverse proxy. Cookies are Secure/HttpOnly/SameSite Strict. Plain HTTP browser login is not a production deployment.

Log in, create an agent enrollment token, and enroll each VPS. Configure each host's current public address. Add its intended TCP/TLS/HTTP probe targets. Deploy independent mainland probes and controls before interpreting block states. No public self-registration is available. Admins can create read-only viewer accounts.

The overview is bounded to 24 hours of audit activity. Search requires a query, runs server-side, and defaults to 24 hours. Lists paginate. CSV exports are admin-only, audited, bounded to seven days and 100,000 rows by default (`EXPORT_MAX_DAYS`, `EXPORT_MAX_ROWS`).

## Update and backup

Run `bash backup.sh /secure/new-backup-dir` before every update. It captures a consistent custom-format `pg_dump`, deployment config and `.env`. Restore only to a compatible release using `bash restore.sh /secure/backup-dir`. Restore stops API/workers, restores the database in one transaction, migrates, then starts services. Credentials in backups are sensitive; encrypt backups outside this project and test restoration regularly.

`bash update-central.sh /secure/new-backup-dir` backs up, checks Compose, builds images, applies Alembic migrations and recreates changed containers. It does not contact or restart any Xray VPS. Keep the previous source/image release available. Database downgrade is not the rollback mechanism: restore the saved database and previous images when required.

To stop central without deleting data, use `docker compose down`. `docker compose down -v` destroys database volumes and is never part of a normal update.
