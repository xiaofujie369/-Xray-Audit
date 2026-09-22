#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
SOURCE="${1:?Usage: restore.sh /backup/directory}"
test -s "$SOURCE/audit.dump"
read -r -p 'Replace central database using this backup? Type RESTORE: ' answer
[ "$answer" = RESTORE ] || exit 1
docker compose stop audit-api audit-worker audit-ai-worker audit-scheduler
umask 077
restore_sql=$(mktemp)
trap 'rm -f -- "$restore_sql"' EXIT
# Decode fully before replacing the schema. A single transaction also supports
# restoring a V1 backup into V2 without new tables blocking old-table drops.
docker compose exec -T postgres pg_restore --no-owner --no-privileges < "$SOURCE/audit.dump" > "$restore_sql"
docker compose exec -T postgres psql -U audit -d audit -v ON_ERROR_STOP=1 --single-transaction \
  -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION audit;' -f - < "$restore_sql"
docker compose run --rm audit-migrate
docker compose up -d
