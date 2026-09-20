#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
SOURCE="${1:?Usage: restore.sh /backup/directory}"
test -s "$SOURCE/audit.dump"
read -r -p 'Replace central database using this backup? Type RESTORE: ' answer
[ "$answer" = RESTORE ] || exit 1
docker compose stop audit-api audit-worker audit-scheduler
docker compose exec -T postgres pg_restore -U audit -d audit --clean --if-exists --single-transaction < "$SOURCE/audit.dump"
docker compose run --rm audit-migrate
docker compose up -d
