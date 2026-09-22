#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
bash ./backup.sh "${1:?Supply a new backup directory}"
shift
apply_retention=false
https=false
for option in "$@"; do
  case "$option" in
    --retention-seven-days) apply_retention=true ;;
    --https) https=true ;;
    *) echo "Unknown option: $option" >&2; exit 2 ;;
  esac
done
docker compose config --quiet
docker compose build
# Stop all database writers before establishing the migration's backfill boundary.
docker compose stop audit-api audit-worker audit-ai-worker audit-scheduler
docker compose run --rm audit-migrate
if "$apply_retention"; then
  docker compose run --rm audit-migrate python -m app.retention_policy
fi
if "$https"; then
  docker compose --profile https up -d
else
  docker compose up -d
fi
echo 'Central updated. Check event evidence and Probe versions in the dashboard.'
