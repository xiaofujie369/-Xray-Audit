#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
bash ./backup.sh "${1:?Supply a new backup directory}"
docker compose config --quiet
docker compose build
docker compose run --rm audit-migrate
docker compose up -d
