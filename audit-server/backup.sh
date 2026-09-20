#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077
DEST="${1:?Usage: backup.sh /absolute/new-backup-directory}"
[ ! -e "$DEST" ] || { echo 'Destination already exists'; exit 1; }
mkdir -p -- "$DEST"
cp .env docker-compose.yml "$DEST/"
docker compose exec -T postgres pg_dump -U audit -d audit -Fc > "$DEST/audit.dump"
test -s "$DEST/audit.dump"
echo 'Backup includes credentials: keep this directory private.'
