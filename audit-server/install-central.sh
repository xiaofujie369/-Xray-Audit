#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077
if [ ! -f .env ]; then
  cp .env.example .env
  echo 'Edit .env: configure HTTPS reverse proxy, strong secrets, and matching PostgreSQL URL/password.'
  exit 1
fi
chmod 600 .env
docker compose config --quiet
docker compose build --pull
if [ "${1:-}" = --https ]; then
  docker compose --profile https up -d
else
  docker compose up -d
fi
echo 'Central listens on 127.0.0.1:8080. Configure the HTTPS reverse proxy before enrollment.'
