#!/usr/bin/env bash
# One-command install: local or Linux server with Docker.
# Access: http://<host-IP>:${RELAY_PORT:-18787}/admin/
# First start prints ADMIN_PASSWORD / RELAY_KEYS / ENCRYPTION_KEY once (container logs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker, then re-run ./deploy.sh" >&2
  exit 2
fi

mkdir -p data
chmod 700 data 2>/dev/null || true

echo "Building and starting relay-gate (http://0.0.0.0:${RELAY_PORT:-18787})..."
docker compose up -d --build

echo
echo "Waiting for healthz..."
ok=0
for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${RELAY_PORT:-18787}/healthz" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 1
done
if [[ "$ok" -ne 1 ]]; then
  echo "Service did not become healthy. Recent logs:" >&2
  docker compose logs --tail=80
  exit 1
fi

echo
echo "Open http://<this-host-IP>:${RELAY_PORT:-18787}/admin/"
echo "On first start, three secrets are printed once in the container log:"
echo "  docker compose logs --no-color 2>&1 | sed -n '/ADMIN_PASSWORD=/p;/RELAY_KEYS=/p;/ENCRYPTION_KEY=/p'"
echo "Later restarts do not reprint them. Env still wins if you set ENCRYPTION_KEY / RELAY_KEYS / ADMIN_PASSWORD."
