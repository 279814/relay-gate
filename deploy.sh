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
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for the health check. Install curl, then re-run ./deploy.sh" >&2
  exit 2
fi

mkdir -p data
chmod 700 data 2>/dev/null || true

echo "Building and starting relay-gate..."
docker compose up -d --build

# Ask Compose for the actual binding: it already resolved .env, environment
# overrides and any Compose overrides. Never source .env as executable shell.
if ! bindings=$(docker compose port relay-gate 18787); then
  echo "Could not resolve relay-gate's published port." >&2
  exit 1
fi
binding=${bindings%%$'\n'*}
binding=${binding%$'\r'}
binding_pattern='^(\[[^]]+\]|[^:[:space:]]+):([0-9]{1,5})$'
if [[ ! "$binding" =~ $binding_pattern ]]; then
  echo "No valid published port for relay-gate:18787." >&2
  exit 1
fi
port=$((10#${BASH_REMATCH[2]}))
if (( port < 1 || port > 65535 )); then
  echo "Published relay-gate port must be between 1 and 65535." >&2
  exit 1
fi

echo
echo "Waiting for healthz..."
ok=0
for i in $(seq 1 60); do
  if curl -fsS --connect-timeout 2 --max-time 2 "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
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
echo "Open http://<this-host-IP>:${port}/admin/"
echo "On first start, three secrets are printed once in the container log:"
echo "  docker compose logs --no-color --no-log-prefix 2>&1 | sed -n '/ADMIN_PASSWORD=/p;/RELAY_KEYS=/p;/ENCRYPTION_KEY=/p'"
echo "Later restarts do not reprint them. Env still wins if you set ENCRYPTION_KEY / RELAY_KEYS / ADMIN_PASSWORD."
