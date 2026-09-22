#!/usr/bin/env bash
# Local one-line deploy (P2 §12.1). Does NOT replace docs/03 public nginx guide.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

MODE="${1:-}"
if [[ "$MODE" != "--local" ]]; then
  echo "Usage: ./deploy.sh --local"
  echo "Public IP mode is not verified in this PR; keep using docs/03 for domain/nginx deploys."
  exit 2
fi

rand_hex() { openssl rand -hex "$1"; }

if [[ ! -f .env ]]; then
  ENC="$(rand_hex 32)"
  RELAY="rk-$(rand_hex 24)"
  ADMIN="$(rand_hex 24)"
  cat > .env <<EOF
ENCRYPTION_KEY=$ENC
RELAY_KEYS=$RELAY
ADMIN_PASSWORD=$ADMIN
EOF
  chmod 600 .env
  echo "Wrote .env with one-time credentials (shown once below):"
  echo "ADMIN_PASSWORD=$ADMIN"
  echo "RELAY_KEYS=$RELAY"
  echo "ENCRYPTION_KEY=$ENC"
else
  echo ".env already exists; not regenerating credentials."
fi

mkdir -p data/secrets
chmod 700 data data/secrets || true

echo "Building relay-gate..."
go build -o relay-gate ./cmd/relay-gate
echo "Start with: ./relay-gate"
echo "Admin UI: http://127.0.0.1:18787/admin/"
