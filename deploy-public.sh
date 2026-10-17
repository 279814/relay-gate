#!/usr/bin/env bash
# Linux public-IP HTTPS deployment. Never falls back to a plaintext gateway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
ip=""
confirmation=""
mode=install
while (( $# )); do
  case "$1" in
    --ip|--confirm-ip)
      if (( $# < 2 )); then echo "$1 requires an IP" >&2; exit 2; fi
      if [[ "$1" == --ip ]]; then ip=$2; else confirmation=$2; fi
      shift 2 ;;
    --status) mode=status; shift ;;
    --renew) mode=renew; shift ;;
    *) echo "Unknown public option: $1" >&2; exit 2 ;;
  esac
done
if [[ "$(uname -s)" != Linux ]]; then
  echo "Public HTTPS requires a Linux host; the default HTTP installer supports this host." >&2
  exit 2
fi

if [[ "$mode" == install ]]; then
  if [[ -z "$ip" ]]; then
    if ! command -v curl >/dev/null 2>&1; then echo "curl is required for public IP discovery; or pass --ip." >&2; exit 2; fi
    ip=$(curl -4fsS --connect-timeout 3 --max-time 8 https://api.ipify.org)
    echo "Detected public IP: $ip"
  fi
  # Restrict interpolation before building/running containers. The Go edge
  # performs the authoritative globally routable-IP validation before issuance.
  if [[ ! "$ip" =~ ^[0-9A-Fa-f:.]+$ ]]; then echo "Invalid public IP syntax." >&2; exit 2; fi
  if [[ -z "$confirmation" && -t 0 ]]; then
    echo "Confirm that $ip is this Linux host and that public TCP 80/443 reach it."
    read -r -p "Type the exact public IP to continue: " confirmation
  fi
  if [[ "$confirmation" != "$ip" ]]; then
    echo "Explicit target confirmation required: --confirm-ip $ip" >&2
    exit 2
  fi
fi

if ! command -v docker >/dev/null 2>&1; then echo "Docker and Compose are required." >&2; exit 2; fi
docker compose version >/dev/null
public_file="$ROOT/deploy/compose.public.yaml"
state="$ROOT/data-public"
env_file="$state/public.env"
public_project="relay-gate-public-$(printf '%s' "$ROOT" | cksum | cut -d ' ' -f 1)"
compose=(docker compose --project-directory "$ROOT" --project-name "$public_project" -f "$public_file")
if [[ -f "$ROOT/.env" ]]; then compose+=(--env-file "$ROOT/.env"); fi

if [[ "$mode" != install ]]; then
  if [[ ! -f "$env_file" ]]; then echo "No confirmed public deployment state; install first." >&2; exit 2; fi
  # Compose reads this as dotenv data; never execute/source environment files.
  compose+=(--env-file "$env_file")
  if [[ "$mode" == status ]]; then
    "${compose[@]}" exec -T public-edge relay-public-edge --status
  else
    "${compose[@]}" kill --signal SIGUSR1 public-edge
    echo "Renewal requested. Inspect ./deploy.sh --public --status and public-edge logs."
  fi
  exit 0
fi

# Build/validate the target before stopping the old listener or creating ACME
# accounts. This helper does no networking and starts neither Nginx nor Certbot.
export RELAY_PUBLIC_IP="$ip" RELAY_CONFIRMED_PUBLIC_IP="$ip"
if [[ "$ip" == *:* ]]; then export RELAY_PUBLIC_ORIGIN="https://[$ip]"; else export RELAY_PUBLIC_ORIGIN="https://$ip"; fi
"${compose[@]}" build public-edge
canonical=$("${compose[@]}" run --rm --no-deps public-edge --check-ip --ip "$ip")
if [[ ! "$canonical" =~ ^[0-9A-Fa-f:.]+$ ]]; then echo "Public IP validation failed." >&2; exit 1; fi
export RELAY_PUBLIC_IP="$canonical" RELAY_CONFIRMED_PUBLIC_IP="$canonical"
if [[ "$canonical" == *:* ]]; then export RELAY_PUBLIC_ORIGIN="https://[$canonical]"; else export RELAY_PUBLIC_ORIGIN="https://$canonical"; fi
umask 077
mkdir -p "$state/status" "$ROOT/data"
chmod 700 "$state" "$ROOT/data"
chmod 755 "$state/status"
temp_env=$(mktemp "$state/.public-env.XXXXXX")
trap 'rm -f "$temp_env"' EXIT
printf 'RELAY_PUBLIC_IP=%s\nRELAY_CONFIRMED_PUBLIC_IP=%s\nRELAY_PUBLIC_ORIGIN=%s\n' "$canonical" "$canonical" "$RELAY_PUBLIC_ORIGIN" > "$temp_env"
chmod 600 "$temp_env"
mv -f "$temp_env" "$env_file"
compose+=(--env-file "$env_file")

# Only the default Compose project belonging to this checkout is stopped. This
# removes its published 18787 port before the separate HTTPS project starts.
old=(docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml")
if [[ -n "$("${old[@]}" ps -q relay-gate)" ]]; then
  echo "Stopping this checkout's HTTP deployment before enabling HTTPS..."
  "${old[@]}" down --timeout 35
fi
"${compose[@]}" up -d --build
echo "Waiting for validated public-IP TLS; ACME-only mode returns 503 for all business routes..."
for (( attempt=0; attempt<180; attempt++ )); do
  status=$("${compose[@]}" exec -T public-edge relay-public-edge --status 2>/dev/null || true)
  if [[ "$status" =~ \"phase\"[[:space:]]*:[[:space:]]*\"live_https\" && "$status" =~ \"business_allowed\"[[:space:]]*:[[:space:]]*true ]]; then
    echo "Open $RELAY_PUBLIC_ORIGIN/admin/"
    echo "Status: ./deploy.sh --public --status"
    echo "First-start credentials: docker compose --project-directory '$ROOT' --project-name '$public_project' -f '$public_file' --env-file '$env_file' logs --no-color --no-log-prefix relay-gate"
    exit 0
  fi
  if [[ "$status" =~ \"phase\"[[:space:]]*:[[:space:]]*\"(failed|expired)\" ]]; then
    echo "Public TLS setup failed. Business remains closed; inspect public-edge logs and --status." >&2
    exit 1
  fi
  sleep 2
done
echo "Timed out waiting for public TLS. Business remains gated; use --public --status." >&2
exit 1
