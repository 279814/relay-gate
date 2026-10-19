#!/usr/bin/env bash
# Thin authorization/argument adapter; URL/Auth/stream/classification belong to Go.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command_name="${1:-}"
shift || true
case "$command_name" in probe-one|probe-matrix) ;; *) exit 2 ;; esac

online=0
cost=0
control=0
replay=0
forwarded=()
while (( $# )); do
  case "$1" in
    --online) online=1; forwarded+=("$1"); shift ;;
    --accept-probe-cost) cost=1; forwarded+=("$1"); shift ;;
    --accept-control-replay) replay=1; forwarded+=("$1"); shift ;;
    --input|--name|--output|--report|--base-url|--key-env|--claude-model|--gpt-model|--control-manifest)
      if (( $# < 2 )); then echo 'Missing option value.' >&2; exit 2; fi
      if [[ "$1" == --control-manifest ]]; then control=1; fi
      forwarded+=("$1" "$2")
      shift 2
      ;;
    *) echo 'Use named CLI options; plaintext Key arguments are not accepted.' >&2; exit 2 ;;
  esac
done
if (( ! online || ! cost || (control && ! replay) )); then
  echo 'Explicit --online --accept-probe-cost are required; control also requires --accept-control-replay.' >&2
  exit 2
fi

BIN="${RELAY_GATE_BIN:-}"
if [[ -z "$BIN" ]]; then
  BIN="$ROOT/relay-gate"
  (cd "$ROOT" && go build -o "$BIN" ./cmd/relay-gate)
fi
exec "$BIN" "$command_name" "${forwarded[@]}"
