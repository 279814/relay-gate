#!/usr/bin/env bash
# Thin wrapper：单站 Probe（probe-one）。判断逻辑全部在 CLI。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="${1:?usage: probe-upstream.sh <base_url> <api_key> <claude_models> <gpt_models> <name>}"
KEY="${2:?}"
CLAUDE="${3:--}"
GPT="${4:--}"
NAME="${5:?}"
IN_TSV="$(mktemp)"
trap 'rm -f "$IN_TSV"' EXIT
# Key 只写进临时 TSV，不作为子进程长 argv 持久化到 shell history 之外的二次封装。
printf '%s\t%s\t%s\t%s\t%s\t\n' "$NAME" "$BASE" "$KEY" "$CLAUDE" "$GPT" >"$IN_TSV"

BIN="${RELAY_GATE_BIN:-}"
if [ -z "$BIN" ]; then
  BIN="$ROOT/relay-gate"
  if [ ! -x "$BIN" ]; then
    go build -o "$BIN" "$ROOT/./cmd/relay-gate"
  fi
fi
OUT="$ROOT/.local/p0/reports/probe-one-${NAME}.json"
mkdir -p "$(dirname "$OUT")"
exec "$BIN" probe-one --online --accept-probe-cost --input "$IN_TSV" --name "$NAME" --output "$OUT"
