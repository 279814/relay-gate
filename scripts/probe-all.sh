#!/usr/bin/env bash
# Thin wrapper：定位 binary、校验 ignored 路径，调用 relay-gate probe-matrix。
# 不再实现 UA/Auth/stream/error 判断 —— 全部由 CLI 使用生产 Decoder/Classifier。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IN="${1:?usage: probe-all.sh <ignored-tsv>}"
OUT_JSON="${2:-$ROOT/.local/p0/reports/probe-matrix.json}"
OUT_MD="${3:-$ROOT/.local/p0/reports/probe-matrix.md}"
MANIFEST="${CONTROL_MANIFEST:-}"

BIN="${RELAY_GATE_BIN:-}"
if [ -z "$BIN" ]; then
  BIN="$ROOT/relay-gate"
  if [ ! -x "$BIN" ]; then
    go build -o "$BIN" "$ROOT/./cmd/relay-gate"
  fi
fi

case "$IN" in
  *.tsv|*/upstreams.tsv|*/.local/*) ;;
  *) echo "输入应是被 gitignore 的 TSV（见 upstreams.example.tsv）" >&2; exit 1 ;;
esac

mkdir -p "$(dirname "$OUT_JSON")" "$(dirname "$OUT_MD")"
args=(probe-matrix --online --accept-probe-cost --input "$IN" --output "$OUT_JSON" --report "$OUT_MD")
if [ -n "$MANIFEST" ]; then
  args+=(--control-manifest "$MANIFEST" --accept-control-replay)
fi
exec "$BIN" "${args[@]}"
