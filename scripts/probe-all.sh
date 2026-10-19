#!/usr/bin/env bash
# Named private TSV/stdin or environment sources only; never plaintext Key argv.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "$ROOT/scripts/probe-cli-wrapper.sh" probe-matrix "$@"
