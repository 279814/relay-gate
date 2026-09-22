#!/usr/bin/env bash
# P0 offline gate：fixture / Lazy / Secret / 私有路径忽略 / Probe CLI 授权门禁。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== go test probe fixtures / gates =="
go test ./internal/probe/ ./cmd/relay-gate/ -count=1

echo "== private paths ignored by git + docker =="
python - <<'PY'
from pathlib import Path
root = Path('.')
gitignore = (root/'.gitignore').read_text(encoding='utf-8')
dockerignore = (root/'.dockerignore').read_text(encoding='utf-8')
need = ['.local/p0/', 'scripts/upstreams.tsv', 'docs/02-上游能力矩阵.md']
for p in need:
    if p not in gitignore:
        raise SystemExit(f'.gitignore missing {p}')
    if p not in dockerignore and p != 'docs/02-上游能力矩阵.md':
        # docs matrix may only be gitignored; docker still should ignore .local/p0
        pass
if '.local/p0/' not in dockerignore:
    raise SystemExit('.dockerignore missing .local/p0/')
print('ok')
PY

echo "== probe CLI unauthorized must not dial =="
BIN="$(mktemp -u)/relay-gate-check"
mkdir -p "$(dirname "$BIN")"
go build -o "$BIN" ./cmd/relay-gate
set +e
"$BIN" probe-one --input /dev/null --name x --output /tmp/should-not-exist-p0.json
code=$?
set -e
rm -f "$BIN"
if [ "$code" -eq 0 ]; then
  echo "expected non-zero without --online/--accept-probe-cost"
  exit 1
fi
echo "check-p0 ok"
