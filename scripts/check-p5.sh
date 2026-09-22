#!/usr/bin/env bash
# P5 release validation gate（离线）：迁移终态、Keyring、备份拒绝门、
# 安全扫描不改字节、Transform 未绑定透传、RecoveryGate single-flight。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== P5 release package tests =="
go test ./internal/release/ -count=1

echo "== docs/03 still present (P2 public IP not verified) =="
test -f docs/03-部署与配置.md
test -f docs/RELEASE-NOTES-v1.0.0.md
test -f docs/09-P5-发布验证.md

echo "== secrets / private assets stay untracked =="
python - <<'PY'
from pathlib import Path
import subprocess
root = Path('.')
tracked = subprocess.check_output(['git', 'ls-files'], text=True, encoding='utf-8')
forbidden = ['.env', 'upstreams.tsv', 'docs/02-上游能力矩阵.md']
for name in forbidden:
    for line in tracked.splitlines():
        if line == name or line.endswith('/' + name) or line.endswith('\\' + name):
            raise SystemExit(f'tracked forbidden path: {line}')
print('ok')
PY

echo "check-p5 ok"
