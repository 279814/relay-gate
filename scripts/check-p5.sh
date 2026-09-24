#!/usr/bin/env bash
# P5 release validation gate（离线）：schema 6 终态、Keyring、备份拒绝门、
# 安全扫描不改字节、Transform 未绑定透传、RecoveryGate single-flight、
# IP 证书续期可观测（fake RenewWatch；不冒充真实公网签发）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== P5 release package tests =="
go test ./internal/release/ -count=1

echo "== release docs present =="
test -f docs/RELEASE-NOTES-v1.0.0.md
test -f docs/09-P5-发布验证.md
# Old domain/cert deploy guide must stay deleted for HTTP IP:port install.
if [ -e docs/03-部署与配置.md ]; then
  echo "docs/03 should remain deleted" >&2
  exit 1
fi
if [ -e deploy/Caddyfile ] || [ -e scripts/deploy-nginx.sh ]; then
  echo "Caddyfile / deploy-nginx.sh should remain deleted" >&2
  exit 1
fi

echo "== secrets / private assets stay untracked =="
python - <<'PY'
from pathlib import Path
import subprocess
tracked = subprocess.check_output(['git', 'ls-files'], text=True, encoding='utf-8')
forbidden = ['.env', 'upstreams.tsv', 'docs/02-上游能力矩阵.md']
for name in forbidden:
    for line in tracked.splitlines():
        if line == name or line.endswith('/' + name) or line.endswith('\\' + name):
            raise SystemExit(f'tracked forbidden path: {line}')
print('ok')
PY

echo "== release notes must not claim public cert or multi-day prod validation done =="
python - <<'PY'
from pathlib import Path
text = Path('docs/RELEASE-NOTES-v1.0.0.md').read_text(encoding='utf-8')
bad = [
    '公网证书已验证',
    '多日 soak 已完成',
    '生产 soak 已通过',
    '已完成多日 soak',
]
for claim in bad:
    if claim in text:
        raise SystemExit(f'release notes falsely claim: {claim}')
if '真实公网证书' not in text:
    raise SystemExit('release notes missing 真实公网证书 leftover')
# Must not assert a live public cert was issued (allow 「未签发」/「不得声称」).
if '已签发公网证书' in text:
    idx = text.index('已签发公网证书')
    window = text[max(0, idx-16):idx]
    if '未' not in window and '不得' not in window and '声称' not in window:
        raise SystemExit('release notes appear to claim public cert issued')
print('ok')
PY

echo "check-p5 ok"
