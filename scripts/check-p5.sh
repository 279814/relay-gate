#!/usr/bin/env bash
# P5 release validation gate（离线）：schema 6 终态、Keyring、备份拒绝门、
# 安全扫描不改字节、Transform 未绑定透传、RecoveryGate single-flight。
# 不覆盖公网证书签发或多日 soak——那些不得在本脚本里冒充通过。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== P5 release package tests =="
go test ./internal/release/ -count=1

echo "== docs/03 still present (public IP cert not verified) =="
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

echo "== release notes must not claim public cert or multi-day soak done =="
python - <<'PY'
from pathlib import Path
text = Path('docs/RELEASE-NOTES-v1.0.0.md').read_text(encoding='utf-8')
# Require honest leftovers; reject phrasing that asserts completion.
bad = [
    '公网证书已验证',
    '多日 soak 已完成',
    '生产 soak 已通过',
    '已完成多日 soak',
]
for claim in bad:
    if claim in text:
        raise SystemExit(f'release notes falsely claim: {claim}')
# Must still name the two explicit leftovers.
if '真实公网证书' not in text:
    raise SystemExit('release notes missing 真实公网证书 leftover')
if '多日' not in text or 'soak' not in text.lower():
    raise SystemExit('release notes missing multi-day soak leftover')
# Must not assert a live public cert was issued (allow 「未签发」/「不得声称」).
if '已签发公网证书' in text and '未' not in text[max(0, text.index('已签发公网证书')-12):text.index('已签发公网证书')]:
    # Only fail when the nearby prefix lacks 未 / 不得 / 声称.
    idx = text.index('已签发公网证书')
    window = text[max(0, idx-16):idx]
    if '未' not in window and '不得' not in window and '声称' not in window:
        raise SystemExit('release notes appear to claim public cert issued')
print('ok')
PY

echo "check-p5 ok"
