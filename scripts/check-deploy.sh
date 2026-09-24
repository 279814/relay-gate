#!/bin/sh
# 部署清单的静态检查。不需要 Docker，因此能进 CI。
#
# 盯的是「一旦写错就有实际后果、但不会报错」的不变量：
# HTTP IP:port 发布、无域名/ACME/登录 IP 白名单、凭据不进构建上下文、
# ENTRYPOINT exec 形式、无 CGO、可选 .env 三项凭据。
#
# 跑法：sh scripts/check-deploy.sh

set -eu

root="$(dirname "$0")/.."
compose="$root/compose.yaml"
dockerfile="$root/Dockerfile"
dockerignore="$root/.dockerignore"
envexample="$root/.env.example"
caddyfile="$root/deploy/Caddyfile"
deploy_nginx="$root/scripts/deploy-nginx.sh"
docs03="$root/docs/03-部署与配置.md"

fails=0
fail() {
    echo "  [FAIL] $1" >&2
    fails=$((fails + 1))
}
pass() { echo "  [PASS] $1"; }

echo "=== 宿主机端口发布到所有接口（HTTP IP:port）==="
# 支持的安装形态是 http://IP:port，不再绑 127.0.0.1 或经 Caddy/nginx。
if grep -qE '^[[:space:]]*-[[:space:]]*"\$\{RELAY_PORT:-[0-9]+\}:[0-9]+"' "$compose"; then
    pass '网关 ports 发布到所有接口（无 127.0.0.1 前缀）'
else
    fail 'compose ports 应为 "${RELAY_PORT:-18787}:18787" 形式（发布到所有接口）'
fi
if grep -qE '127\.0\.0\.1:\$\{RELAY_PORT' "$compose"; then
    fail 'compose 仍把端口绑在 127.0.0.1 —— 与 http://IP:port 安装形态冲突'
else
    pass 'compose 未把端口限制在 127.0.0.1'
fi

echo "=== 已移除域名 / ACME / 登录 IP 白名单部署入口 ==="
if [ -e "$caddyfile" ]; then
    fail "仍存在 deploy/Caddyfile —— 旧域名/ACME 路径应已删除"
else
    pass 'deploy/Caddyfile 已删除'
fi
if [ -e "$deploy_nginx" ]; then
    fail "仍存在 scripts/deploy-nginx.sh —— 旧域名/白名单路径应已删除"
else
    pass 'scripts/deploy-nginx.sh 已删除'
fi
if [ -e "$docs03" ]; then
    fail "仍存在 docs/03 —— 旧域名部署指南应已删除"
else
    pass 'docs/03 已删除'
fi
if grep -qE 'RELAY_(DOMAIN|ACME_EMAIL|ALLOW_IPS)' "$compose" "$envexample" 2>/dev/null; then
    fail 'compose / .env.example 仍引用 RELAY_DOMAIN / RELAY_ACME_EMAIL / RELAY_ALLOW_IPS'
else
    pass '部署模板不再要求域名、ACME 邮箱或登录 IP 白名单'
fi
if grep -qE 'profiles:[[:space:]]*\[["'"'"']public' "$compose" || grep -qE 'caddy:' "$compose"; then
    fail 'compose 仍含 public profile / caddy 服务'
else
    pass 'compose 仅单容器网关（无 Caddy）'
fi

echo "=== 优雅关闭的宽限期要大于进程自己的收尾时间 ==="
grace=$(grep -oE '^[[:space:]]*stop_grace_period:[[:space:]]*[0-9]+' "$compose" |
    grep -oE '[0-9]+$' || echo 0)
if [ "$grace" -gt 30 ]; then
    pass "stop_grace_period=${grace}s，大于进程自己的 30s 收尾窗口"
else
    fail "stop_grace_period=${grace}s，不大于 main.go 的 30s —— 在途的流会被 SIGKILL 掐断"
fi

echo "=== 构建上下文不含凭据 ==="
for pat in 'data/' '.env' 'scripts/upstreams.tsv'; do
    if sed 's/#.*//' "$dockerignore" | sed 's/[[:space:]]*$//' |
        grep -qxF "$pat"; then
        pass ".dockerignore 排除了 $pat"
    else
        fail ".dockerignore 没有排除 $pat —— 凭据或对话原文会进构建上下文"
    fi
done

echo "=== ENTRYPOINT 必须是 exec 形式 ==="
if grep -qE '^ENTRYPOINT[[:space:]]*\[' "$dockerfile"; then
    pass 'ENTRYPOINT 用 JSON 数组（exec 形式）'
else
    fail 'ENTRYPOINT 是 shell 形式 —— PID 1 会是 shell，SIGTERM 不转发'
fi

echo "=== 镜像必须无 CGO ==="
if grep -qE 'CGO_ENABLED=0' "$dockerfile"; then
    pass 'CGO_ENABLED=0'
else
    fail '没有 CGO_ENABLED=0'
fi

echo "=== GOPROXY 必须声明为 ARG ==="
if grep -qE '^ARG[[:space:]]+GOPROXY=' "$dockerfile"; then
    pass 'Dockerfile 声明了 ARG GOPROXY'
else
    fail 'Dockerfile 缺 ARG GOPROXY'
fi

echo "=== .env.example 不再把三项凭据标成必填 ==="
# 三项可注释留空；首次启动 bootstrap。不应再要求域名/白名单。
if grep -qE '^ENCRYPTION_KEY=$' "$envexample" || grep -qE '^# ENCRYPTION_KEY=' "$envexample"; then
    pass '.env.example 允许 ENCRYPTION_KEY 缺省（首次自动生成）'
else
    fail '.env.example 对 ENCRYPTION_KEY 的缺省约定不清晰'
fi
for key in RELAY_DOMAIN RELAY_ACME_EMAIL RELAY_ALLOW_IPS; do
    if grep -qE "^${key}=" "$envexample"; then
        fail ".env.example 仍含 $key"
    fi
done
pass '.env.example 无域名 / ACME / 登录 IP 白名单键'

echo "=== 送进容器 shell 的 here-string 必须先转成 LF ==="
for ps1 in "$root"/scripts/*.ps1; do
    [ -e "$ps1" ] || continue
    raw=$(grep -cE "sh +-ec +@'" "$ps1" || true)
    if [ "$raw" -gt 0 ]; then
        fail "$(basename "$ps1") 有 $raw 处把 here-string 直接交给 sh -ec —— 应先过 ShLF"
    else
        pass "$(basename "$ps1") 的内嵌 shell 都经过 LF 转换"
    fi
done

echo
if [ "$fails" -gt 0 ]; then
    echo "$fails 项失败" >&2
    exit 1
fi
echo "全部通过"
