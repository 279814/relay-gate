#!/bin/sh
# 部署清单的静态检查（M7）。**不需要 Docker**，因此能进 CI。
#
# 它盯的是几条「一旦写错就有实际安全后果、但不会报错」的不变量。
# 真正的容器行为由 scripts/smoke-m7.ps1 验（那个需要 Docker 引擎）；
# 这里守的是那些光读文件就能判定、且值得每次提交都查的部分。
#
# 跑法：sh scripts/check-deploy.sh

set -eu

root="$(dirname "$0")/.."
compose="$root/compose.yaml"
caddyfile="$root/deploy/Caddyfile"
dockerfile="$root/Dockerfile"
dockerignore="$root/.dockerignore"
envexample="$root/.env.example"

fails=0
fail() {
    echo "  [FAIL] $1" >&2
    fails=$((fails + 1))
}
pass() { echo "  [PASS] $1"; }

echo "=== 端口只绑 127.0.0.1（§5.2f）==="
# 这是整份部署里安全后果最重的一行。写成 "18787:18787" 的话 Docker 会插一条
# iptables 规则把端口直接暴露到公网，**而且绕过 ufw/firewalld** ——
# 你在防火墙里看不到，`ufw status` 显示一切正常。
# 那等于把管理界面和所有上游 key 公开。
if grep -qE '^[[:space:]]*-[[:space:]]*"127\.0\.0\.1:\$\{RELAY_PORT:-[0-9]+\}:[0-9]+"' "$compose"; then
    pass '网关端口带 127.0.0.1 前缀'
else
    fail '网关的 ports 没有 127.0.0.1 前缀 —— Docker 会绕过防火墙把它暴露到公网'
fi

echo "=== Caddy 的必填变量不能用 :? 语法 ==="
# compose 的变量插值发生在 profile 过滤**之前**，所以 caddy 段里一个
# ${VAR:?...} 会让根本不起 Caddy 的 `docker compose up -d` 直接报错退出 ——
# 而那是这个项目最常走的路径。（实测踩到过。）
#
# 必须**先剥掉注释再匹配**：这份 compose 的注释里就写着「这里不能用
# ${RELAY_DOMAIN:?...}」这句解释，连着正则一起命中的话，正确的实现会被
# 自己的说明文字判成违规。（第一版就是这么误报的。）
if sed 's/#.*//' "$compose" |
    grep -qE '\$\{RELAY_(DOMAIN|ACME_EMAIL|ALLOW_IPS):\?'; then
    fail 'caddy 段用了 ${VAR:?...} —— 默认的 docker compose up 会跟着失败'
else
    pass '公网变量都用软默认（:-），不拖累默认路径'
fi

echo "=== 空 ACME 邮箱不会产生非法 Caddyfile ==="
# Caddy 的 `email` global option 在值为空时不是「不设置」，而是
# **语法错误（email 缺参数）** —— 公网 profile 会启动即退出。
# compose 的 command 用 sed 在邮箱为空时删掉这一行，所以两件事都要成立：
#   1. compose 里真的有那段条件删除
#   2. 那个 sed 的正则真的能匹配 Caddyfile 里的那一行
if grep -q 'RELAY_ACME_EMAIL' "$compose" && grep -q 'sed' "$compose"; then
    pass 'compose 里有条件删除 email 的逻辑'
else
    fail 'compose 缺少「邮箱为空时删掉 email 行」的处理 —— 公网 profile 会启动即退出'
fi

# 直接跑一遍那个 sed，断言结果里不再有 email 指令。
# 只检查「compose 里有 sed」不够 —— 正则写错了照样匹配不到，
# 而症状是 Caddy 报一个与邮箱毫无关系的语法错误。
remaining=$(sed '/^[[:space:]]*email[[:space:]].*RELAY_ACME_EMAIL.*$/d' "$caddyfile" |
    grep -c 'email' || true)
if [ "$remaining" -eq 0 ]; then
    pass 'sed 的正则确实能删掉 Caddyfile 里那一行'
else
    fail "sed 之后还剩 $remaining 行 email —— 正则与 Caddyfile 的实际缩进对不上"
fi

echo "=== 管理面白名单默认拒绝，而不是默认放行 ==="
# 忘了配 RELAY_ALLOW_IPS 的后果应该是「我进不去管理界面」（立刻发现、
# 自己动手修），而不是「全世界都能进我的管理界面」（永远不会发现）。
# 判据是 `not remote_ip`：列表为空时它匹配任何来源，于是全部 403。
if grep -qE '@notAllowed[[:space:]]+not[[:space:]]+remote_ip[[:space:]]+\{\$RELAY_ALLOW_IPS\}' "$caddyfile"; then
    pass '白名单为空时管理面全部 403（not remote_ip）'
else
    fail '管理面的白名单判据不是 `not remote_ip {$RELAY_ALLOW_IPS}` —— '\
'空值可能变成「放行所有人」'
fi

echo "=== SSE 不能被缓冲 ==="
# 一旦缓冲，流式输出会变成「长时间无反应后一次性刷出」，
# 而那正是这个项目要优化的东西。
if grep -qE '^[[:space:]]*flush_interval[[:space:]]+-1' "$caddyfile"; then
    pass 'reverse_proxy 显式 flush_interval -1'
else
    fail '缺少 flush_interval -1 —— 将来有人加 buffer 时没有防线'
fi

echo "=== 长思考的超时必须放宽（§4.2）==="
# 首 Token 可达 20 分钟，期间连接上没有任何字节。
# 不放宽的话 Caddy 会在默认超时后掐断一个完全正常的请求。
if grep -qE 'response_header_timeout[[:space:]]+[0-9]+m' "$caddyfile"; then
    pass 'response_header_timeout 已按分钟级放宽'
else
    fail 'response_header_timeout 没放宽 —— 正常的长思考会被 Caddy 掐断'
fi

echo "=== 优雅关闭的宽限期要大于进程自己的收尾时间 ==="
# main.go 给在途请求留了 30s。compose 的 stop_grace_period 若小于它，
# 进程还没收完就被 SIGKILL，每次重启都掐断一次正在进行的对话。
grace=$(grep -oE '^[[:space:]]*stop_grace_period:[[:space:]]*[0-9]+' "$compose" |
    grep -oE '[0-9]+$' || echo 0)
if [ "$grace" -gt 30 ]; then
    pass "stop_grace_period=${grace}s，大于进程自己的 30s 收尾窗口"
else
    fail "stop_grace_period=${grace}s，不大于 main.go 的 30s —— 在途的流会被 SIGKILL 掐断"
fi

echo "=== 构建上下文不含凭据 ==="
# data/ 里有明文样本（完整对话原文），.env 里有三项凭据。
# 它们不会进最终镜像（运行阶段只 COPY 二进制），但会留在构建缓存层里，
# 而镜像层是可以逐层导出的。
#
# 判据必须是**整行精确匹配**，不能用 grep -F 做子串匹配：
# 子串匹配下把 `.env` 注释成 `#.env` 仍然会被 `.env.local` 那一行命中，
# 把 `data/` 注释成 `#data/` 也会被自己命中 —— 检查器全绿，而凭据与
# 明文对话原文照进构建上下文。（实测：两处注释掉后原版都不报。）
for pat in 'data/' '.env' 'scripts/upstreams.tsv'; do
    # 剥掉注释与首尾空白后按整行比对
    if sed 's/#.*//' "$dockerignore" | sed 's/[[:space:]]*$//' |
        grep -qxF "$pat"; then
        pass ".dockerignore 排除了 $pat"
    else
        fail ".dockerignore 没有排除 $pat —— 凭据或对话原文会进构建上下文"
    fi
done

echo "=== ENTRYPOINT 必须是 exec 形式 ==="
# shell 形式会让 PID 1 变成 /bin/sh，它不转发信号，于是优雅关闭
# （§4.8）完全不执行，docker stop 只能等超时后 SIGKILL。
if grep -qE '^ENTRYPOINT[[:space:]]*\[' "$dockerfile"; then
    pass 'ENTRYPOINT 用 JSON 数组（exec 形式）'
else
    fail 'ENTRYPOINT 是 shell 形式 —— PID 1 会是 shell，SIGTERM 不转发'
fi

echo "=== 镜像必须无 CGO（纯 Go 驱动，交叉编译不用改工具链）==="
if grep -qE 'CGO_ENABLED=0' "$dockerfile"; then
    pass 'CGO_ENABLED=0'
else
    fail '没有 CGO_ENABLED=0 —— alpine(musl) 与 debian(glibc) 的动态链接差异会让「本地好好的，容器里起不来」'
fi

echo "=== .env.example 覆盖 config.validate 要求的三项 ==="
# 少一项的话，用户照着模板填完仍然起不来，而错误信息出现在容器日志里 ——
# 一个本该在模板里就避免的往返。
for key in ENCRYPTION_KEY RELAY_KEYS ADMIN_PASSWORD; do
    if grep -qE "^${key}=" "$envexample"; then
        pass ".env.example 有 $key"
    else
        fail ".env.example 缺 $key —— 照模板填完仍然起不来"
    fi
done

echo "=== 送进容器 shell 的 here-string 必须先转成 LF ==="
# *.ps1 是 CRLF 的（.gitattributes 强制），而运行镜像是 alpine ——
# 它的 /bin/sh 是 busybox ash，**不容忍任何 \r**：`then\r` 不是关键字 `then`，
# 整段脚本报 `syntax error: unexpected end of file (expecting "then")` 后
# 一行都不执行。
#
# 症状是**冒烟脚本少跑了一整段却依然显示通过**，这比断言失败更糟。
# 而开发机上的 MSYS sh 恰好容忍行尾 \r，所以这个问题本地复现不出来 ——
# 只在 CI 的 Linux runner + alpine 容器里才现形。（实测：CI 抓到的。）
#
# 判据：凡是把 here-string 交给 `sh -ec` 的地方，都必须经过 ShLF 去掉 \r。
# 也就是 `/bin/sh -ec` 后面只能跟变量，不能直接跟 @' 开头的 here-string。
for ps1 in "$root"/scripts/*.ps1; do
    [ -e "$ps1" ] || continue
    # `sh -ec @'` ：here-string 直接喂给容器 shell，没有过 ShLF
    raw=$(grep -cE "sh +-ec +@'" "$ps1" || true)
    if [ "$raw" -gt 0 ]; then
        fail "$(basename "$ps1") 有 $raw 处把 here-string 直接交给 sh -ec —— "\
"CRLF 会让 busybox ash 整段拒绝执行，断言恒不触发。应先过 ShLF 去掉 \\r"
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
