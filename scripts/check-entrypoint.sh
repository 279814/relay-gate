#!/bin/sh
# entrypoint.sh 的静态检查。**不需要 Docker**，因此能进 CI。
#
# 为什么值得单独有这么一个脚本：entrypoint 里的 bug 全是静默的。
# 它跑在容器启动的最前面，出错时的表现是「容器起不来」或者更糟 ——
# 「起来了但权限没收紧」，而后者没有任何输出。
#
# 具体防的是一个真实发生过的 bug：那段收归库文件属主的循环写成了
# `for suffix in '' -wal -shm -journal; do file="${DB_PATH}${suffix}"`，
# 而 DB_PATH **从未被赋值** —— 于是 4 个 chown 目标是 ""、"-wal"、"-shm"、
# "-journal" 四个相对路径垃圾，一个都不指向真实的库文件。
# 整段「恢复 root-owned 库」的逻辑是死代码，而且完全不报错。
#
# 跑法：sh scripts/check-entrypoint.sh

set -eu

script="$(dirname "$0")/../deploy/entrypoint.sh"
fails=0

fail() {
    echo "  [FAIL] $1" >&2
    fails=$((fails + 1))
}
pass() { echo "  [PASS] $1"; }

echo "=== 1. 语法必须合法 ==="
if sh -n "$script" 2>/dev/null; then
    pass 'sh -n 通过'
else
    fail 'sh -n 报错 —— 容器会在启动瞬间退出'
    exit 1
fi

echo "=== 2. 脚本里引用的每个变量都必须先被赋值 ==="
# 取出所有 ${VAR} **与裸 $VAR** 形式的引用（排除 $1 $@ $? 这类特殊变量与
# 位置参数），再确认它要么在脚本里赋过值，要么是我们刻意从环境读的那几个。
#
# 这一条正是上面那个 bug 的直接判据：DB_PATH 被引用但从未赋值。
#
# 必须同时认裸 $VAR：第一版只匹配 ${VAR}，于是同一个 bug 换成
# `chown "$RELAY_UID" "$MISSING"` 的写法就能整个漏过去 —— 检查器全绿，
# 而那正是它唯一存在的理由。（实测：注入裸 $MISSING_MODE 后原版不报。）
env_provided='RELAY_DB RELAY_UID RELAY_GID'
referenced=$(grep -oE '\$\{?[A-Za-z_][A-Za-z0-9_]*' "$script" |
    sed 's/^\$[{]\?//' | sort -u)
for var in $referenced; do
    # 在脚本里被赋值？（VAR=... 或 for VAR in ...）
    if grep -qE "^[[:space:]]*${var}=" "$script" ||
        grep -qE "^[[:space:]]*for[[:space:]]+${var}[[:space:]]+in" "$script"; then
        continue
    fi
    # 是刻意从环境读的？
    case " $env_provided " in
        *" $var "*) continue ;;
    esac
    fail "变量 \$$var 被引用但从未赋值，也不在环境变量白名单里 —— "\
"它会展开成空串，而那通常让一整段逻辑静默变成空操作"
done
[ "$fails" -eq 0 ] && pass '所有引用的变量都有来源'

echo "=== 3. chown 的目标必须是绝对路径 ==="
# 直接跑一遍 entrypoint.sh **自己**的那段路径拼接，断言四个目标都以 / 开头。
# 只看代码文本不够：${DB_PATH} 拼出来是什么，得真的展开一次才知道。
#
# 关键是从真实脚本里把那两行抠出来跑，而不是在这里重抄一份。
# 第一版就是重抄的 —— 于是它验的是检查器里那份硬编码副本，
# entrypoint.sh 的默认值被改成相对路径时它照样全绿。（实测：把默认值
# 换成 relay-gate.db 后原版仍 PASS。）一个永远为真的断言不是防线。
assign=$(grep -E '^DB_PATH=' "$script")
if [ -z "$assign" ]; then
    fail 'entrypoint.sh 里找不到 DB_PATH= 赋值 —— 无法验证 chown 目标'
else
    # 不带 RELAY_DB 跑，验的是**默认值**那条路径（真实部署里 compose
    # 不设 RELAY_DB 时走的就是它）。
    targets=$(env -u RELAY_DB sh -c "
        $assign
        for suffix in \"\" -wal -shm -journal; do printf '%s\n' \"\${DB_PATH}\${suffix}\"; done")
    abs=0
    total=0
    for t in $targets; do
        total=$((total + 1))
        case "$t" in /*) abs=$((abs + 1)) ;; esac
    done
    if [ "$abs" -eq "$total" ] && [ "$total" -eq 4 ]; then
        pass "4 个 chown 目标全是绝对路径"
    else
        fail "只有 $abs/$total 个目标是绝对路径 —— 其余是相对路径垃圾，chown 不到真实库文件"
    fi
fi

echo "=== 4. 必须用 exec 交棒（SIGTERM 直达） ==="
# 不用 exec 的话 PID 1 是这个 shell，它不转发信号，于是优雅关闭
# （§4.8：不杀在途的流式连接）根本不执行，docker stop 只能等超时后 SIGKILL。
# 症状是每次重启都掐断一次正在进行的对话，而容器看起来一切正常。
if grep -qE '^[[:space:]]*exec su-exec' "$script" &&
    grep -qE '^[[:space:]]*exec "\$@"' "$script"; then
    pass '两条路径都用 exec 交棒'
else
    fail '缺少 exec —— PID 1 会是 shell，SIGTERM 不转发，优雅关闭形同虚设'
fi

echo
if [ "$fails" -gt 0 ]; then
    echo "$fails 项失败" >&2
    exit 1
fi
echo "全部通过"
