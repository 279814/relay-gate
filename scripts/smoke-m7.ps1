# M7 容器化部署的端到端验证（§8）。
#
# 为什么需要它，而 M2–M6 的冒烟不够：那些脚本验的是**进程**的行为，
# 而 M7 引入的每一样东西都只在**容器**里才成立或才会坏 ——
#
#   1. 「库文件是 0600」。store.restrictPerms 的单测在 Windows 上是 skip 的
#      （ACL 与 mode 位不可比），也就是说本地全绿证明不了这条。而它保护的是
#      明文的对话原文，且 M7 恰好把 data/ 挂到了宿主机上。
#   2. 「SIGTERM 直达 Go 进程」。ENTRYPOINT 写成 shell 形式、或 entrypoint.sh
#      漏了 exec，PID 1 就变成 /bin/sh —— 它不转发信号，于是优雅关闭
#      （§4.8：不杀在途的流式连接）**完全不执行**，docker stop 只能等超时
#      后 SIGKILL。症状是每次重启都掐断一次正在进行的对话，而容器看起来
#      一切正常。
#   3. 「端口只绑 127.0.0.1」。写成 "18787:18787" 的话 Docker 会插一条
#      iptables 规则把端口直接暴露到公网，**而且绕过 ufw/firewalld** ——
#      你在防火墙里看不到，`ufw status` 显示一切正常。那等于把管理界面和
#      所有上游 key 公开（§5.2f）。
#   4. 「非 root 运行且能写库」。绑定挂载的属主是宿主决定的，与镜像里的
#      uid 对不上时报的是 `unable to open database file (14)` —— 一个完全
#      看不出是权限问题的错误。（开发 M7 时实测踩到过。）
#   5. 「默认路径不被可选服务拖累」。compose 的变量插值发生在 profile 过滤
#      **之前**，所以 caddy 段里一个 `${VAR:?...}` 会让根本不起 Caddy 的
#      `docker compose up -d` 直接失败。（同样是实测踩到的。）
#
# 用法：pwsh -File scripts/smoke-m7.ps1
# 前置：Docker 引擎必须在跑（Docker Desktop 已启动）。

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$PORT = 18907          # 刻意与 compose 默认的 18787 不同，避免撞上你正在跑的那一份
$TAG = 'relay-gate:m7-smoke'
$CNAME = 'relay-gate-m7-smoke'
$DATA = 'data/m7-smoke'

$KEY = 'rk-m7-smoke-client'
$ADMIN = 'admin-m7-smoke'

$script:fails = 0

# 是否由本脚本创建了 .env。只有为 true 时才允许删它 ——
# 绝不能碰你正在用的那份：里面有 ENCRYPTION_KEY，删掉等于
# 所有已存的上游 key 再也解不开（config.validate 的注释写明了这一点）。
$script:envCreatedByUs = $false

function Say($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:fails++
}
function Check($what, $ok, $detail) {
    if ($ok) { Pass $what } else { Fail "$what —— $detail" }
}

function Cleanup {
    docker rm -f $CNAME 2>&1 | Out-Null
    Remove-Item -Recurse -Force $DATA -ErrorAction SilentlyContinue
    Remove-Item -Force 'm7-*.log' -ErrorAction SilentlyContinue
    # 只删自己建的那份。放在这里而不是用完就删：中途抛异常时
    # 那个临时 .env 会留在仓库根目录，而它长得和真的一模一样 ——
    # 下次部署时你会以为那就是自己的配置。
    if ($script:envCreatedByUs) {
        Remove-Item -Force '.env' -ErrorAction SilentlyContinue
        $script:envCreatedByUs = $false
    }
}

# 在容器里跑一条命令并返回 stdout（去掉尾部换行）。
function InC($cmd) {
    (docker exec $CNAME sh -c $cmd 2>&1 | Out-String).Trim()
}

function WaitFor($what, $timeoutSec, $probe) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (& $probe) { return $true }
        Start-Sleep -Milliseconds 500
    }
    Fail "$what（等了 ${timeoutSec}s 没等到）"
    return $false
}

try {
    Say '前置：Docker 引擎必须可用'
    docker info --format '{{.ServerVersion}}' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker 引擎没在跑。启动 Docker Desktop 后重试 —— M7 的全部内容都在容器里，没有引擎无法验证任何一条。'
    }
    Pass "引擎可用（$(docker info --format '{{.ServerVersion}}' 2>$null)）"

    Cleanup

    Say '构建镜像'
    docker build --build-arg VERSION=m7-smoke -t $TAG . 2>&1 | Tee-Object -FilePath 'm7-build.log' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Get-Content 'm7-build.log' -Tail 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        throw '镜像构建失败'
    }
    Pass '镜像已构建'

    # 镜像大小是个粗略但有用的回归信号：一旦有人把构建阶段的 SDK 带进
    # 运行阶段（例如误删多阶段的第二个 FROM），它会从 ~20MB 跳到 ~800MB。
    $sizeStr = (docker images $TAG --format '{{.Size}}')
    $mb = [double]($sizeStr -replace '[^\d.]', '')
    if ($sizeStr -match 'GB') { $mb *= 1024 }
    Check '镜像大小在合理区间（多阶段构建生效）' ($mb -lt 100) `
        "得到 $sizeStr —— 超过 100MB 说明构建阶段的工具链被带进了运行镜像"

    Say '缺凭据必须拒绝启动（而不是带着空 key 跑起来）'
    # 这条是 §5.2f 的底线：RELAY_KEYS 为空等于把所有上游 key 免费公开。
    $out = (docker run --rm $TAG 2>&1 | Out-String)
    Check '缺环境变量时拒绝启动' ($out -match 'ENCRYPTION_KEY') `
        "应报缺失的变量名，实际输出：$($out.Trim())"
    Check '错误信息给出生成办法' ($out -match 'openssl rand') `
        '只说「缺变量」而不说怎么生成，等于让人去翻文档'

    Say '启动容器（绑定挂载 + 非 root）'
    New-Item -ItemType Directory -Force $DATA | Out-Null
    $absData = (Resolve-Path $DATA).Path
    docker run -d --name $CNAME `
        -e ENCRYPTION_KEY='0123456789abcdef0123456789abcdef' `
        -e RELAY_KEYS=$KEY `
        -e ADMIN_PASSWORD=$ADMIN `
        -e TZ=Asia/Shanghai `
        -p "127.0.0.1:${PORT}:18787" `
        -v "${absData}:/app/data" `
        $TAG 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '容器启动命令失败' }

    if (-not (WaitFor '容器就绪' 30 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) {
        Write-Host '--- 容器日志 ---' -ForegroundColor DarkGray
        docker logs $CNAME 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        throw '容器没起来'
    }
    Pass '容器已就绪'

    $health = (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing).Content | ConvertFrom-Json
    Check '/healthz 报 running' ($health.state -eq 'running') "得到 $($health.state)"
    # 版本注入：-X main.version 指向一个不存在的变量时 Go **不报错**，
    # 只是静默不注入 —— 于是「线上跑的是哪个版本」永远答不上来。
    Check '版本号由构建注入（不是默认的 dev）' ($health.version -eq 'm7-smoke') `
        "得到 '$($health.version)' —— ldflags -X 没生效，或 main.version 变量被改名了"

    Say '进程身份：PID 1 是 relay-gate，且不是 root'
    # PID 1 必须是 Go 进程本身。是 /bin/sh 的话信号不会转发，
    # 优雅关闭完全不执行（下面那条 SIGTERM 测试会跟着红）。
    $pid1 = InC 'cat /proc/1/cmdline | tr "\0" " "'
    Check 'PID 1 是 relay-gate（信号能直达）' ($pid1 -match 'relay-gate') `
        "PID 1 是 '$pid1' —— 若是 shell，SIGTERM 不会转发给 Go 进程"
    $uid = InC 'grep "^Uid:" /proc/1/status'
    Check '进程已降权（非 root）' ($uid -notmatch '^\s*Uid:\s+0\s') `
        "得到 '$uid' —— 以 root 跑会让挂载出去的 data/ 变成 root 拥有，你自己备份都要 sudo"

    Say '库文件权限 0600（§3.6.3d）'
    # 这条只在 Linux 生效，而 store 包的单测在 Windows 上是 skip 的ーー
    # 也就是说本地 go test 全绿证明不了它，只能在容器里验。
    # 它保护的是**明文的**样本：完整对话原文与贴进去的代码。
    $modes = InC 'stat -c "%n %a %u:%g" /app/data/relay-gate.db*'
    foreach ($line in ($modes -split "`n")) {
        $line = $line.Trim()
        if (-not $line) { continue }
        $parts = $line -split '\s+'
        $name = Split-Path $parts[0] -Leaf
        Check "$name 权限为 600" ($parts[1] -eq '600') `
            "得到 $($parts[1]) —— 同机其它用户能读到全部对话原文"
        Check "$name 属主是 relay(10001)" ($parts[2] -eq '10001:10001') `
            "得到 $($parts[2])"
    }

    Say '恢复场景：目录属主正确，但现有库文件是 root-owned'
    # 真实来源很多：从另一台机器 root 用户 rsync 回来、手工用 sudo 恢复备份、
    # 或旧镜像曾经以 root 运行。此时目录本身已经是 relay(10001)，若 entrypoint
    # 只看目录属主就跳过，非 root 进程仍然打不开库。
    #
    # 把主库与 SQLite 副产品都改成 root-owned，再重启。正确行为是 entrypoint
    # 逐个收归 relay 后正常启动；只 chown 目录、或拼错 DB 路径都会在这里现形。
    docker exec -u 0 $CNAME sh -c 'chown 0:0 /app/data/relay-gate.db*' 2>&1 | Out-Null
    docker restart $CNAME 2>&1 | Out-Null
    $recovered = WaitFor 'root-owned 库恢复后容器重新就绪' 30 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    }
    if ($recovered) {
        Pass '现有 root-owned 库被 entrypoint 收归 relay，容器正常恢复'
        $owners = InC 'stat -c "%u:%g" /app/data/relay-gate.db*'
        Check '恢复后主库与副产品全部属于 10001:10001' `
            ((($owners -split "`n") | Where-Object { $_ -ne '10001:10001' }).Count -eq 0) `
            "得到：$($owners -replace "`n", ', ')"
    }

    Say '时区生效（探活成本按天分桶，§5.2d）'
    # 没有 tzdata 时容器只认 UTC，「今日 L1 次数」会在东八区的早上 8 点
    # 才清零 —— 一个说不清含义的计数器。
    $tz = InC 'date +%z'
    Check 'TZ=Asia/Shanghai 生效（+0800）' ($tz -eq '+0800') `
        "得到 '$tz' —— 镜像里缺 tzdata 的话 TZ 环境变量是死的"

    Say '出站 CA 证书就位'
    # alpine 默认不带根证书。缺了它所有 HTTPS 上游一律 x509 校验失败，
    # 而症状是「所有站都连不上」，很容易被误判成网络问题。
    $ca = InC 'test -f /etc/ssl/certs/ca-certificates.crt && echo yes || echo no'
    Check 'ca-certificates 已安装' ($ca -eq 'yes') `
        '缺根证书链会让所有 HTTPS 上游一律握手失败'

    Say '管理 API 与鉴权在容器里照常工作'
    $code = try {
        (Invoke-WebRequest "http://127.0.0.1:$PORT/admin/api/upstreams" `
            -UseBasicParsing -TimeoutSec 10 -SkipHttpErrorCheck).StatusCode
    } catch { 0 }
    Check '无凭据访问管理 API 得到 401' ($code -eq 401) "得到 $code"

    $ups = Invoke-WebRequest "http://127.0.0.1:$PORT/admin/api/upstreams" `
        -Headers @{ Authorization = "Bearer $ADMIN" } -UseBasicParsing -TimeoutSec 10
    Check '带凭据能访问管理 API' ($ups.StatusCode -eq 200) "得到 $($ups.StatusCode)"

    Say '管理界面（go:embed，容器里没有静态目录）'
    # 前端全部 embed 进二进制，所以运行镜像里**不该**有 static/ 目录。
    # 有的话说明有人为了「保险」把它拷进去了，那是两份会分叉的副本。
    $ui = Invoke-WebRequest "http://127.0.0.1:$PORT/admin/" -UseBasicParsing -TimeoutSec 10
    Check '管理界面可访问' ($ui.Content -match '<!DOCTYPE html>') '没返回 HTML'
    $hasStatic = InC 'test -d /app/static && echo yes || echo no'
    Check '运行镜像里没有静态资源目录（全靠 embed）' ($hasStatic -eq 'no') `
        '存在 /app/static —— 那是与 embed 内容会分叉的第二份副本'

    Say '总闸状态跨重启保持（§4.8）'
    # 暂停后重启不能自动跑起来。会的话，一个你刻意停掉的网关会在
    # 容器重启（或宿主重启）后悄悄开始转发，继续消耗别人的额度。
    Invoke-WebRequest -Method Post "http://127.0.0.1:$PORT/admin/api/state" `
        -Headers @{ Authorization = "Bearer $ADMIN" } -ContentType 'application/json' `
        -Body '{"state":"paused"}' -UseBasicParsing -TimeoutSec 10 | Out-Null

    docker restart $CNAME 2>&1 | Out-Null
    if (-not (WaitFor '容器重启后就绪' 30 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) { throw '重启后没起来' }

    $h2 = (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing).Content | ConvertFrom-Json
    Check '重启后仍是 paused（状态落库、没被重置）' ($h2.state -eq 'paused') `
        "得到 $($h2.state) —— 一个你刻意停掉的网关会在重启后悄悄开始转发"

    # 暂停时必须拒绝转发，否则上面那条状态就只是个显示用的摆设
    $relay = Invoke-WebRequest -Method Post "http://127.0.0.1:$PORT/v1/messages" `
        -Headers @{ 'X-Api-Key' = $KEY } -ContentType 'application/json' `
        -Body '{"model":"whatever","max_tokens":1}' `
        -UseBasicParsing -TimeoutSec 15 -SkipHttpErrorCheck
    Check '暂停时拒绝转发（503）' ($relay.StatusCode -eq 503) "得到 $($relay.StatusCode)"
    Check '暂停时带 X-Relay-State 头' ($relay.Headers['X-Relay-State'] -eq 'paused') `
        '没有这个头，客户端分不清「暂停」与「所有站都挂了」'

    Say '优雅关闭：SIGTERM 直达，不被 SIGKILL 兜底'
    # 这是整个 M7 里最容易静默坏掉的一条。ENTRYPOINT 写成 shell 形式、
    # 或 entrypoint.sh 漏了 exec，PID 1 就变成 /bin/sh —— 它不转发信号，
    # 于是 docker stop 一定等满超时再 SIGKILL，而容器看起来一切正常。
    # 症状：每次重启都掐断一次正在进行的对话。
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker stop -t 30 $CNAME 2>&1 | Out-Null
    $sw.Stop()
    $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)

    # 空闲进程收到 SIGTERM 应该立刻退。留 10s 余量给 Docker 自身的开销;
    # 接近 30s 就说明信号没被处理、是超时后被杀的。
    Check "docker stop 快速返回（${secs}s，未走超时）" ($sw.Elapsed.TotalSeconds -lt 10) `
        "耗时 ${secs}s —— 接近 30s 说明 SIGTERM 没被 Go 进程收到，是 SIGKILL 兜的底"

    $exitCode = (docker inspect $CNAME --format '{{.State.ExitCode}}' 2>$null)
    Check '退出码 0（正常退出，非被杀)' ($exitCode -eq '0') `
        "得到 $exitCode —— 137 = SIGKILL，说明优雅关闭没执行"

    $logs = (docker logs $CNAME 2>&1 | Out-String)
    Check '日志显示走完了优雅关闭流程' ($logs -match '开始优雅关闭' -and $logs -match '已停止') `
        '没看到关闭日志 —— 进程是被直接杀掉的，在途的流式请求会被掐断'

    Say 'compose 配置：默认路径与公网 profile'
    # compose 的变量插值发生在 profile 过滤**之前**，所以 caddy 段里一个
    # `${VAR:?...}` 会让根本不起 Caddy 的默认命令直接失败。
    # 而默认路径是这个项目最常走的那条。
    #
    # 必须先备好 .env：compose.yaml 里有 `env_file: .env`，缺了它完整的
    # `docker compose config` 会失败 —— 而真实部署的第一步就是
    # `cp .env.example .env`，所以这里照做才是在验真实路径。
    #
    # 只在**不存在时**才建。清理交给 Cleanup（它只删自己建的那份）——
    # 写成「用完就删」的话，中途抛异常时那个临时 .env 会留在仓库根目录，
    # 而它长得和真的一模一样。
    if (-not (Test-Path '.env')) {
        @(
            'ENCRYPTION_KEY=0123456789abcdef0123456789abcdef'
            "RELAY_KEYS=$KEY"
            "ADMIN_PASSWORD=$ADMIN"
        ) | Set-Content -Path '.env' -Encoding utf8
        $script:envCreatedByUs = $true
    }

    # 判据用**输出内容**而不是 $LASTEXITCODE：实测 compose 在
    # 「env file not found」时把错误写到 stdout 且退出码仍是 0 ——
    # 靠退出码判断会让这条断言恒绿，也就是恒等于没测。
    $svcDefault = (docker compose config --services 2>&1 | Out-String)
    Check '默认路径无需任何公网变量即可解析' `
        ($svcDefault -notmatch 'error|not found') `
        "docker compose config 报错：$($svcDefault.Trim())"
    Check '默认只起网关（不起 Caddy）' `
        ($svcDefault -match 'relay-gate' -and $svcDefault -notmatch 'caddy') `
        "默认服务列表：$($svcDefault -replace "`n", ' ')"

    $svcPublic = (docker compose --profile public config --services 2>&1 | Out-String)
    Check '--profile public 时带上 Caddy' ($svcPublic -match 'caddy') `
        "public 服务列表：$($svcPublic -replace "`n", ' ')"

    Say 'Caddy 配置：邮箱可空、管理面默认拒绝'
    # 这里跑 Caddy 自己的 parser，不靠 grep 猜。`email {$VAR}` 在变量为空时
    # 不是「匿名 ACME」，而是**语法错误（email 缺参数）**；公网 profile 会
    # 启动即退出。compose 的 command 应只在邮箱非空时保留这行。
    $caddyMount = "${root}/deploy/Caddyfile:/etc/caddy/Caddyfile:ro"
    $caddyCheck = (docker run --rm `
        -e RELAY_DOMAIN=example.com `
        -e RELAY_ACME_EMAIL= `
        -e RELAY_ALLOW_IPS= `
        -v $caddyMount `
        caddy:2.8-alpine /bin/sh -ec @'
config=/tmp/relay-gate-Caddyfile
if [ -n "${RELAY_ACME_EMAIL:-}" ]; then
  cp /etc/caddy/Caddyfile "${config}"
else
  sed '/^[[:space:]]*email[[:space:]].*RELAY_ACME_EMAIL.*$/d' \
    /etc/caddy/Caddyfile > "${config}"
fi
caddy validate --config "${config}" --adapter caddyfile
'@ 2>&1 | Out-String)
    Check 'RELAY_ACME_EMAIL 留空时 Caddyfile 仍合法' ($caddyCheck -match 'Valid configuration') `
        "Caddy 验证失败：$($caddyCheck.Trim())"

    # 空白名单的语义也不能靠注释自证。Caddy 会把空 remote_ip 适配成
    # `remote_ip: {}`；在 `not` 外层下应匹配所有来源，管理面全部 403，
    # 而普通转发路径仍可达。用真实 Caddy 进程跑两个请求验证这一点。
    $caddyRuntime = (docker run --rm `
        -e RELAY_ALLOW_IPS= `
        caddy:2.8-alpine /bin/sh -ec @'
cat >/tmp/acl.Caddyfile <<'EOF'
:8080 {
  @admin path /admin*
  handle @admin {
    @notAllowed not remote_ip {$RELAY_ALLOW_IPS}
    respond @notAllowed "blocked" 403
    respond "admin-ok" 200
  }
  respond "proxy-ok" 200
}
EOF
caddy run --config /tmp/acl.Caddyfile --adapter caddyfile >/tmp/caddy.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
for i in 1 2 3 4 5; do
  wget -qO- http://127.0.0.1:8080/v1/messages >/tmp/proxy 2>/dev/null && break
  sleep 1
done
admin=$(wget -qO- --server-response http://127.0.0.1:8080/admin/ 2>&1 || true)
printf 'admin403=%s\n' "$(printf '%s' "$admin" | grep -c '403 Forbidden')"
printf 'proxy=%s\n' "$(cat /tmp/proxy 2>/dev/null || true)"
'@ 2>&1 | Out-String)
    Check 'IP 白名单留空时管理面全部 403' ($caddyRuntime -match 'admin403=1') `
        "运行结果：$($caddyRuntime.Trim())"
    Check 'IP 白名单留空不影响转发端点' ($caddyRuntime -match 'proxy=proxy-ok') `
        "运行结果：$($caddyRuntime.Trim())"

    # 端口绑定是整个部署里安全后果最重的一行（§5.2f）。
    # 写成 "18787:18787" 的话 Docker 会把它直接暴露到公网，且绕过 ufw。
    #
    # 这一条**必须**用完整的 config（不是 --services）：只有它会展开
    # ports 段。而完整 config 会读 env_file，所以上面那几行准备是必需的。
    $cfg = (docker compose config 2>&1 | Out-String)
    Check '端口只绑 127.0.0.1（不暴露公网）' ($cfg -match 'host_ip:\s*127\.0\.0\.1') `
        "没看到 host_ip: 127.0.0.1 —— Docker 的端口映射会绕过 ufw/firewalld 直接暴露到公网。config 输出：$($cfg.Trim() -split "`n" | Select-Object -First 3)"

    Say '构建上下文不含凭据（.dockerignore）'
    # data/ 里有明文样本、.env 里有三项凭据。它们不会进最终镜像
    # （运行阶段只 COPY 二进制），但会留在构建缓存层里，而层是可导出的。
    foreach ($pat in @('data/', '.env', 'scripts/upstreams.tsv')) {
        Check ".dockerignore 排除了 $pat" `
            ((Get-Content .dockerignore -Raw) -match [regex]::Escape($pat)) `
            '含真实凭据或对话原文的路径必须排除在构建上下文之外'
    }
}
finally {
    Say '收尾'
    Cleanup
    docker rmi $TAG 2>&1 | Out-Null
}

if ($script:fails -gt 0) {
    Write-Host "`n$($script:fails) 项失败" -ForegroundColor Red
    exit 1
}
Write-Host "`n全部通过" -ForegroundColor Green
