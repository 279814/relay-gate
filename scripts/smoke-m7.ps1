# M7 容器化部署的端到端验证。
#
# 验的是只在容器里才成立的不变量：0600 库权限、PID 1、SIGTERM、
# 端口发布到所有接口、首次启动打印三项凭据且重启不重复、非 root。
#
# 用法：pwsh -File scripts/smoke-m7.ps1
# 前置：Docker 引擎必须在跑。

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSNativeCommandUseErrorActionPreference = $false

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$PORT = 18907
$TAG = 'relay-gate:m7-smoke'
$CNAME = 'relay-gate-m7-smoke'
$DATA = 'data/m7-smoke'

$KEY = 'rk-m7-smoke-client'
$ADMIN = 'admin-m7-smoke'

$script:fails = 0
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
    if ($script:envCreatedByUs) {
        Remove-Item -Force '.env' -ErrorAction SilentlyContinue
        $script:envCreatedByUs = $false
    }
}

function InC($cmd) {
    (docker exec $CNAME sh -c $cmd 2>&1 | Out-String).Trim()
}

function ShLF($script) { $script -replace "`r", '' }

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
        throw 'Docker 引擎没在跑。启动 Docker Desktop 后重试。'
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

    $sizeStr = (docker images $TAG --format '{{.Size}}')
    $mb = [double]($sizeStr -replace '[^\d.]', '')
    if ($sizeStr -match 'GB') { $mb *= 1024 }
    Check '镜像大小在合理区间（多阶段构建生效）' ($mb -lt 100) `
        "得到 $sizeStr —— 超过 100MB 说明构建阶段的工具链被带进了运行镜像"

    Say '首次启动（无 env 凭据）生成并打印三项密钥'
    New-Item -ItemType Directory -Force $DATA | Out-Null
    $absData = (Resolve-Path $DATA).Path
    docker run -d --name $CNAME `
        -e TZ=Asia/Shanghai `
        -p "${PORT}:18787" `
        -v "${absData}:/app/data" `
        $TAG 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '容器启动命令失败' }

    if (-not (WaitFor '首次启动容器就绪' 45 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) {
        Write-Host '--- 容器日志 ---' -ForegroundColor DarkGray
        docker logs $CNAME 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        throw '容器没起来'
    }
    Pass '首次启动已就绪'

    $bootLogs = (docker logs $CNAME 2>&1 | Out-String)
    Check '打印 ADMIN_PASSWORD' ($bootLogs -match 'ADMIN_PASSWORD=') '首次启动日志应含 ADMIN_PASSWORD='
    Check '打印 RELAY_KEYS' ($bootLogs -match 'RELAY_KEYS=') '首次启动日志应含 RELAY_KEYS='
    Check '打印 ENCRYPTION_KEY' ($bootLogs -match 'ENCRYPTION_KEY=') '首次启动日志应含 ENCRYPTION_KEY='

    $health = (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing).Content | ConvertFrom-Json
    Check '/healthz 报 running' ($health.state -eq 'running') "得到 $($health.state)"
    Check '版本号由构建注入（不是默认的 dev）' ($health.version -eq 'm7-smoke') `
        "得到 '$($health.version)'"

    Say '进程身份：PID 1 是 relay-gate，且不是 root'
    $pid1 = InC 'cat /proc/1/cmdline | tr "\0" " "'
    Check 'PID 1 是 relay-gate（信号能直达）' ($pid1 -match 'relay-gate') `
        "PID 1 是 '$pid1'"
    $uid = InC 'grep "^Uid:" /proc/1/status'
    Check '进程已降权（非 root）' ($uid -notmatch '^\s*Uid:\s+0\s') "得到 '$uid'"

    Say '库文件权限 0600'
    $modes = InC 'stat -c "%n %a %u:%g" /app/data/relay-gate.db*'
    foreach ($line in ($modes -split "`n")) {
        $line = $line.Trim()
        if (-not $line) { continue }
        $parts = $line -split '\s+'
        $name = Split-Path $parts[0] -Leaf
        Check "$name 权限为 600" ($parts[1] -eq '600') "得到 $($parts[1])"
        Check "$name 属主是 relay(10001)" ($parts[2] -eq '10001:10001') "得到 $($parts[2])"
    }

    Say '重启不重复打印三项密钥'
    docker restart $CNAME 2>&1 | Out-Null
    if (-not (WaitFor '重启后就绪' 30 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) { throw '重启后容器没起来' }
    $after = (docker logs $CNAME 2>&1 | Out-String)
    $adminHits = ([regex]::Matches($after, 'ADMIN_PASSWORD=')).Count
    Check '重启后 ADMIN_PASSWORD 仍只出现一次' ($adminHits -eq 1) "出现 $adminHits 次"

    Say '恢复场景：现有库文件是 root-owned'
    docker exec -u 0 $CNAME sh -c 'chown 0:0 /app/data/relay-gate.db*' 2>&1 | Out-Null
    docker restart $CNAME 2>&1 | Out-Null
    $recovered = WaitFor 'root-owned 库恢复后容器重新就绪' 30 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    }
    if ($recovered) {
        Pass '现有 root-owned 库被 entrypoint 收归 relay'
        $owners = InC 'stat -c "%u:%g" /app/data/relay-gate.db*'
        Check '恢复后主库与副产品全部属于 10001:10001' `
            ((($owners -split "`n") | Where-Object { $_ -ne '10001:10001' }).Count -eq 0) `
            "得到：$($owners -replace "`n", ', ')"
    }

    Say '时区与 CA'
    $tz = InC 'date +%z'
    Check 'TZ=Asia/Shanghai 生效（+0800）' ($tz -eq '+0800') "得到 '$tz'"
    $ca = InC 'test -f /etc/ssl/certs/ca-certificates.crt && echo yes || echo no'
    Check 'ca-certificates 已安装' ($ca -eq 'yes') "得到 '$ca'"

    Say '管理面可达（无登录 IP 白名单）'
    $ui = Invoke-WebRequest "http://127.0.0.1:$PORT/admin/" -UseBasicParsing -TimeoutSec 10
    Check '管理界面 HTTP 200' ($ui.StatusCode -eq 200) "得到 $($ui.StatusCode)"

    Say '环境变量凭据仍可用（覆盖 bootstrap）'
    docker rm -f $CNAME 2>&1 | Out-Null
    Remove-Item -Recurse -Force $DATA -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $DATA | Out-Null
    $absData = (Resolve-Path $DATA).Path
    docker run -d --name $CNAME `
        -e ENCRYPTION_KEY='0123456789abcdef0123456789abcdef' `
        -e RELAY_KEYS=$KEY `
        -e ADMIN_PASSWORD=$ADMIN `
        -e TZ=Asia/Shanghai `
        -p "${PORT}:18787" `
        -v "${absData}:/app/data" `
        $TAG 2>&1 | Out-Null
    if (-not (WaitFor 'env 凭据容器就绪' 30 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) { throw 'env 凭据容器没起来' }
    $envLogs = (docker logs $CNAME 2>&1 | Out-String)
    Check '设置 env 时不打印 bootstrap 三项' (
        ($envLogs -notmatch 'ADMIN_PASSWORD=') -and
        ($envLogs -notmatch 'RELAY_KEYS=rk-') -and
        ($envLogs -notmatch 'ENCRYPTION_KEY=[0-9a-f]{32}')
    ) 'env 路径不应触发首次打印'

    $ups = Invoke-WebRequest "http://127.0.0.1:$PORT/admin/api/upstreams" `
        -Headers @{ Authorization = "Bearer $ADMIN" } -UseBasicParsing
    Check 'Bearer 管理口令可用' ($ups.StatusCode -eq 200) "得到 $($ups.StatusCode)"

    Say 'SIGTERM 优雅关闭'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    docker stop -t 30 $CNAME 2>&1 | Out-Null
    $sw.Stop()
    $secs = [int]$sw.Elapsed.TotalSeconds
    Check "docker stop 快速返回（${secs}s，未走超时）" ($sw.Elapsed.TotalSeconds -lt 10) `
        "耗时 ${secs}s"
    $exitCode = (docker inspect $CNAME --format '{{.State.ExitCode}}' 2>$null)
    Check '退出码 0（正常退出，非被杀)' ($exitCode -eq '0') "得到 $exitCode"
    $logs = (docker logs $CNAME 2>&1 | Out-String)
    Check '日志显示走完了优雅关闭流程' ($logs -match '开始优雅关闭' -and $logs -match '已停止') `
        '没看到关闭日志'

    Say 'compose 配置：单服务、端口发布到所有接口'
    if (-not (Test-Path '.env')) {
        @(
            'ENCRYPTION_KEY=0123456789abcdef0123456789abcdef'
            "RELAY_KEYS=$KEY"
            "ADMIN_PASSWORD=$ADMIN"
        ) | Set-Content -Path '.env' -Encoding utf8
        $script:envCreatedByUs = $true
    }
    $svcDefault = (docker compose config --services 2>&1 | Out-String)
    Check 'compose config 可解析' ($svcDefault -notmatch 'error|not found') `
        "docker compose config 报错：$($svcDefault.Trim())"
    Check '仅 relay-gate 服务（无 Caddy）' `
        ($svcDefault -match 'relay-gate' -and $svcDefault -notmatch 'caddy') `
        "服务列表：$($svcDefault -replace "`n", ' ')"

    $cfg = (docker compose config 2>&1 | Out-String)
    Check '端口发布到所有接口（无 host_ip: 127.0.0.1）' ($cfg -notmatch 'host_ip:\s*127\.0\.0\.1') `
        "不应再绑 127.0.0.1。config 片段：$($cfg.Trim() -split "`n" | Select-Object -First 5)"
    Check 'compose 含端口映射' ($cfg -match 'published:\s*"?18907"?|published:\s*"?18787"?|target:\s*18787') `
        "ports 段缺失。输出：$($cfg.Trim() -split "`n" | Select-Object -First 8)"

    Say '构建上下文不含凭据（.dockerignore）'
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
