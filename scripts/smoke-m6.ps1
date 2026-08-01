# M6 请求内重试 + 请求日志的端到端验证（§3.5）
#
# 为什么需要它，而单测不够：M6 的核心不变量横跨**多个组件的接缝**，
# 而接缝正是单测最看不到的地方 ——
#
#   1. 「A 站的 key 绝不出现在发往 B 站的请求里」。单测里我断言过它，
#      但那是用假的 Candidate 断言的。真实链路上这个头要经过
#      PrepareOutboundHeaders → Transport → 真实 TCP，中间任何一处缓存
#      或复用都会让它成立不了。而这条一旦破，后果是 B 站收到 A 站的 key
#      → 401 → B 站被判死：一个好站因为我们的 bug 被踢出池子。
#   2. 「日志、样本、健康三份记录说的是同一件事」。它们由三条独立的路径
#      写出，单测各自绿着，合起来对不上完全可能。
#   3. 「明文 key 不落库」。§9.4 的验收标准是「真 key 全表 grep 零命中」,
#      而 M6 新增了一整张表 —— 那是一个新的泄露面。
#
# M5 的教训也在这里：那一轮 UI 层的 bug（登出不清内存数据）单测全绿，
# 靠端到端才发现。
#
# 用法：pwsh -File scripts/smoke-m6.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$GO = 'C:\Program Files\Go\bin\go.exe'
$PORT = 18806
$MOCK_BAD = 19011   # 恒 502：可重试的失败
$MOCK_OK = 19012    # 健康站

$KEY = 'rk-m6-smoke-client'
$ADMIN = 'admin-m6-smoke'
$DB = 'data/m6-smoke.db'

# 两个站用**不同**的 key。相同的话，「A 的 key 发给了 B」这个 bug 是隐形的。
$KEY_BAD = 'sk-m6-bad-station-secret-aaaa'
$KEY_OK = 'sk-m6-ok-station-secret-bbbb'

$script:procs = @()
$script:fails = 0

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
    foreach ($p in $script:procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item -Force "$DB*" -ErrorAction SilentlyContinue
    Remove-Item -Force 'm6-mock-*.log', 'm6-gate*.log' -ErrorAction SilentlyContinue
}

function Admin($method, $path, $body) {
    $h = @{ Authorization = "Bearer $ADMIN" }
    $a = @{
        Uri = "http://127.0.0.1:$PORT$path"; Method = $method; Headers = $h
        UseBasicParsing = $true; TimeoutSec = 20
    }
    if ($body) {
        $a.Body = ($body | ConvertTo-Json -Depth 10 -Compress)
        $a.ContentType = 'application/json'
    }
    (Invoke-WebRequest @a).Content | ConvertFrom-Json
}

function WaitFor($what, $timeoutSec, $probe) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (& $probe) { return $true }
        Start-Sleep -Milliseconds 400
    }
    Fail "$what（等了 ${timeoutSec}s 没等到）"
    return $false
}

# 发一个真实的转发请求，返回完整响应（含头），失败也不抛。
function Relay($body) {
    Invoke-WebRequest -Method Post "http://127.0.0.1:$PORT/v1/messages" `
        -Headers @{ 'X-Api-Key' = $KEY } -ContentType 'application/json' `
        -Body $body -UseBasicParsing -TimeoutSec 60 -SkipHttpErrorCheck
}

try {
    Say '准备：编译 + 起靶站'
    & $GO build -o relay-gate.exe ./cmd/relay-gate
    if ($LASTEXITCODE -ne 0) { throw '编译失败' }
    Remove-Item -Force "$DB*" -ErrorAction SilentlyContinue

    foreach ($cfg in @(
        @{ Port = $MOCK_BAD; Scenario = 'bad_gateway' },
        @{ Port = $MOCK_OK;  Scenario = 'normal' }
    )) {
        $script:procs += Start-Process -FilePath 'python' `
            -ArgumentList "scripts/mock-upstream.py $($cfg.Port) $($cfg.Scenario)" `
            -NoNewWindow -PassThru -RedirectStandardError "m6-mock-$($cfg.Port).log"
    }
    Start-Sleep -Seconds 2

    Say '启动 relay-gate'
    $env:ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef'
    $env:RELAY_KEYS = $KEY
    $env:ADMIN_PASSWORD = $ADMIN
    $env:RELAY_ADDR = "127.0.0.1:$PORT"
    $env:RELAY_DB = $DB
    $script:procs += Start-Process -FilePath '.\relay-gate.exe' -NoNewWindow -PassThru `
        -RedirectStandardOutput 'm6-gate.log' -RedirectStandardError 'm6-gate-err.log'

    if (-not (WaitFor '网关启动' 15 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) { throw '网关没起来' }
    Pass '网关已启动'

    Say '配置：坏站优先级 1、好站优先级 2'
    # 关掉探活：否则坏站会被判 dead 而在选路时被跳过，重试就撞不上它了。
    # 而这个脚本要验证的恰恰是「撞上去、失败、换站」。
    Admin PUT '/admin/api/settings' @{
        real_connect_sec = 5; real_first_token_sec = 300; real_idle_sec = 30; real_total_sec = 300
        l1_connect_sec = 3; l1_total_sec = 5
        l2_connect_sec = 3; l2_first_token_sec = 5; l2_total_sec = 8
        count_tokens_sec = 10
        l1_interval_alive_sec = 60; l1_interval_dead_sec = 60
        l2_interval_alive_sec = 300; l2_interval_dead_sec = 300
        fail_threshold = 2; ok_threshold = 2; cooldown_sec = 5
        global_l2_concurrency = 3
        probe_enabled = $false; piggyback_enabled = $false; half_open_enabled = $false
        retry_max_attempts = 3
        sample_enabled = $true; sample_max_body_bytes = 0
        sample_resp_head_bytes = 0; sample_resp_tail_bytes = 0
        sample_keep_count = 300; sample_keep_days = 7; sample_queue_size = 256
        request_log_enabled = $true; request_log_keep_count = 5000
        request_log_keep_days = 7; request_log_queue_size = 512
    } | Out-Null
    Pass '设置已写入（探活关闭，重试上限 3）'

    $mn = Admin POST '/admin/api/model-names' @{
        name = 'claude-opus-5'; protocol = 'anthropic'; match_mode = 'exact'; enabled = $true
    }
    $upBad = Admin POST '/admin/api/upstreams' @{
        name = 'mock-bad'; base_url = "http://127.0.0.1:$MOCK_BAD"
        api_key = $KEY_BAD; auth_style = 'auto'; enabled = $true; l1_path = '/v1/models'
    }
    $upOK = Admin POST '/admin/api/upstreams' @{
        name = 'mock-ok'; base_url = "http://127.0.0.1:$MOCK_OK"
        api_key = $KEY_OK; auth_style = 'auto'; enabled = $true; l1_path = '/v1/models'
    }
    # priority 小的先选。坏站排前面，保证第一次尝试必然撞上它。
    $rtBad = Admin POST '/admin/api/routes' @{
        model_name_id = $mn.id; upstream_id = $upBad.id
        priority = 1; weight = 100; enabled = $true
    }
    $rtOK = Admin POST '/admin/api/routes' @{
        model_name_id = $mn.id; upstream_id = $upOK.id
        priority = 2; weight = 100; enabled = $true
    }
    Pass "配置完成（坏站 route=$($rtBad.id)，好站 route=$($rtOK.id)）"

    # 等配置快照生效。livecfg 有 2s TTL 缓存 —— 刚写完就发请求会撞上
    # 上一份快照（那时还没有任何 ModelName），得到一个误导性的
    # 「模型未配置」404。轮询直到真的可选，而不是固定 Sleep：
    # 固定睡的脚本在慢机器上会偶发失败，而偶发失败的冒烟没人会信。
    if (-not (WaitFor '配置快照生效' 15 {
        $r = Relay '{"model":"claude-opus-5","max_tokens":16}'
        $r.StatusCode -ne 404
    })) { throw '配置一直没生效' }
    Pass '配置快照已生效'

    # 清空预热请求留下的日志，让后面的统计从 0 开始
    Admin DELETE '/admin/api/request-logs' | Out-Null
    Start-Sleep -Seconds 2

    # ── 核心：换站重试 ───────────────────────────────────────
    Say '换站重试：坏站 502 → 好站成功'
    $r = Relay '{"model":"claude-opus-5","max_tokens":16}'

    Check '客户端拿到 200（重试兜住了坏站）' ($r.StatusCode -eq 200) `
        "得到 $($r.StatusCode)：$($r.Content)"
    Check '响应体来自好站' ($r.Content -match 'msg_1') "得到 $($r.Content)"
    # X-Relay-Attempts 只在真重试过时才有 —— 一次过的响应必须与 M5 逐字节相同
    Check 'X-Relay-Attempts = 2' ($r.Headers['X-Relay-Attempts'] -eq '2') `
        "得到 '$($r.Headers['X-Relay-Attempts'])'"

    Say '不需要重试时不留痕迹'
    # 停掉坏站的 Route，让请求一次就成功
    Admin PUT "/admin/api/routes/$($rtBad.id)" @{
        model_name_id = $mn.id; upstream_id = $upBad.id
        priority = 1; weight = 100; enabled = $false
    } | Out-Null
    Start-Sleep -Seconds 3  # 等 livecfg 的 2s TTL 过期

    $r2 = Relay '{"model":"claude-opus-5","max_tokens":16}'
    Check '一次过成功' ($r2.StatusCode -eq 200) "得到 $($r2.StatusCode)"
    Check '没重试就不该有 X-Relay-Attempts 头' `
        (-not $r2.Headers['X-Relay-Attempts']) `
        "得到 '$($r2.Headers['X-Relay-Attempts'])' —— 正常响应必须与 M5 逐字节相同"

    # 恢复坏站 Route，后面的检查要用到那条重试记录
    Admin PUT "/admin/api/routes/$($rtBad.id)" @{
        model_name_id = $mn.id; upstream_id = $upBad.id
        priority = 1; weight = 100; enabled = $true
    } | Out-Null

    # ── 最危险的一条：出站头必须每次重建 ──────────────────────
    Say 'A 站的 key 绝不能出现在发往 B 站的请求里'
    # 从**站那一侧**看：mock 的 stderr 记下了每个请求收到的 x-api-key。
    # 网关自己的样本是脱敏后的，看不出收到的到底是谁的 key。
    Start-Sleep -Seconds 1
    $badLog = Get-Content "m6-mock-$MOCK_BAD.log" -Raw -ErrorAction SilentlyContinue
    $okLog = Get-Content "m6-mock-$MOCK_OK.log" -Raw -ErrorAction SilentlyContinue

    Check '坏站收到的是它自己的 key' ($badLog -match [regex]::Escape($KEY_BAD)) `
        '坏站日志里没有它自己的 key'
    Check '好站收到的是它自己的 key' ($okLog -match [regex]::Escape($KEY_OK)) `
        '好站日志里没有它自己的 key'
    # 这一条是重点：换站时若复用了上一次的 outHeader，好站就会收到坏站的 key
    Check '好站**没有**收到坏站的 key' (-not ($okLog -match [regex]::Escape($KEY_BAD))) `
        '好站收到了坏站的 key —— 换站时复用了上一次尝试的出站头'
    Check '坏站**没有**收到好站的 key' (-not ($badLog -match [regex]::Escape($KEY_OK))) `
        '坏站收到了好站的 key'

    # ── 请求日志 ─────────────────────────────────────────────
    Say '请求日志：每次尝试一行，同一 req_id'
    Start-Sleep -Seconds 2  # 等后台 writer 落库

    $logs = Admin GET '/admin/api/request-logs?limit=100'
    Check '日志有记录' ($logs.total -gt 0) "total=$($logs.total)"

    # 找出那次重试的组：它有 2 行、同一个 req_id
    $groups = $logs.logs | Group-Object req_id
    $retried = $groups | Where-Object { $_.Count -gt 1 } | Select-Object -First 1
    Check '存在一组多次尝试的日志' ($null -ne $retried) '没有任何一组包含多行'

    if ($retried) {
        $rows = $retried.Group | Sort-Object attempt
        Check '该组恰好 2 行' ($rows.Count -eq 2) "得到 $($rows.Count) 行"
        Check 'attempt 依次为 1、2' `
            ($rows[0].attempt -eq 1 -and $rows[1].attempt -eq 2) `
            "得到 $($rows[0].attempt)、$($rows[1].attempt)"
        # attempts 是**总次数**，每一行都该是最终值（要等循环结束才知道）
        Check '两行的 attempts 都是 2' `
            ($rows[0].attempts -eq 2 -and $rows[1].attempts -eq 2) `
            "得到 $($rows[0].attempts)、$($rows[1].attempts) —— 前几行没回填最终值"
        Check '第 1 次打的是坏站' ($rows[0].upstream_name -eq 'mock-bad') `
            "得到 $($rows[0].upstream_name)"
        Check '第 2 次打的是好站' ($rows[1].upstream_name -eq 'mock-ok') `
            "得到 $($rows[1].upstream_name)"
        Check '第 1 次记录为 502' ($rows[0].resp_status -eq 502) `
            "得到 $($rows[0].resp_status)"
        Check '第 1 次标记 retried（被丢弃换站）' ($rows[0].retried -eq $true) `
            'retried 为 false —— 算不出「重试救回来了多少」'
        Check '第 2 次不标 retried（它是最终采用的）' ($rows[1].retried -eq $false) `
            'retried 为 true'
        Check '第 2 次 outcome=ok' ($rows[1].outcome -eq 'ok') `
            "得到 $($rows[1].outcome)"
        # 最后一行必须在 Commit 之后才记，否则字节数是 0 —— 而 0 字节的 200
        # 正是「假活」的判据，所有正常请求都会被显示成假活
        Check '第 2 次记下了写出的字节数' ($rows[1].bytes_written -gt 0) `
            "bytes_written=$($rows[1].bytes_written) —— 日志在 Commit 之前就记了？"
    }

    Say '重试统计'
    $stats = (Admin GET '/admin/api/retry-stats?hours=24').stats
    Check '统计到了客户端请求' ($stats.requests -ge 2) "requests=$($stats.requests)"
    Check '尝试数多于请求数（重试的额外开销）' ($stats.attempts -gt $stats.requests) `
        "attempts=$($stats.attempts) requests=$($stats.requests)"
    Check '有 1 次重试被救回' ($stats.rescued_by_retry -ge 1) `
        "rescued_by_retry=$($stats.rescued_by_retry)"
    # 自洽性：救回来的 + 仍失败的 = 重试过的。
    # 不自洽的展示会让人立刻不再相信整个界面。
    Check '统计自洽（救回 + 仍失败 = 重试过）' `
        (($stats.rescued_by_retry + $stats.failed_after_retry) -eq $stats.retried) `
        "$($stats.rescued_by_retry) + $($stats.failed_after_retry) != $($stats.retried)"

    Say '日志与样本靠 req_id 关联'
    $samples = Admin GET '/admin/api/samples?limit=100'
    Check '样本有记录' ($samples.total -gt 0) "total=$($samples.total)"
    if ($retried) {
        $linked = $samples.samples | Where-Object { $_.req_id -eq $retried.Name }
        Check '能用日志的 req_id 找到对应样本' ($null -ne $linked) `
            "req_id=$($retried.Name) 在样本里找不到 —— 两张表关联不上"
        # 样本记的是**最终**那次尝试（客户端实际拿到的），不是被丢弃的那次
        if ($linked) {
            Check '样本记的是最终那次尝试（好站）' ($linked.upstream_id -eq $upOK.id) `
                "样本的 upstream_id=$($linked.upstream_id)，期望好站 $($upOK.id)"
        }
    }

    # ── 脱敏：M6 新增了一整张表，那是一个新的泄露面 ────────────
    Say 'key 脱敏（§9.4：真 key 全表 grep 零命中）'
    # 坏站的响应体里回显了它收到的 key（真实中转站的常见格式）。
    # 那段文本会流进 request_log.error 与 sample.resp_body。
    $logsJson = (Admin GET '/admin/api/request-logs?limit=100' | ConvertTo-Json -Depth 10)
    $leakInLogs = @()
    foreach ($secret in @($KEY_BAD, $KEY_OK, $KEY)) {
        if ($logsJson.Contains($secret)) { $leakInLogs += $secret }
    }
    Check 'API 返回的日志里搜不到明文 key' ($leakInLogs.Count -eq 0) `
        "泄露：$($leakInLogs -join ', ')"

    # 直接扫库文件 —— API 层脱敏对了不代表落库时也对
    Start-Sleep -Seconds 2  # 等 WAL 落盘
    $dbDir = Split-Path $DB
    $dbName = Split-Path $DB -Leaf
    $leakInDB = @()
    foreach ($f in Get-ChildItem -Path $dbDir -Filter "$dbName*") {
        # 必须共享读打开：relay-gate 还开着这个文件
        $fs = [IO.File]::Open($f.FullName, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $raw = New-Object byte[] $fs.Length
            $fs.Read($raw, 0, $raw.Length) | Out-Null
        } finally { $fs.Dispose() }
        $text = [Text.Encoding]::ASCII.GetString($raw)
        foreach ($secret in @($KEY_BAD, $KEY_OK, $KEY)) {
            if ($text.Contains($secret)) { $leakInDB += "$($f.Name) 含 $secret" }
        }
    }
    # 上游 key 在 upstream 表里是 AES-GCM 密文，relay key 根本不落库，
    # 而 M6 新增的 request_log 同样要过脱敏 —— 三处都不该有明文。
    Check '库文件里搜不到明文 key（含新增的 request_log 表）' `
        ($leakInDB.Count -eq 0) ($leakInDB -join '; ')

    # ── 健康回写：被丢弃的尝试也要算账 ────────────────────────
    Say '被丢弃的尝试也回写了健康状态（§3.5）'
    $health = Admin GET '/admin/api/health'
    $badHealth = $health.routes | Where-Object { $_.route_id -eq $rtBad.id }
    # 字段在嵌套的 health 对象里（api/health.go 的 routeHealth 结构）
    Check '坏站有失败记录' ($badHealth.health.consecutive_fail -gt 0) `
        ("consecutive_fail=$($badHealth.health.consecutive_fail) —— 重试成功兜住了，" +
         '但那次失败必须照样回写，否则挂掉的站要等下一个定时探活才被发现')
    Check '坏站的 last_error 里也没有明文 key' `
        (-not ($badHealth.health.last_error -match [regex]::Escape($KEY_BAD))) `
        "last_error=$($badHealth.health.last_error)"

    # ── 关掉日志开关 ─────────────────────────────────────────
    Say '关掉日志开关后零写入'
    $before = (Admin GET '/admin/api/request-logs?limit=1').total
    Admin PUT '/admin/api/settings' @{
        real_connect_sec = 5; real_first_token_sec = 300; real_idle_sec = 30; real_total_sec = 300
        l1_connect_sec = 3; l1_total_sec = 5
        l2_connect_sec = 3; l2_first_token_sec = 5; l2_total_sec = 8
        count_tokens_sec = 10
        l1_interval_alive_sec = 60; l1_interval_dead_sec = 60
        l2_interval_alive_sec = 300; l2_interval_dead_sec = 300
        fail_threshold = 2; ok_threshold = 2; cooldown_sec = 5
        global_l2_concurrency = 3
        probe_enabled = $false; piggyback_enabled = $false; half_open_enabled = $false
        retry_max_attempts = 3
        sample_enabled = $true; sample_max_body_bytes = 0
        sample_resp_head_bytes = 0; sample_resp_tail_bytes = 0
        sample_keep_count = 300; sample_keep_days = 7; sample_queue_size = 256
        request_log_enabled = $false; request_log_keep_count = 5000
        request_log_keep_days = 7; request_log_queue_size = 512
    } | Out-Null
    Start-Sleep -Seconds 3  # 等 livecfg TTL

    Relay '{"model":"claude-opus-5","max_tokens":16}' | Out-Null
    Start-Sleep -Seconds 2
    $after = (Admin GET '/admin/api/request-logs?limit=1').total
    Check '关掉开关后不再写日志' ($after -eq $before) "$before → $after"

    # ── 运行时计数有出口 ─────────────────────────────────────
    Say '丢弃计数有出口'
    $rt = Admin GET '/admin/api/runtime'
    Check 'runtime 暴露了日志的写入计数' `
        ($null -ne $rt.request_logs_written) '字段缺失 —— 界面上看不到丢弃数'
    Check '日志写入数 > 0' ($rt.request_logs_written -gt 0) `
        "request_logs_written=$($rt.request_logs_written)"
    Check '本次没有丢弃（队列够用）' ($rt.request_logs_dropped -eq 0) `
        "dropped=$($rt.request_logs_dropped)"

} catch {
    Fail "脚本异常：$_"
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
} finally {
    Say '收尾'
    Cleanup
}

Write-Host ''
if ($script:fails -eq 0) {
    Write-Host '全部通过' -ForegroundColor Green
    exit 0
} else {
    Write-Host "$($script:fails) 项失败" -ForegroundColor Red
    exit 1
}
