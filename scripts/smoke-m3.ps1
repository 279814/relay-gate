# M3 故障注入验证（§9.3）
#
# 用 mock-upstream.py 起几个不同行为的靶站，验证探活能否正确判死/判活/恢复。
# 这些场景本地可复现，不消耗真实公益站的额度。
#
# 用法：pwsh -File scripts/smoke-m3.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$GO = 'C:\Program Files\Go\bin\go.exe'
$PORT = 18801
$MOCK_OK = 19001
$MOCK_DEAD = 19002
$MOCK_FAKE = 19003

$KEY = 'rk-m3-smoke'
$ADMIN = 'admin-m3-smoke'
$DB = 'data/m3-smoke.db'

$script:procs = @()
$script:fails = 0

function Say($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg) {
    Write-Host "  [FAIL] $msg" -ForegroundColor Red
    $script:fails++
}

function Cleanup {
    foreach ($p in $script:procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item -Force "$DB*" -ErrorAction SilentlyContinue
}

# admin API 用 Bearer，不是 Basic
function Admin($method, $path, $body) {
    $h = @{ Authorization = "Bearer $ADMIN" }
    $args = @{
        Uri = "http://127.0.0.1:$PORT$path"
        Method = $method
        Headers = $h
        UseBasicParsing = $true
        TimeoutSec = 15
    }
    if ($body) {
        $args.Body = ($body | ConvertTo-Json -Depth 10 -Compress)
        $args.ContentType = 'application/json'
    }
    (Invoke-WebRequest @args).Content | ConvertFrom-Json
}

# 轮询直到条件成立，避免固定 Sleep 造成的偶发失败
function WaitFor($what, $timeoutSec, $probe) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (& $probe) { return $true }
        Start-Sleep -Milliseconds 500
    }
    Fail "$what（等了 ${timeoutSec}s 没等到）"
    return $false
}

function StateOf($routeId) {
    $h = Admin GET '/admin/api/health'
    ($h.routes | Where-Object { $_.route_id -eq $routeId }).state
}

try {
    Say '准备：编译 + 起靶站'
    & $GO build -o relay-gate.exe ./cmd/relay-gate
    if ($LASTEXITCODE -ne 0) { throw '编译失败' }
    Remove-Item -Force "$DB*" -ErrorAction SilentlyContinue

    foreach ($cfg in @(
        @{ Port = $MOCK_OK;   Scenario = 'normal' },
        @{ Port = $MOCK_DEAD; Scenario = 'dead' },
        @{ Port = $MOCK_FAKE; Scenario = 'fake_empty' }
    )) {
        $script:procs += Start-Process -FilePath 'python' `
            -ArgumentList "scripts/mock-upstream.py $($cfg.Port) $($cfg.Scenario)" `
            -NoNewWindow -PassThru -RedirectStandardError "mock-$($cfg.Port).log"
    }
    Start-Sleep -Seconds 2

    Say '启动 relay-gate'
    $env:ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef'
    $env:RELAY_KEYS = $KEY
    $env:ADMIN_PASSWORD = $ADMIN
    $env:RELAY_ADDR = "127.0.0.1:$PORT"
    $env:RELAY_DB = $DB
    $script:procs += Start-Process -FilePath '.\relay-gate.exe' -NoNewWindow -PassThru `
        -RedirectStandardOutput 'm3-gate.log' -RedirectStandardError 'm3-gate-err.log'

    if (-not (WaitFor '网关启动' 15 {
        try { (Invoke-WebRequest "http://127.0.0.1:$PORT/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { $false }
    })) { throw '网关没起来' }
    Pass '网关已启动'

    Say '配置：3 个站 + 1 个 ModelName + 3 条 Route'
    # 探活间隔压到最短，让验证不必等分钟级
    Admin PUT '/admin/api/settings' @{
        real_connect_sec = 5; real_first_token_sec = 300; real_idle_sec = 30; real_total_sec = 300
        l1_connect_sec = 3; l1_total_sec = 5
        l2_connect_sec = 3; l2_first_token_sec = 5; l2_total_sec = 8
        count_tokens_sec = 10
        l1_interval_alive_sec = 2; l1_interval_dead_sec = 2
        l2_interval_alive_sec = 3; l2_interval_dead_sec = 2
        fail_threshold = 2; ok_threshold = 2; cooldown_sec = 5
        global_l2_concurrency = 3
        probe_enabled = $true; piggyback_enabled = $true; half_open_enabled = $true
        sample_enabled = $true; sample_max_body_bytes = 262144
        sample_resp_head_bytes = 65536; sample_resp_tail_bytes = 8192
        sample_keep_count = 500; sample_keep_days = 7; sample_queue_size = 256
    } | Out-Null
    Pass '设置已写入（探活间隔压到 2-3s）'

    $mn = Admin POST '/admin/api/model-names' @{
        name = 'claude-opus-5'; protocol = 'anthropic'; match_mode = 'exact'; enabled = $true
    }

    $upOK = Admin POST '/admin/api/upstreams' @{
        name = 'mock-ok'; base_url = "http://127.0.0.1:$MOCK_OK"
        api_key = 'sk-mock-ok-key-1234'; auth_style = 'auto'; enabled = $true; l1_path = '/v1/models'
    }
    $upDead = Admin POST '/admin/api/upstreams' @{
        name = 'mock-dead'; base_url = "http://127.0.0.1:$MOCK_DEAD"
        api_key = 'sk-mock-dead-key-1234'; auth_style = 'auto'; enabled = $true; l1_path = '/v1/models'
    }
    $upFake = Admin POST '/admin/api/upstreams' @{
        name = 'mock-fake'; base_url = "http://127.0.0.1:$MOCK_FAKE"
        api_key = 'sk-mock-fake-key-1234'; auth_style = 'auto'; enabled = $true; l1_path = '/v1/models'
    }

    # 优先级：好站 1，假活站 2，死站 3
    $rtOK = Admin POST '/admin/api/routes' @{
        model_name_id = $mn.id; upstream_id = $upOK.id; priority = 1; weight = 100; enabled = $true
    }
    $rtFake = Admin POST '/admin/api/routes' @{
        model_name_id = $mn.id; upstream_id = $upFake.id; priority = 2; weight = 100; enabled = $true
    }
    $rtDead = Admin POST '/admin/api/routes' @{
        model_name_id = $mn.id; upstream_id = $upDead.id; priority = 3; weight = 100; enabled = $true
    }
    Pass "配置完成（好站 route=$($rtOK.id)，假活 route=$($rtFake.id)，死站 route=$($rtDead.id)）"

    # ── §9.3 验收项 ─────────────────────────────────────────

    Say '9.3a  好站应被探活判为 alive'
    if (WaitFor '好站转 alive' 30 { (StateOf $rtOK.id) -eq 'alive' }) {
        Pass "好站 state=alive"
    }

    Say '9.3b  全挂站（一律 503）应被判 dead'
    if (WaitFor '死站转 dead' 30 { (StateOf $rtDead.id) -eq 'dead' }) {
        Pass '死站 state=dead'
        $h = Admin GET '/admin/api/health'
        $row = $h.routes | Where-Object { $_.route_id -eq $rtDead.id }
        if ($row.selectable) { Fail 'dead 的 Route 不该 selectable' }
        else { Pass "已从选路排除：$($row.reason)" }
    }

    Say '9.3c  假活站（200 但无 delta）应被判 dead'
    if (WaitFor '假活站转 dead' 30 { (StateOf $rtFake.id) -eq 'dead' }) {
        Pass '假活站 state=dead（只看状态码会漏判这种）'
        $h = Admin GET '/admin/api/health'
        $row = $h.routes | Where-Object { $_.route_id -eq $rtFake.id }
        if ($row.health.last_error -match '假活') { Pass "原因正确：$($row.health.last_error)" }
        else { Fail "原因应说明是假活，得到：$($row.health.last_error)" }
    }

    Say '9.3d  真实请求应路由到好站'
    $body = @{ model = 'claude-opus-5'; max_tokens = 16; stream = $false
               messages = @(@{ role = 'user'; content = '1+1=?' }) } | ConvertTo-Json -Depth 5 -Compress
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$PORT/v1/messages" -Method POST `
        -Headers @{ 'x-api-key' = $KEY; 'anthropic-version' = '2023-06-01' } `
        -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 30
    if ($resp.StatusCode -eq 200) { Pass "真实请求 200（转发到了存活的站）" }
    else { Fail "真实请求应 200，得到 $($resp.StatusCode)" }

    Say '9.3e  手动探活端点'
    $pr = Admin POST "/admin/api/routes/$($rtOK.id)/probe" @{}
    if ($pr.l1.verdict -eq 'ok' -and $pr.l2.verdict -eq 'ok') {
        Pass "手动探活 L1=$($pr.l1.verdict) L2=$($pr.l2.verdict) ttft=$($pr.l2.ttft_ms)ms"
    } else {
        Fail "手动探活应全 ok，得到 L1=$($pr.l1.verdict) L2=$($pr.l2.verdict)"
    }
    $prDead = Admin POST "/admin/api/routes/$($rtDead.id)/probe" @{}
    if ($prDead.l1.verdict -ne 'ok') { Pass "死站手动探活正确失败：L1=$($prDead.l1.verdict)" }
    else { Fail '死站手动探活不该成功' }

    Say '9.3f  死站恢复应在一个探活周期内被发现（§4.4 核心诉求）'
    # 把死站换成正常站：停掉 dead 靶机，在同端口起 normal
    $deadProc = $script:procs | Where-Object { $_.CommandLine -like "*$MOCK_DEAD*" }
    Get-Process python -ErrorAction SilentlyContinue | ForEach-Object {
        $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
        if ($cl -like "*$MOCK_DEAD dead*") { Stop-Process -Id $_.Id -Force }
    }
    Start-Sleep -Seconds 1
    $script:procs += Start-Process -FilePath 'python' `
        -ArgumentList "scripts/mock-upstream.py $MOCK_DEAD normal" `
        -NoNewWindow -PassThru -RedirectStandardError "mock-$MOCK_DEAD-revived.log"
    Start-Sleep -Seconds 2

    $t0 = Get-Date
    if (WaitFor '死站恢复被发现' 30 { (StateOf $rtDead.id) -ne 'dead' }) {
        $took = ((Get-Date) - $t0).TotalSeconds
        Pass ("恢复在 {0:N1}s 内被发现，state={1}" -f $took, (StateOf $rtDead.id))
    }

    Say '9.3g  暂停应停掉探活，恢复应重新全量探'
    Admin POST '/admin/api/state' @{ state = 'paused' } | Out-Null
    Start-Sleep -Seconds 2
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:$PORT/v1/messages" -Method POST `
            -Headers @{ 'x-api-key' = $KEY; 'anthropic-version' = '2023-06-01' } `
            -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 10 | Out-Null
        Fail '暂停时代理端点应回 503'
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 503) { Pass '暂停时代理端点回 503' }
        else { Fail "暂停时应 503，得到 $($_.Exception.Response.StatusCode.value__)" }
    }
    # 管理端点必须始终可用，否则暂停后无法恢复
    $st = Admin GET '/admin/api/state'
    if ($st.state -eq 'paused') { Pass '暂停期间管理端点仍可用' }
    else { Fail "管理端点应报 paused，得到 $($st.state)" }

    Admin POST '/admin/api/state' @{ state = 'running' } | Out-Null
    if (WaitFor '恢复后重新探活' 30 { (StateOf $rtOK.id) -eq 'alive' }) {
        Pass '恢复后好站重新被探为 alive'
    }

    Say '9.3h  route_health 应落库（给 UI 看的快照）'
    Start-Sleep -Seconds 6   # Persister 是 5s 周期
    $h = Admin GET '/admin/api/health'
    if ($h.summary.total -eq 3) { Pass "看板返回 3 条 Route，可选 $($h.summary.selectable) 条" }
    else { Fail "看板应有 3 条，得到 $($h.summary.total)" }

    Say '9.4  样本里不得出现明文 key'
    $samples = Admin GET '/admin/api/samples?limit=50'
    $raw = $samples | ConvertTo-Json -Depth 20
    foreach ($k in @($KEY, 'sk-mock-ok-key-1234', 'sk-mock-dead-key-1234', 'sk-mock-fake-key-1234')) {
        if ($raw -match [regex]::Escape($k)) { Fail "样本里出现了明文 key：$k" }
    }
    Pass '样本中未出现任何明文 key'

} catch {
    Fail "脚本异常：$_"
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
} finally {
    Say '收尾'
    Cleanup
    if ($script:fails -eq 0) {
        Write-Host "`n全部通过`n" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`n$script:fails 项失败`n" -ForegroundColor Red
        exit 1
    }
}
