# M2 端到端冒烟：起一个假上游 + 真 relay-gate，验证透传链路通。
#
# 测试用的是 fake ConfigSource，这个脚本是第一次让 livecfg + health + proxy
# 跑在真实数据库上 —— 接线错误（比如忘了注册端点）只有这里能发现。
$ErrorActionPreference = 'Stop'
$env:PATH = "C:\Program Files\Go\bin;$env:PATH"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$work = Join-Path ([System.IO.Path]::GetTempPath()) "relay-gate-smoke-$(Get-Random)"
New-Item -ItemType Directory -Path $work -Force | Out-Null

$fakeUpstream = $null
$gate = $null
try {
    # ── 假上游：回显收到的请求，让我们能断言逐字节保真 ──
    $upstreamSrc = Join-Path $work 'fake-upstream.go'
    Set-Content -Path $upstreamSrc -Encoding utf8 -Value @'
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hdr := map[string]string{}
		for k := range r.Header {
			hdr[k] = r.Header.Get(k)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Fake-Upstream", "1")
		json.NewEncoder(w).Encode(map[string]any{
			"got_path":    r.URL.Path,
			"got_query":   r.URL.RawQuery,
			"got_body":    string(body),
			"got_headers": hdr,
		})
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:19999", nil))
}
'@

    Write-Host '起假上游...' -ForegroundColor Cyan
    $fakeUpstream = Start-Process -FilePath 'go' -ArgumentList @('run', $upstreamSrc) `
        -PassThru -NoNewWindow -RedirectStandardError (Join-Path $work 'upstream.err')

    Write-Host '编译 relay-gate...' -ForegroundColor Cyan
    $bin = Join-Path $work 'relay-gate.exe'
    & go build -o $bin ./cmd/relay-gate
    if ($LASTEXITCODE -ne 0) { throw '编译失败' }

    $env:RELAY_ADDR = '127.0.0.1:18888'
    $env:RELAY_DB = Join-Path $work 'smoke.db'
    $env:ENCRYPTION_KEY = 'smoke-test-encryption-key-32byte'
    $env:ADMIN_PASSWORD = 'smoke-admin-pw'
    $env:RELAY_KEYS = 'rk-smoke-client'

    Write-Host '起 relay-gate...' -ForegroundColor Cyan
    $gate = Start-Process -FilePath $bin -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $work 'gate.out') `
        -RedirectStandardError (Join-Path $work 'gate.err')

    # 等两个服务就绪
    $ready = $false
    foreach ($i in 1..40) {
        Start-Sleep -Milliseconds 500
        try {
            Invoke-RestMethod 'http://127.0.0.1:18888/healthz' -TimeoutSec 2 | Out-Null
            Invoke-RestMethod 'http://127.0.0.1:19999/ping' -TimeoutSec 2 | Out-Null
            $ready = $true; break
        } catch { }
    }
    if (-not $ready) {
        Write-Host (Get-Content (Join-Path $work 'gate.err') -Raw) -ForegroundColor Red
        throw '服务未就绪'
    }

    $admin = @{ Authorization = 'Bearer smoke-admin-pw' }
    $fail = 0
    function Check($name, $cond, $detail) {
        if ($cond) { Write-Host "  PASS  $name" -ForegroundColor Green }
        else { Write-Host "  FAIL  $name`n        $detail" -ForegroundColor Red; $script:fail++ }
    }

    # ── 配置：1 个上游 + 1 个 ModelName + 1 条 Route ──
    Write-Host "`n配置..." -ForegroundColor Cyan
    $up = Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/admin/api/upstreams' `
        -Headers $admin -ContentType 'application/json' -Body (@{
            name = 'fake'; base_url = 'http://127.0.0.1:19999'
            api_key = 'sk-fake-upstream-key'; enabled = $true
        } | ConvertTo-Json)
    $mn = Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/admin/api/model-names' `
        -Headers $admin -ContentType 'application/json' -Body (@{
            name = 'claude-opus-5'; protocol = 'anthropic'; enabled = $true
        } | ConvertTo-Json)
    Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/admin/api/routes' `
        -Headers $admin -ContentType 'application/json' -Body (@{
            model_name_id = $mn.id; upstream_id = $up.id; enabled = $true
        } | ConvertTo-Json) | Out-Null

    # GET 回显必须脱敏，否则管理接口就是个 key 泄露口子
    $got = Invoke-RestMethod "http://127.0.0.1:18888/admin/api/upstreams/$($up.id)" -Headers $admin
    Check 'api_key 回显已脱敏' ($got.api_key -ne 'sk-fake-upstream-key') "回显了 $($got.api_key)"

    Start-Sleep -Seconds 3  # 等过 livecfg 的 TTL

    # ── 透传 ──
    Write-Host "`n透传..." -ForegroundColor Cyan
    $body = '{"max_tokens":1,"model":"claude-opus-5","temperature":1.0,"system":"A & B"}'
    $resp = Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/v1/messages?beta=true' `
        -Headers @{
            'X-Api-Key' = 'rk-smoke-client'
            'Anthropic-Version' = '2023-06-01'
            'User-Agent' = 'claude-cli/2.1.220 (external, sdk-cli)'
            'X-Stainless-Retry-Count' = '0'
        } -ContentType 'application/json' -Body $body

    Check 'body 逐字节保真' ($resp.got_body -ceq $body) "上游收到 $($resp.got_body)"
    Check '路径 1:1 直通' ($resp.got_path -eq '/v1/messages') "得到 $($resp.got_path)"
    Check 'query 原样带上' ($resp.got_query -eq 'beta=true') "得到 $($resp.got_query)"
    Check '注入上游 key' ($resp.got_headers.'X-Api-Key' -eq 'sk-fake-upstream-key') `
        "得到 $($resp.got_headers.'X-Api-Key')"
    Check 'relay key 未泄露' (($resp.got_headers.PSObject.Properties.Value -notcontains 'rk-smoke-client')) `
        'relay key 出现在上游请求头里'
    Check 'UA 原样转发' ($resp.got_headers.'User-Agent' -eq 'claude-cli/2.1.220 (external, sdk-cli)') `
        "得到 $($resp.got_headers.'User-Agent')"
    Check 'X-Stainless-* 转发' ($resp.got_headers.'X-Stainless-Retry-Count' -eq '0') '丢了'

    # ── 鉴权 ──
    Write-Host "`n鉴权..." -ForegroundColor Cyan
    $r = Invoke-WebRequest -Method Post 'http://127.0.0.1:18888/v1/messages' `
        -Headers @{ 'X-Api-Key' = 'rk-wrong' } -ContentType 'application/json' `
        -Body '{"model":"claude-opus-5"}' -SkipHttpErrorCheck
    Check '错的 relay key 回 401' ($r.StatusCode -eq 401) "得到 $($r.StatusCode)"

    $r = Invoke-WebRequest -Method Post 'http://127.0.0.1:18888/v1/messages' `
        -Headers @{ 'X-Api-Key' = 'rk-smoke-client' } -ContentType 'application/json' `
        -Body '{"model":"never-configured"}' -SkipHttpErrorCheck
    Check '未配置的 model 回 404' ($r.StatusCode -eq 404) "得到 $($r.StatusCode)"

    # ── 样本记录（§3.6 / §9.4）──
    # 这是第一次让样本链路跑在真数据库上：脱敏漏了、字节被改了、
    # 或者根本没落库，都只有这里能发现。
    Write-Host "`n样本记录..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1  # 等后台 writer 落库

    $samples = Invoke-RestMethod 'http://127.0.0.1:18888/admin/api/samples' -Headers $admin
    Check '样本已落库' ($samples.total -ge 1) "total=$($samples.total)"

    if ($samples.total -ge 1) {
        # 找那条成功转发的（列表按 id 倒序，最新的在前）
        $okSample = $samples.samples | Where-Object { $_.outcome -eq 'ok' } | Select-Object -First 1
        Check '记录了 outcome=ok 的样本' ($null -ne $okSample) '没找到成功样本'

        if ($okSample) {
            $detail = Invoke-RestMethod "http://127.0.0.1:18888/admin/api/samples/$($okSample.id)" -Headers $admin

            # body 是 []byte，JSON 编码成 base64
            $inBody = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($detail.in_body))
            $outBody = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($detail.out_body))
            Check 'in_body 是入站原文' ($inBody -ceq $body) "得到 $inBody"
            Check '不映射时两份 body 完全一致' ($inBody -ceq $outBody) "in=$inBody out=$outBody"

            Check '四个时间戳齐全' (
                $detail.ts_recv -gt 0 -and $detail.ts_sent -gt 0 -and
                $detail.ts_first_byte -gt 0 -and $detail.ts_done -gt 0
            ) "recv=$($detail.ts_recv) sent=$($detail.ts_sent) first=$($detail.ts_first_byte) done=$($detail.ts_done)"

            Check '选路结果已留档' (
                $detail.route_id -gt 0 -and $detail.upstream_id -gt 0 -and $detail.model_name_id -gt 0
            ) "route=$($detail.route_id) upstream=$($detail.upstream_id)"
            Check 'in_query 已留档' ($detail.in_query -eq 'beta=true') "得到 $($detail.in_query)"

            # 脱敏必须保留结构：调探活时要知道 key 放哪个头、什么格式
            $auth = $detail.out_headers.Authorization
            Check '出站头保留 Bearer 前缀' ($auth -and $auth[0].StartsWith('Bearer ')) "得到 $auth"
            Check '出站头保留 UA' (
                $detail.out_headers.'User-Agent'[0] -eq 'claude-cli/2.1.220 (external, sdk-cli)'
            ) "得到 $($detail.out_headers.'User-Agent')"
        }
    }

    # §9.4 的验收标准：拿真 key 到数据库文件里 grep，断言 0 命中。
    # 这比查 API 更硬 —— API 可能只是没回显，而字节可能真的躺在库里。
    Write-Host "`nkey 脱敏（直接扫库文件）..." -ForegroundColor Cyan
    Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/admin/api/state' -Headers $admin `
        -ContentType 'application/json' -Body '{"state":"running"}' | Out-Null
    Start-Sleep -Seconds 2  # 等 WAL 落盘

    $dbFiles = Get-ChildItem -Path (Split-Path $env:RELAY_DB) -Filter 'smoke.db*'
    $leaked = @()
    foreach ($f in $dbFiles) {
        # 必须用共享读打开：relay-gate 还开着这个文件，
        # ReadAllBytes 会因独占访问失败。
        $fs = [IO.File]::Open($f.FullName, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $raw = New-Object byte[] $fs.Length
            $fs.Read($raw, 0, $raw.Length) | Out-Null
        } finally { $fs.Dispose() }

        $text = [Text.Encoding]::ASCII.GetString($raw)
        foreach ($secret in @('rk-smoke-client', 'sk-fake-upstream-key')) {
            if ($text.Contains($secret)) { $leaked += "$($f.Name) 含 $secret" }
        }
    }
    # 上游 key 在 upstream 表里是 AES-GCM 密文，relay key 根本不落库，
    # 所以整个库文件里都不该出现明文。
    Check '库文件里搜不到任何明文 key' ($leaked.Count -eq 0) ($leaked -join '; ')

    # ── 总闸 ──
    Write-Host "`n总闸..." -ForegroundColor Cyan
    Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/admin/api/state' -Headers $admin `
        -ContentType 'application/json' -Body '{"state":"paused"}' | Out-Null
    Start-Sleep -Seconds 3

    $r = Invoke-WebRequest -Method Post 'http://127.0.0.1:18888/v1/messages' `
        -Headers @{ 'X-Api-Key' = 'rk-smoke-client' } -ContentType 'application/json' `
        -Body '{"model":"claude-opus-5"}' -SkipHttpErrorCheck
    Check '暂停后回 503' ($r.StatusCode -eq 503) "得到 $($r.StatusCode)"
    Check '带 X-Relay-State' ($r.Headers['X-Relay-State'] -contains 'paused') '缺少该头'

    Invoke-RestMethod -Method Post 'http://127.0.0.1:18888/admin/api/state' -Headers $admin `
        -ContentType 'application/json' -Body '{"state":"running"}' | Out-Null
    Start-Sleep -Seconds 3
    $r = Invoke-WebRequest -Method Post 'http://127.0.0.1:18888/v1/messages' `
        -Headers @{ 'X-Api-Key' = 'rk-smoke-client' } -ContentType 'application/json' `
        -Body '{"model":"claude-opus-5"}' -SkipHttpErrorCheck
    Check '恢复后放行' ($r.StatusCode -eq 200) "得到 $($r.StatusCode)"

    Write-Host ''
    if ($fail -gt 0) { Write-Host "$fail 项失败" -ForegroundColor Red; exit 1 }
    Write-Host '全部通过' -ForegroundColor Green
}
finally {
    foreach ($p in @($gate, $fakeUpstream)) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            # go run 会派生子进程，父进程被杀后子进程还占着端口
            Get-CimInstance Win32_Process -Filter "ParentProcessId = $($p.Id)" -ErrorAction SilentlyContinue |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        }
    }
    Start-Sleep -Milliseconds 500
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
