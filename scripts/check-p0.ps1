# P0 offline gate (Windows).
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host '== go test probe fixtures / gates =='
go test ./internal/probe/ ./cmd/relay-gate/ -count=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '== private paths ignored =='
$gi = Get-Content .gitignore -Raw
$di = Get-Content .dockerignore -Raw
if ($gi -notmatch '\.local/p0/') { throw '.gitignore missing .local/p0/' }
if ($di -notmatch '\.local/p0/') { throw '.dockerignore missing .local/p0/' }

Write-Host '== probe CLI unauthorized =='
$bin = Join-Path $env:TEMP 'relay-gate-check-p0.exe'
go build -o $bin ./cmd/relay-gate
$out = Join-Path $env:TEMP 'should-not-exist-p0.json'
if (Test-Path $out) { Remove-Item $out -Force }
& $bin probe-one --input NUL --name x --output $out
$code = $LASTEXITCODE
Remove-Item $bin -Force -ErrorAction SilentlyContinue
if ($code -eq 0) { throw 'expected non-zero without online flags' }
if (Test-Path $out) { throw 'unauthorized must not create output' }
Write-Host 'check-p0 ok'
