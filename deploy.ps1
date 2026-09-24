# One-command install (Windows/macOS/Linux host with Docker Desktop or Engine).
# Access: http://<host-IP>:18787/admin/
# First start prints ADMIN_PASSWORD / RELAY_KEYS / ENCRYPTION_KEY once (container logs).
param(
  [switch]$Local
)

# -Local kept for README / release-test compatibility; behavior is the same.
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Host "Docker is required. Start Docker Desktop, then re-run .\deploy.ps1" -ForegroundColor Red
  exit 2
}

New-Item -ItemType Directory -Force -Path (Join-Path $root "data") | Out-Null

$port = 18787
if (Test-Path .env) {
  $line = Get-Content .env | Where-Object { $_ -match '^\s*RELAY_PORT\s*=' } | Select-Object -First 1
  if ($line -match '=\s*(.+)$') { $port = [int]($Matches[1].Trim()) }
}

Write-Host "Building and starting relay-gate (http://0.0.0.0:$port)..."
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Waiting for healthz..."
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
  try {
    $r = Invoke-WebRequest "http://127.0.0.1:$port/healthz" -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { $ok = $true; break }
  } catch { }
  Start-Sleep -Seconds 1
}
if (-not $ok) {
  Write-Host "Service did not become healthy. Recent logs:" -ForegroundColor Red
  docker compose logs --tail 80
  exit 1
}

Write-Host ""
Write-Host "Open http://<this-host-IP>:$port/admin/"
Write-Host "On first start, three secrets are printed once in the container log:"
Write-Host '  docker compose logs --no-color 2>&1 | Select-String -Pattern "^(ADMIN_PASSWORD|RELAY_KEYS|ENCRYPTION_KEY)="'
Write-Host "Later restarts do not reprint them. Env still wins if set."
