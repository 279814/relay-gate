# Local one-line deploy (P2 §12.1). Does NOT replace docs/03 public nginx guide.
param(
  [switch]$Local
)

if (-not $Local) {
  Write-Host "Usage: .\deploy.ps1 -Local"
  Write-Host "Public IP mode is not verified in this PR; keep using docs/03 for domain/nginx deploys."
  exit 2
}

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function New-SecretHex([int]$bytes) {
  $buf = New-Object byte[] $bytes
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
  -join ($buf | ForEach-Object { $_.ToString("x2") })
}

if (-not (Test-Path .env)) {
  $enc = New-SecretHex 32
  $relay = "rk-" + (New-SecretHex 24)
  $admin = New-SecretHex 24
  @"
ENCRYPTION_KEY=$enc
RELAY_KEYS=$relay
ADMIN_PASSWORD=$admin
"@ | Set-Content -Encoding ascii .env
  Write-Host "Wrote .env with one-time credentials (shown once below):"
  Write-Host "ADMIN_PASSWORD=$admin"
  Write-Host "RELAY_KEYS=$relay"
  Write-Host "ENCRYPTION_KEY=$enc"
} else {
  Write-Host ".env already exists; not regenerating credentials."
}

$data = Join-Path $root "data"
New-Item -ItemType Directory -Force -Path $data | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $data "secrets") | Out-Null

Write-Host "Building relay-gate..."
go build -o relay-gate.exe ./cmd/relay-gate
Write-Host "Start with: .\relay-gate.exe  (binds per .env / config; prefer 127.0.0.1)"
Write-Host "Admin UI: http://127.0.0.1:18787/admin/"
