#Requires -Version 7.2
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$AllowedRoot,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$Alias,
    [Parameter(Mandatory)][string]$ClaudePath,
    [switch]$Execute
)

# Reuse the existing private-file and HTTP helpers, never its legacy launcher.
. "$PSScriptRoot/capture-claude-request.ps1" -RepositoryRoot $RepositoryRoot -AllowedRoot $AllowedRoot -OutputPath $OutputPath -ManifestPath $ManifestPath -Alias $Alias -ClaudePath $ClaudePath -Execute:$Execute
$profile220 = 'claude-code-2.1.220-windows-isolated-v1'
$executable220SHA = 'af5bf1f1b2aadffc768eccd787084c6fdf9ba81624cbe96c1c6d9ac1a1550231'

function Get-Control220Hash {
    param([AllowEmptyString()][string]$Text)
    return (Get-SHA256Text $Text).ToLowerInvariant()
}

function Initialize-Control220PrivateDirectory {
    param([string]$Repository, [string]$Allowed)
    $repositoryPath=Get-NormalizedFullPath $Repository
    $allowedPath=Get-NormalizedFullPath $Allowed
    $privateRoot=Join-Path $repositoryPath '.local/p0'
    if (-not (Test-PathWithinRoot $allowedPath $privateRoot)) { throw 'capture_not_under_private_context_root' }
    Assert-DirectoryCreationPathSafe $allowedPath $repositoryPath
    [void][IO.Directory]::CreateDirectory((Join-Path $repositoryPath '.local'))
    $current=$privateRoot
    $relative=[IO.Path]::GetRelativePath($privateRoot,$allowedPath)
    $directories=@($privateRoot)
    if ($relative -cne '.') {
        foreach ($part in $relative.Split([IO.Path]::DirectorySeparatorChar)) { $current=Join-Path $current $part; $directories+= $current }
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    foreach ($directory in $directories) {
        if (-not (Test-Path -LiteralPath $directory)) {
            [void][IO.Directory]::CreateDirectory($directory)
            & icacls.exe $directory '/inheritance:r' '/grant:r' "$($identity.Name):(OI)(CI)F" '/Q' *> $null
            if ($LASTEXITCODE -ne 0) { throw 'capture_acl_failed' }
        }
        Assert-NoReparsePoint $directory $repositoryPath
        $acl=Get-Acl -LiteralPath $directory
        $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl)
        if ($null -eq $raw.DiscretionaryAcl) { throw 'capture_parent_permissions_rejected' }
        foreach ($ace in $raw.DiscretionaryAcl) {
            if (($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -ne 0 -or $ace.AceType -eq [Security.AccessControl.AceType]::AccessDenied) { continue }
            if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or @($identity.User.Value,'S-1-5-18','S-1-5-32-544') -cnotcontains $ace.SecurityIdentifier.Value) { throw 'capture_parent_permissions_rejected' }
        }
    }
}

function Get-Control220Identity {
    param([string]$Nonce)
    $device = Get-Control220Hash "relay-gate-control-device-v1:$Nonce"
    $bytes = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("relay-gate-control-session-v1:$Nonce"))
    $bytes[6] = ($bytes[6] -band 15) -bor 64
    $bytes[8] = ($bytes[8] -band 63) -bor 128
    $hex = [Convert]::ToHexString($bytes[0..15]).ToLowerInvariant()
    return @{ Device = $device; Session = $hex.Substring(0,8)+'-'+$hex.Substring(8,4)+'-'+$hex.Substring(12,4)+'-'+$hex.Substring(16,4)+'-'+$hex.Substring(20,12) }
}

function Assert-Control220Block {
    param([Text.Json.JsonElement]$Value, [string]$Text, [bool]$Cached)
    $keys = @('type','text')
    if ($Cached) { $keys += 'cache_control' }
    Assert-ControlObjectKeys $Value $keys
    if ($Value.GetProperty('type').GetString() -cne 'text' -or $Value.GetProperty('text').GetString() -cne $Text) { throw 'capture_control_body_rejected' }
    if ($Cached) {
        $cache = $Value.GetProperty('cache_control')
        Assert-ControlObjectKeys $cache @('type')
        if ($cache.GetProperty('type').GetString() -cne 'ephemeral') { throw 'capture_control_body_rejected' }
    }
}

function Assert-Control220Body {
    param([byte[]]$Body, [string]$Nonce, [string]$CapturedAt)
    # Throw on invalid UTF-8 rather than silently replacing bytes.
    $doc = [Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($Body))
    try {
        $v = $doc.RootElement
        Assert-ControlObjectKeys $v @('model','messages','system','tools','metadata','max_tokens','thinking','output_config','stream')
        $model = $v.GetProperty('model').GetString()
        if ([string]::IsNullOrEmpty($model) -or $model.Length -gt 512 -or $model.Contains('{{') -or $model.Contains("`r") -or $model.Contains("`n") -or $v.GetProperty('max_tokens').GetInt64() -ne 64 -or -not $v.GetProperty('stream').GetBoolean()) { throw 'capture_control_body_rejected' }
        $tools = $v.GetProperty('tools')
        if ($tools.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $tools.GetArrayLength() -ne 0) { throw 'capture_control_body_rejected' }
        $thinking = $v.GetProperty('thinking'); Assert-ControlObjectKeys $thinking @('type')
        $output = $v.GetProperty('output_config'); Assert-ControlObjectKeys $output @('effort')
        if ($thinking.GetProperty('type').GetString() -cne 'disabled' -or $output.GetProperty('effort').GetString() -cne 'low') { throw 'capture_control_body_rejected' }
        $metadata = $v.GetProperty('metadata'); Assert-ControlObjectKeys $metadata @('user_id')
        $identity = [Text.Json.JsonDocument]::Parse($metadata.GetProperty('user_id').GetString())
        try {
            $id = $identity.RootElement; Assert-ControlObjectKeys $id @('device_id','account_uuid','session_id')
            $expected = Get-Control220Identity $Nonce
            if ($id.GetProperty('account_uuid').GetString() -cne '' -or $id.GetProperty('device_id').GetString() -cne $expected.Device -or $id.GetProperty('session_id').GetString() -cne $expected.Session) { throw 'capture_control_body_rejected' }
        } finally { $identity.Dispose() }
        $prompt = "1+1=? control:$Nonce"
        $checksum = (Get-Control220Hash ('59cf53e54c78'+$prompt[4]+$prompt[7]+$prompt[20]+'2.1.220')).Substring(0,3)
        $system = $v.GetProperty('system')
        if ($system.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $system.GetArrayLength() -ne 3) { throw 'capture_control_body_rejected' }
        Assert-Control220Block $system[0] "x-anthropic-billing-header: cc_version=2.1.220.$checksum; cc_entrypoint=sdk-cli;" $false
        $publicText = $system[1].GetProperty('text').GetString()
        if ((Get-Control220Hash $publicText) -cne '0d7062851dd7bd7e66d4be4f12ac4951e3d2f587ec408295333a49963bd3f6b7') { throw 'capture_control_body_rejected' }
        Assert-Control220Block $system[1] $publicText $true
        Assert-Control220Block $system[2] 'Reply with 2 only.' $true
        $messages = $v.GetProperty('messages')
        if ($messages.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $messages.GetArrayLength() -ne 1) { throw 'capture_control_body_rejected' }
        $message = $messages[0]; Assert-ControlObjectKeys $message @('role','content')
        $blocks = $message.GetProperty('content')
        if ($message.GetProperty('role').GetString() -cne 'user' -or $blocks.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $blocks.GetArrayLength() -ne 2) { throw 'capture_control_body_rejected' }
        $dateText = $blocks[0].GetProperty('text').GetString()
        $dates = [regex]::Matches($dateText,'[0-9]{4}-[0-9]{2}-[0-9]{2}')
        if ($dates.Count -ne 1) { throw 'capture_control_body_rejected' }
        $stamp = [DateTimeOffset]::Parse($CapturedAt).UtcDateTime
        $allowed = @($stamp.AddDays(-1).ToString('yyyy-MM-dd'),$stamp.ToString('yyyy-MM-dd'),$stamp.AddDays(1).ToString('yyyy-MM-dd'))
        if ($allowed -cnotcontains $dates[0].Value -or (Get-Control220Hash ([regex]::Replace($dateText,'[0-9]{4}-[0-9]{2}-[0-9]{2}','<date>'))) -cne '01e1d5f4002869dbdac1f7d22231b35f4b67467f0fe246bdb5cbcbe1d49ed865') { throw 'capture_control_body_rejected' }
        Assert-Control220Block $blocks[0] $dateText $false
        Assert-Control220Block $blocks[1] $prompt $true
    } finally { $doc.Dispose() }
}

function ConvertTo-Control220Envelope {
    param($Request, [string]$FakeKey, [string]$Nonce, [string]$CapturedAt, [string]$CompletedAt)
    Assert-Control220Body $Request.Body $Nonce $CapturedAt
    $expected = @{
        'host'=''; 'accept'='application/json'; 'accept-encoding'='identity'; 'content-type'='application/json';
        'content-length'=[string]$Request.Body.Length; 'connection'='keep-alive'; 'x-api-key'=$FakeKey;
        'user-agent'='claude-cli/2.1.220 (external, sdk-cli)'; 'x-stainless-arch'='x64'; 'x-stainless-lang'='js';
        'x-stainless-os'='Windows'; 'x-stainless-package-version'='0.94.0'; 'x-stainless-retry-count'='0';
        'x-stainless-runtime'='node'; 'x-stainless-runtime-version'='v26.3.0'; 'x-stainless-timeout'='600';
        'anthropic-beta'='claude-code-20250219,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07,effort-2025-11-24,fallback-credit-2026-06-01';
        'anthropic-dangerous-direct-browser-access'='true'; 'anthropic-version'='2023-06-01'; 'x-app'='cli';
        'x-claude-code-session-id'=(Get-Control220Identity $Nonce).Session
    }
    $headers = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($h in $Request.HeaderEntries) {
        $name = $h.Name.ToLowerInvariant()
        if (-not $expected.ContainsKey($name) -or -not $seen.Add($name) -or $h.Values.Count -ne 1) { throw 'capture_control_header_rejected' }
        if ($name -ceq 'host') { Assert-ControlHeader $name $h.Values $Request.Body.Length $null }
        elseif ($h.Values[0] -cne $expected[$name]) { throw 'capture_control_header_rejected' }
        $values = if ($name -ceq 'x-api-key') { @('{{UPSTREAM_API_KEY}}') } else { @($h.Values) }
        $headers.Add([ordered]@{name=$h.Name; values=@($values)})
    }
    if ($seen.Count -ne $expected.Count -or [Text.Encoding]::UTF8.GetString($Request.Body).Contains($FakeKey)) { throw 'capture_control_header_rejected' }
    $parts = $Request.RequestLine.Split(' ')
    if ($parts.Count -ne 3 -or $parts[0] -cne 'POST' -or $parts[2] -cne 'HTTP/1.1' -or @('/v1/messages','/v1/messages?beta=true') -cnotcontains $parts[1]) { throw 'capture_invalid_request_line' }
    $headerJSON = ConvertTo-Json -InputObject @($headers.ToArray()) -Depth 8 -Compress
    $envelope = [ordered]@{
        format_version=3; profile=$profile220; source_executable_sha256=$executable220SHA;
        test_mode=($env:RELAY_GATE_CAPTURE_TESTING -ceq '1'); source_version='2.1.220 (Claude Code)'; source='claude-code-isolated';
        protocol='anthropic'; endpoint='messages'; captured_at=$CapturedAt; completed_at=$CompletedAt; control_id=$Nonce; nonce=$Nonce; truncated=$false;
        isolation=[ordered]@{configuration=$true; mcp=$true; hooks=$true; plugins=$true; environment=$true; temporary_workdir=$true};
        method='POST'; request_target=$parts[1]; request_line=$Request.RequestLine; headers=@($headers.ToArray()); header_sha256=(Get-Control220Hash $headerJSON);
        body_base64=[Convert]::ToBase64String($Request.Body); body_sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Request.Body)).ToLowerInvariant();
        body_bytes=$Request.Body.Length; secret_scan_version='1'; authentication_verified=$true
    }
    return ,([Text.Encoding]::UTF8.GetBytes(($envelope | ConvertTo-Json -Depth 10 -Compress)))
}

function Invoke-Control220Capture {
    param([string]$Executable, [string]$VolumeRoot)
    $temporaryRoot = Join-Path $VolumeRoot ('relay-gate-control220-'+[guid]::NewGuid().ToString('N'))
    $listener = $null; $client = $null; $process = $null
    try {
        Assert-NoClaudeProjectConfigAncestors $VolumeRoot
        [void][IO.Directory]::CreateDirectory($temporaryRoot)
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $temporaryRoot '/inheritance:r' '/grant:r' "${identity}:(OI)(CI)F" '/Q' *> $null
        if ($LASTEXITCODE -ne 0) { throw 'capture_acl_failed' }
        foreach ($dir in @('cwd','home','config','appdata','localappdata','temp')) { [void][IO.Directory]::CreateDirectory((Join-Path $temporaryRoot $dir)) }
        $cwd = Join-Path $temporaryRoot 'cwd'; Assert-NoClaudeProjectConfigAncestors $cwd
        $nonce = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(12)).ToLowerInvariant()
        $derived = Get-Control220Identity $nonce
        New-PrivateCaptureFile (Join-Path $temporaryRoot 'config/.claude.json') ([Text.Encoding]::UTF8.GetBytes((@{userID=$derived.Device} | ConvertTo-Json -Compress)))
        $fakeKey = 'p0-fixture-'+[guid]::NewGuid().ToString('N')
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $listener.Start()
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $info = [Diagnostics.ProcessStartInfo]::new()
        $info.FileName=$Executable; $info.WorkingDirectory=$cwd; $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
        $info.Environment.Clear()
        foreach ($name in @('PATH','SYSTEMROOT','WINDIR','COMSPEC','PATHEXT')) {
            $value = [Environment]::GetEnvironmentVariable($name)
            if ($null -ne $value) { $info.Environment[$name]=$value }
        }
        foreach ($pair in @{
            HOME='home'; USERPROFILE='home'; APPDATA='appdata'; LOCALAPPDATA='localappdata'; TEMP='temp'; TMP='temp'; CLAUDE_CONFIG_DIR='config'
        }.GetEnumerator()) { $info.Environment[$pair.Key]=Join-Path $temporaryRoot $pair.Value }
        foreach ($pair in @{
            ANTHROPIC_BASE_URL="http://127.0.0.1:$port"; ANTHROPIC_API_KEY=$fakeKey;
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1'; DISABLE_AUTOUPDATER='1'; DISABLE_TELEMETRY='1'; DISABLE_ERROR_REPORTING='1';
            CLAUDE_CODE_MAX_OUTPUT_TOKENS='64'; MAX_THINKING_TOKENS='0'; ANTHROPIC_CUSTOM_HEADERS='Accept-Encoding: identity'
        }.GetEnumerator()) { $info.Environment[$pair.Key]=$pair.Value }
        foreach ($arg in @('--print','--bare','--safe-mode','--setting-sources','','--settings','{"alwaysThinkingEnabled":false}',
            '--strict-mcp-config','--mcp-config','{"mcpServers":{}}','--tools','','--system-prompt','Reply with 2 only.',
            '--no-chrome','--no-session-persistence','--disable-slash-commands','--output-format','json','--model','claude-opus-5',
            '--effort','low','--session-id',$derived.Session,'--max-budget-usd','.01',"1+1=? control:$nonce")) { $info.ArgumentList.Add($arg) }
        $accept = $listener.AcceptTcpClientAsync()
        $process = [Diagnostics.Process]::Start($info)
        $stdout = $process.StandardOutput.ReadToEndAsync(); $stderr = $process.StandardError.ReadToEndAsync()
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30); $hello = 0; $request = $null
        while ($null -eq $request) {
            $remaining = $deadline - [DateTimeOffset]::UtcNow
            if ($remaining -le [TimeSpan]::Zero -or -not $accept.Wait($remaining)) { throw 'capture_request_timeout' }
            $client=$accept.Result; $accept=$listener.AcceptTcpClientAsync(); $client.ReceiveTimeout=30000; $client.SendTimeout=30000
            $exchange = Read-ControlExchange $client.GetStream() $fakeKey $nonce
            if ($exchange.Kind -ceq 'hello') {
                if (++$hello -gt 3) { throw 'capture_unexpected_request_line' }
            } else {
                $request=$exchange; $capturedAt=[DateTimeOffset]::UtcNow.ToString('O')
                Write-ControlResponse $client.GetStream()
            }
            $client.Dispose(); $client=$null
        }
        if (-not $process.WaitForExit(30000)) { throw 'claude_process_timeout' }
        [void]$stdout.GetAwaiter().GetResult(); [void]$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'claude_process_failed' }
        return ,(ConvertTo-Control220Envelope $request $fakeKey $nonce $capturedAt ([DateTimeOffset]::UtcNow.ToString('O')))
    } finally {
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $listener) { $listener.Stop() }
        if ($null -ne $process) {
            if (-not $process.HasExited) { $process.Kill($true); if (-not $process.WaitForExit(5000)) { throw 'claude_process_did_not_stop' } }
            $process.Dispose()
        }
        if (Test-Path -LiteralPath $temporaryRoot) {
            $resolved = Get-NormalizedFullPath $temporaryRoot
            if ([IO.Path]::GetDirectoryName($resolved) -cne (Get-NormalizedFullPath $VolumeRoot) -or [IO.Path]::GetFileName($resolved) -cnotmatch '^relay-gate-control220-[a-f0-9]{32}$') { throw 'capture_cleanup_path_rejected' }
            # Only remove the newly created, private task directory on this volume.
            Assert-NoReparsePoint $resolved $VolumeRoot
            if (Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }) { throw 'capture_cleanup_reparse_rejected' }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}

function Invoke-Control220Main {
    if (-not $Execute) { Write-Output 'capture_not_started'; return }
    if (-not $IsWindows) { throw 'capture_platform_not_reviewed' }
    if ($Alias -cnotmatch '^[\p{L}\p{Nd}_.-]{1,64}$') { throw 'capture_manifest_arguments_invalid' }
    if (-not $AllowedRoot) { $AllowedRoot=Join-Path $RepositoryRoot '.local/p0/controls' }
    Initialize-Control220PrivateDirectory $RepositoryRoot $AllowedRoot
    $target=Resolve-CaptureTarget $RepositoryRoot $AllowedRoot $OutputPath
    $manifestTarget=Resolve-CaptureTarget $RepositoryRoot $AllowedRoot $ManifestPath
    if ([IO.Path]::GetDirectoryName($target) -cne [IO.Path]::GetDirectoryName($manifestTarget) -or $target -ceq $manifestTarget) { throw 'capture_manifest_must_be_distinct_and_adjacent' }
    $executable=Get-NormalizedFullPath $ClaudePath
    $handle=[IO.File]::Open($executable,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($handle)).ToLowerInvariant() -cne $executable220SHA) { throw 'capture_executable_not_reviewed' }
        [byte[]]$capture=Invoke-Control220Capture $executable ([IO.Path]::GetPathRoot((Get-NormalizedFullPath $RepositoryRoot)))
        $handle.Position=0
        if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($handle)).ToLowerInvariant() -cne $executable220SHA) { throw 'capture_executable_changed' }
    } finally { $handle.Dispose() }
    [byte[]]$manifest=ConvertTo-ControlManifest $capture $Alias ([IO.Path]::GetFileName($target)) -Profile $profile220
    $target=Resolve-CaptureTarget $RepositoryRoot $AllowedRoot $OutputPath
    $manifestTarget=Resolve-CaptureTarget $RepositoryRoot $AllowedRoot $ManifestPath
    New-PrivateCaptureFile $target $capture
    New-PrivateCaptureFile $manifestTarget $manifest
    Write-Output 'capture_completed'
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-Control220Main } catch {
        $code=$_.Exception.Message
        if ($code -cnotmatch '^[a-z0-9_]{1,80}$') { $code='capture_failed' }
        [Console]::Error.WriteLine($code)
        exit 1
    }
}
