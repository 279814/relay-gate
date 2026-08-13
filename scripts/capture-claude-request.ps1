#Requires -Version 7.2

[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [string]$AllowedRoot,
    [string]$OutputPath,
    [switch]$ValidateIsolationOnly,
    [switch]$ValidateTargetOnly,
    [switch]$ReservePrivateOutput,
    [switch]$Execute,
    [string]$ClaudePath = "claude",
    [string]$ExpectedClaudeVersion = "2.1.220",
    [string]$Model = "claude-opus-5"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-NormalizedFullPath {
    param([Parameter(Mandatory)][string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    $comparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    if ($fullPath.Equals($root, $comparison)) {
        return $root
    }
    return $fullPath.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root
    )
    $comparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    $rootPrefix = $Root + [System.IO.Path]::DirectorySeparatorChar
    return $Path.Equals($Root, $comparison) -or $Path.StartsWith($rootPrefix, $comparison)
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory)][string]$StartPath,
        [Parameter(Mandatory)][string]$StopPath
    )
    $current = Get-NormalizedFullPath $StartPath
    $stop = Get-NormalizedFullPath $StopPath
    while ($true) {
        if (-not (Test-Path -LiteralPath $current)) {
            throw "capture_parent_missing"
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "capture_reparse_point_rejected"
        }
        if ($current -eq $stop) {
            return
        }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            throw "capture_root_not_reached"
        }
        $current = Get-NormalizedFullPath $parent
    }
}

function Assert-DirectoryCreationPathSafe {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][string]$Repository
    )
    $repositoryPath = Get-NormalizedFullPath $Repository
    $current = Get-NormalizedFullPath $Directory
    if (-not (Test-PathWithinRoot -Path $current -Root $repositoryPath)) {
        throw "capture_directory_outside_repository"
    }
    while (-not (Test-Path -LiteralPath $current)) {
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            throw "capture_existing_ancestor_not_found"
        }
        $current = Get-NormalizedFullPath $parent
    }
    Assert-NoReparsePoint -StartPath $current -StopPath $repositoryPath
}

function Assert-NoClaudeProjectConfigAncestors {
    param([Parameter(Mandatory)][string]$WorkingDirectory)
    $current = Get-NormalizedFullPath $WorkingDirectory
    $homePath = $null
    $homeVariable = Get-Variable HOME -ErrorAction SilentlyContinue
    if ($null -ne $homeVariable -and -not [string]::IsNullOrWhiteSpace([string]$homeVariable.Value)) {
        $homePath = Get-NormalizedFullPath ([string]$homeVariable.Value)
    }
    while ($true) {
        if ($null -ne $homePath -and $current.Equals($homePath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
        foreach ($name in @('CLAUDE.md', 'CLAUDE.local.md', '.mcp.json', '.claude')) {
            if (Test-Path -LiteralPath (Join-Path $current $name)) {
                throw "claude_project_config_in_ancestor"
            }
        }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            return
        }
        $current = Get-NormalizedFullPath $parent
    }
}

function Assert-DockerIgnoredPrivatePath {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$RelativePath
    )
    $normalized = $RelativePath.Replace('\', '/')
    if (-not $normalized.StartsWith('.local/p0/', [System.StringComparison]::Ordinal)) {
        throw "capture_not_under_private_context_root"
    }
    $dockerIgnore = Join-Path $Repository ".dockerignore"
    if (-not (Test-Path -LiteralPath $dockerIgnore -PathType Leaf)) {
        throw "dockerignore_missing"
    }
    $dockerRules = Get-Content -LiteralPath $dockerIgnore
    $hasPrivateRule = $dockerRules | Where-Object {
        $_.Trim() -eq '.local/p0/'
    }
    if (-not $hasPrivateRule) {
        throw "dockerignore_private_rule_missing"
    }
    if ($dockerRules | Where-Object { $_.TrimStart().StartsWith('!') }) {
        throw "dockerignore_negation_requires_review"
    }
}

function Resolve-CaptureTarget {
    param(
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Allowed,
        [Parameter(Mandatory)][string]$Target
    )
    $repositoryPath = Get-NormalizedFullPath $Repository
    $allowedPath = Get-NormalizedFullPath $Allowed
    $targetPath = Get-NormalizedFullPath $Target

    if (-not (Test-Path -LiteralPath $repositoryPath -PathType Container)) {
        throw "repository_root_missing"
    }
    if (-not (Test-Path -LiteralPath $allowedPath -PathType Container)) {
        throw "capture_allowed_root_missing"
    }
    if (-not (Test-PathWithinRoot -Path $allowedPath -Root $repositoryPath)) {
        throw "capture_allowed_root_outside_repository"
    }
    if (-not (Test-PathWithinRoot -Path $targetPath -Root $allowedPath)) {
        throw "capture_target_outside_allowed_root"
    }

    $relativePath = [System.IO.Path]::GetRelativePath($repositoryPath, $targetPath).Replace('\', '/')
    & git -C $repositoryPath ls-files --error-unmatch -- $relativePath *> $null
    if ($LASTEXITCODE -eq 0) {
        throw "capture_target_is_tracked"
    }
    if (Test-Path -LiteralPath $targetPath) {
        throw "capture_target_exists"
    }

    $targetParent = [System.IO.Path]::GetDirectoryName($targetPath)
    Assert-NoReparsePoint -StartPath $targetParent -StopPath $repositoryPath

    & git -C $repositoryPath check-ignore --quiet -- $relativePath
    if ($LASTEXITCODE -ne 0) {
        throw "capture_target_not_git_ignored"
    }
    Assert-DockerIgnoredPrivatePath -Repository $repositoryPath -RelativePath $relativePath
    return $targetPath
}

function Set-PrivateFilePermissions {
    param([Parameter(Mandatory)][string]$Path)
    if ($env:RELAY_GATE_CAPTURE_TEST_FAIL_PERMISSIONS) {
        if ($env:RELAY_GATE_CAPTURE_TESTING -cne '1') {
            throw "capture_test_permission_override_rejected"
        }
        throw "capture_test_permission_failure"
    }
    if ($IsWindows) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        & icacls.exe $Path '/inheritance:r' '/grant:r' "${identity}:(F)" '/Q' *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "capture_acl_failed"
        }
        return
    }
    [System.IO.File]::SetUnixFileMode($Path, [System.IO.UnixFileMode]384)
}

function New-PrivateCaptureFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [byte[]]$Content = [byte[]]::new(0)
    )
    $stream = $null
    $created = $false
    try {
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $created = $true
        Set-PrivateFilePermissions -Path $Path
        if ($Content.Length -gt 0) {
            $stream.Write($Content, 0, $Content.Length)
            $stream.Flush($true)
        }
    } catch {
        $failure = $_
        if ($null -ne $stream) {
            $stream.Dispose()
            $stream = $null
        }
        if ($created) {
            try {
                [System.IO.File]::Delete($Path)
            } catch {
                throw "capture_failed_file_cleanup_failed"
            }
        }
        throw $failure
    } finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-SHA256Text {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))
}

function Get-UserStateFingerprint {
    $records = [System.Collections.Generic.List[string]]::new()
    if ($env:RELAY_GATE_CAPTURE_TEST_STATE_ROOT) {
        if ($env:RELAY_GATE_CAPTURE_TESTING -cne '1') {
            throw "capture_test_state_override_rejected"
        }
        $testRoot = Get-NormalizedFullPath $env:RELAY_GATE_CAPTURE_TEST_STATE_ROOT
        $tempRoot = Get-NormalizedFullPath ([System.IO.Path]::GetTempPath())
        if (-not (Test-PathWithinRoot -Path $testRoot -Root $tempRoot)) {
            throw "capture_test_state_root_outside_temp"
        }
        Assert-NoReparsePoint -StartPath $testRoot -StopPath $tempRoot
        $roots = @($testRoot)
    } else {
        $roots = @(
            (Join-Path $HOME '.claude'),
            (Join-Path $HOME '.cc-switch')
        )
        if ($env:APPDATA) {
            $roots += Join-Path $env:APPDATA 'Claude'
            $roots += Join-Path $env:APPDATA 'CCSwitch'
        }
        if ($env:LOCALAPPDATA) {
            $roots += Join-Path $env:LOCALAPPDATA 'Claude'
            $roots += Join-Path $env:LOCALAPPDATA 'CCSwitch'
        }
    }
    $roots = $roots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

    foreach ($root in $roots) {
        $records.Add("root|$(Get-SHA256Text $root)|$(Test-Path -LiteralPath $root)")
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        try {
            $rootItem = Get-Item -LiteralPath $root -Force
            if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "capture_state_root_is_reparse_point"
            }
            $items = Get-ChildItem -LiteralPath $root -Force -Recurse | Sort-Object FullName
            foreach ($item in $items) {
                $relative = [System.IO.Path]::GetRelativePath($root, $item.FullName)
                $pathHash = Get-SHA256Text $relative
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    $records.Add("link|$pathHash|$(Get-SHA256Text ([string]$item.LinkTarget))")
                } elseif ($item.PSIsContainer) {
                    $records.Add("dir|$pathHash")
                } else {
                    $contentHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
                    $records.Add("file|$pathHash|$($item.Length)|$contentHash")
                }
            }
        } catch {
            if (($_.Exception.HResult -band 0xFFFF) -eq 32) {
                throw "capture_state_not_quiescent"
            }
            throw "capture_state_snapshot_failed"
        }
    }

    $userEnvironment = [System.Environment]::GetEnvironmentVariables(
        [System.EnvironmentVariableTarget]::User
    )
    foreach ($name in @($userEnvironment.Keys) | Sort-Object) {
        $records.Add("env|$(Get-SHA256Text ([string]$name))|$(Get-SHA256Text ([string]$userEnvironment[$name]))")
    }

    if ($IsWindows) {
        foreach ($registryPath in @(
            'HKCU\Environment',
            'HKCU\Software\Anthropic',
            'HKCU\Software\Claude',
            'HKCU\Software\CCSwitch'
        )) {
            $registryOutput = (& reg.exe query $registryPath /s 2>$null | Out-String)
            $records.Add("registry|$(Get-SHA256Text $registryPath)|$(Get-SHA256Text $registryOutput)")
        }
    }
    return Get-SHA256Text ($records -join "`n")
}

function Assert-ClaudeIsolationCapabilities {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$ExpectedVersion
    )
    $version = (& $Executable --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $version.StartsWith("$ExpectedVersion ")) {
        throw "claude_version_not_reviewed"
    }
    $help = (& $Executable --help 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "claude_help_unavailable"
    }
    $normalizedHelp = [System.Text.RegularExpressions.Regex]::Replace($help, '\s+', ' ')
    foreach ($required in @(
        '--bare',
        '--safe-mode',
        '--strict-mcp-config',
        '--settings',
        '--no-session-persistence',
        '--disable-slash-commands',
        '--tools',
        '--no-chrome',
        '--max-budget-usd'
    )) {
        if (-not $normalizedHelp.Contains($required, [System.StringComparison]::Ordinal)) {
            throw "claude_isolation_flag_missing"
        }
    }
    foreach ($bareCapability in @(
        'hooks',
        'LSP',
        'plugin sync',
        'attribution',
        'auto-memory',
        'background prefetches',
        'keychain reads',
        'CLAUDE.md auto-discovery'
    )) {
        if (-not $normalizedHelp.Contains($bareCapability, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "claude_bare_capability_unproven"
        }
    }
    return [ordered]@{ Version = $version; Executable = (Get-Command $Executable).Source }
}

function Find-HeaderTerminator {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    for ($index = 0; $index -le $Bytes.Length - 4; $index++) {
        if ($Bytes[$index] -eq 13 -and $Bytes[$index + 1] -eq 10 -and
            $Bytes[$index + 2] -eq 13 -and $Bytes[$index + 3] -eq 10) {
            return $index
        }
    }
    return -1
}

function Read-ControlRequest {
    param(
        [Parameter(Mandatory)][System.Net.Sockets.NetworkStream]$Stream,
        [Parameter(Mandatory)][string]$FakeKey,
        [Parameter(Mandatory)][string]$Nonce
    )
    $memory = [System.IO.MemoryStream]::new()
    $buffer = [byte[]]::new(4096)
    $headerIndex = -1
    while ($headerIndex -lt 0) {
        $read = $Stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) {
            throw "capture_request_eof_before_headers"
        }
        $memory.Write($buffer, 0, $read)
        if ($memory.Length -gt 65536) {
            throw "capture_request_headers_too_large"
        }
        $headerIndex = Find-HeaderTerminator -Bytes $memory.ToArray()
    }

    $received = $memory.ToArray()
    $headerBytes = $received[0..($headerIndex - 1)]
    $headerText = [System.Text.Encoding]::ASCII.GetString($headerBytes)
    $lines = $headerText -split "`r`n"
    if ($lines.Count -lt 1 -or -not $lines[0].StartsWith('POST /v1/messages ', [System.StringComparison]::Ordinal)) {
        throw "capture_unexpected_request_line"
    }
    $headers = [ordered]@{}
    foreach ($line in $lines[1..($lines.Count - 1)]) {
        $separator = $line.IndexOf(':')
        if ($separator -le 0) {
            throw "capture_malformed_header"
        }
        $name = $line.Substring(0, $separator).Trim().ToLowerInvariant()
        $value = $line.Substring($separator + 1).Trim()
        if ($headers.Contains($name)) {
            $headers[$name] = @($headers[$name]) + @($value)
        } else {
            $headers[$name] = @($value)
        }
    }
    if (-not $headers.Contains('content-length')) {
        throw "capture_content_length_required"
    }
    $contentLength = 0
    if (-not [int]::TryParse($headers['content-length'][0], [ref]$contentLength) -or
        $contentLength -lt 1 -or $contentLength -gt 2097152) {
        throw "capture_content_length_invalid"
    }
    if (-not $headers.Contains('x-api-key') -or $headers['x-api-key'].Count -ne 1 -or
        $headers['x-api-key'][0] -cne $FakeKey) {
        throw "capture_fake_auth_mismatch"
    }
    if ($headers.Contains('authorization')) {
        if ($headers['authorization'].Count -ne 1 -or
            $headers['authorization'][0] -cne "Bearer $FakeKey") {
            throw "capture_fake_auth_mismatch"
        }
    }

    $bodyOffset = $headerIndex + 4
    $body = [System.IO.MemoryStream]::new()
    if ($received.Length -gt $bodyOffset) {
        $available = [Math]::Min($received.Length - $bodyOffset, $contentLength)
        $body.Write($received, $bodyOffset, $available)
    }
    while ($body.Length -lt $contentLength) {
        $remaining = $contentLength - [int]$body.Length
        $read = $Stream.Read($buffer, 0, [Math]::Min($buffer.Length, $remaining))
        if ($read -le 0) {
            throw "capture_request_eof_before_body"
        }
        $body.Write($buffer, 0, $read)
    }
    $bodyBytes = $body.ToArray()
    $bodyText = [System.Text.Encoding]::UTF8.GetString($bodyBytes)
    if (-not $bodyText.Contains("control:$Nonce", [System.StringComparison]::Ordinal)) {
        throw "capture_control_nonce_missing"
    }
    return [ordered]@{
        RequestLine = $lines[0]
        Headers = $headers
        Body = $bodyBytes
    }
}

function Write-ControlResponse {
    param([Parameter(Mandatory)][System.Net.Sockets.NetworkStream]$Stream)
    $body = @'
event: message_start
data: {"type":"message_start","message":{"id":"msg_fixture","type":"message","role":"assistant","model":"fixture","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"2"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}

event: message_stop
data: {"type":"message_stop"}

'@
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $head = "HTTP/1.1 200 OK`r`nContent-Type: text/event-stream`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
    $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
    $Stream.Write($headBytes, 0, $headBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

function Start-IsolatedClaudeProcess {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$ConfigDirectory,
        [Parameter(Mandatory)][string]$SettingsPath,
        [Parameter(Mandatory)][string]$MCPPath,
        [Parameter(Mandatory)][string]$BaseURL,
        [Parameter(Mandatory)][string]$FakeKey,
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][string]$SelectedModel
    )
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.WorkingDirectory = $WorkingDirectory
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true

    foreach ($name in @($info.Environment.Keys)) {
        if ($name -match '^(?i:ANTHROPIC|OPENAI|CLAUDE|CODEX|CCSWITCH|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|AWS_|AZURE_|GOOGLE_|VERTEX)') {
            [void]$info.Environment.Remove($name)
        }
    }
    $info.Environment['ANTHROPIC_API_KEY'] = $FakeKey
    $info.Environment['ANTHROPIC_BASE_URL'] = $BaseURL
    $info.Environment['CLAUDE_CONFIG_DIR'] = $ConfigDirectory
    $info.Environment['CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'] = '1'
    $info.Environment['DISABLE_AUTOUPDATER'] = '1'
    $info.Environment['DISABLE_TELEMETRY'] = '1'
    $info.Environment['DISABLE_ERROR_REPORTING'] = '1'
    $info.Environment['DISABLE_BUG_COMMAND'] = '1'

    foreach ($argument in @(
        '--print',
        '--bare',
        '--safe-mode',
        '--no-session-persistence',
        '--strict-mcp-config',
        '--mcp-config', $MCPPath,
        '--settings', $SettingsPath,
        '--tools', '',
        '--disable-slash-commands',
        '--no-chrome',
        '--output-format', 'json',
        '--model', $SelectedModel,
        '--max-budget-usd', '0.01',
        $Prompt
    )) {
        $info.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) {
        throw "claude_process_start_failed"
    }
    return $process
}

function Invoke-ControlCapture {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Claude,
        [Parameter(Mandatory)][string]$SelectedModel
    )
    if (-not $IsWindows) {
        throw "capture_platform_not_reviewed"
    }
    $before = Get-UserStateFingerprint
    $temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("relay-gate-capture-" + [guid]::NewGuid().ToString('N'))
    $listener = $null
    $client = $null
    $process = $null
    $operationError = $null
    $cleanupError = $null
    $request = $null
    $nonce = $null
    try {
        $workingDirectory = Join-Path $temporaryRoot 'cwd'
        $configDirectory = Join-Path $temporaryRoot 'config'
        [System.IO.Directory]::CreateDirectory($workingDirectory) | Out-Null
        [System.IO.Directory]::CreateDirectory($configDirectory) | Out-Null
        Assert-NoClaudeProjectConfigAncestors -WorkingDirectory $workingDirectory
        $settingsPath = Join-Path $temporaryRoot 'settings.json'
        $mcpPath = Join-Path $temporaryRoot 'mcp.json'
        [System.IO.File]::WriteAllText($settingsPath, '{}', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($mcpPath, '{"mcpServers":{}}', [System.Text.UTF8Encoding]::new($false))

        $nonce = [System.Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(8)).ToLowerInvariant()
        $fakeKey = 'p0-fixture-' + [guid]::NewGuid().ToString('N')
        $prompt = "1+1=? control:$nonce"
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $accept = $listener.AcceptTcpClientAsync()
        $process = Start-IsolatedClaudeProcess `
            -Executable $Claude.Executable `
            -WorkingDirectory $workingDirectory `
            -ConfigDirectory $configDirectory `
            -SettingsPath $settingsPath `
            -MCPPath $mcpPath `
            -BaseURL "http://127.0.0.1:$port" `
            -FakeKey $fakeKey `
            -Prompt $prompt `
            -SelectedModel $SelectedModel

        if (-not $accept.Wait([TimeSpan]::FromSeconds(30))) {
            throw "capture_request_timeout"
        }
        $client = $accept.Result
        $client.ReceiveTimeout = 30000
        $client.SendTimeout = 30000
        $stream = $client.GetStream()
        $request = Read-ControlRequest -Stream $stream -FakeKey $fakeKey -Nonce $nonce
        Write-ControlResponse -Stream $stream
        $client.Close()
        $client = $null

        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            throw "claude_process_timeout"
        }
        [void]$process.StandardOutput.ReadToEnd()
        [void]$process.StandardError.ReadToEnd()
        if ($process.ExitCode -ne 0) {
            throw "claude_process_failed"
        }
    } catch {
        $operationError = $_
    } finally {
        try {
            if ($null -ne $client) {
                $client.Dispose()
            }
            if ($null -ne $listener) {
                $listener.Stop()
            }
            if ($null -ne $process -and -not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) {
                    throw "claude_process_did_not_stop"
                }
            }
            if (Test-Path -LiteralPath $temporaryRoot) {
                $normalizedTemp = Get-NormalizedFullPath ([System.IO.Path]::GetTempPath())
                $normalizedWork = Get-NormalizedFullPath $temporaryRoot
                if ((Test-PathWithinRoot -Path $normalizedWork -Root $normalizedTemp) -and
                    ([System.IO.Path]::GetFileName($normalizedWork)).StartsWith('relay-gate-capture-', [System.StringComparison]::Ordinal)) {
                    [System.IO.Directory]::Delete($normalizedWork, $true)
                }
            }
        } catch {
            $cleanupError = $_
        }
    }

    $after = Get-UserStateFingerprint
    if ($before -cne $after) {
        throw "claude_or_ccswitch_state_changed"
    }
    if ($null -ne $operationError) {
        throw $operationError
    }
    if ($null -ne $cleanupError) {
        throw $cleanupError
    }

    $capture = [ordered]@{
        format_version = 1
        test_mode = ($env:RELAY_GATE_CAPTURE_TESTING -ceq '1')
        claude_version = $Claude.Version
        captured_at_utc = [DateTimeOffset]::UtcNow.ToString('O')
        control_id = $nonce
        request_line = $request.RequestLine
        headers = $request.Headers
        body_base64 = [System.Convert]::ToBase64String($request.Body)
        authentication_verified = $true
    }
    $json = $capture | ConvertTo-Json -Depth 8 -Compress
    return ,([System.Text.UTF8Encoding]::new($false).GetBytes($json))
}

function Invoke-Main {
    $modeCount = @($ValidateIsolationOnly, $ValidateTargetOnly, $ReservePrivateOutput, $Execute).Where({ $_ }).Count
    if ($modeCount -eq 0) {
        Write-Output "capture_not_started"
        return
    }
    if ($modeCount -ne 1) {
        throw "capture_mode_conflict"
    }
    if ($ValidateIsolationOnly) {
        [void](Assert-ClaudeIsolationCapabilities -Executable $ClaudePath -ExpectedVersion $ExpectedClaudeVersion)
        Write-Output "claude_isolation_valid"
        return
    }
    if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
        $RepositoryRoot = [System.IO.Path]::GetDirectoryName($PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($AllowedRoot)) {
        $AllowedRoot = Join-Path $RepositoryRoot '.local/p0/captures'
    }
    if (-not (Test-Path -LiteralPath $AllowedRoot) -and ($ReservePrivateOutput -or $Execute)) {
        $repositoryPath = Get-NormalizedFullPath $RepositoryRoot
        $allowedPath = Get-NormalizedFullPath $AllowedRoot
        Assert-DirectoryCreationPathSafe -Directory $allowedPath -Repository $repositoryPath
        [System.IO.Directory]::CreateDirectory($allowedPath) | Out-Null
    }
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        if ($ValidateTargetOnly -or $ReservePrivateOutput) {
            throw "capture_output_required"
        }
        $name = 'claude-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' +
            [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json'
        $OutputPath = Join-Path $AllowedRoot $name
    }

    $target = Resolve-CaptureTarget -Repository $RepositoryRoot -Allowed $AllowedRoot -Target $OutputPath
    if ($ValidateTargetOnly) {
        Write-Output "capture_target_valid"
        return
    }
    if ($ReservePrivateOutput) {
        New-PrivateCaptureFile -Path $target
        Write-Output "capture_reserved"
        return
    }

    $claude = Assert-ClaudeIsolationCapabilities -Executable $ClaudePath -ExpectedVersion $ExpectedClaudeVersion
    [byte[]]$captureContent = Invoke-ControlCapture -Target $target -Claude $claude -SelectedModel $Model
    $target = Resolve-CaptureTarget -Repository $RepositoryRoot -Allowed $AllowedRoot -Target $OutputPath
    New-PrivateCaptureFile -Path $target -Content $captureContent
    Write-Output "capture_completed"
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-Main
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
