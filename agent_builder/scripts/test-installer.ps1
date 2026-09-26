param(
    [string] $Version = '',
    [switch] $RequireSigned,
    [switch] $SkipPackagedExecutionCheck,
    [switch] $Install,
    [string] $InstallerPath = '',
    [string] $ServerUrl,
    [string] $EnrollmentToken
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$agent = Join-Path $script:BuilderRoot 'dist\agent\ForgeSecAgent.exe'
$tray = Join-Path $script:BuilderRoot 'dist\agent\ForgeSecTray.exe'
$installer = if ($InstallerPath) { [IO.Path]::GetFullPath($InstallerPath) } else { Join-Path $script:BuilderRoot "dist\installer\ForgeSec-Network-Agent-Setup-$Version.exe" }
foreach ($artifact in @($agent, $tray, $installer)) {
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw "Missing build artifact: $artifact" }
    if ((Get-Item -LiteralPath $artifact).Length -lt 100KB) { throw "Artifact is unexpectedly small: $artifact" }
    if ($RequireSigned -and (Get-AuthenticodeSignature -FilePath $artifact).Status -ne 'Valid') {
        throw "Artifact is not validly signed: $artifact"
    }
}

if (-not $SkipPackagedExecutionCheck) {
    $reportedVersion = (& $agent --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $reportedVersion -ne $Version) { throw 'Packaged agent version check failed.' }
    & $agent doctor | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Packaged agent diagnostics failed.' }
}

if ($Install) {
    if (-not $ServerUrl -or -not $EnrollmentToken) {
        throw 'ServerUrl and EnrollmentToken are required for an installation test.'
    }
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run the installation pilot from an elevated PowerShell session.'
    }
    $installStartedAt = [DateTime]::UtcNow
    $process = Start-Process -FilePath $installer -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        "/SERVERURL=$ServerUrl", "/ENROLLMENTTOKEN=$EnrollmentToken"
    ) -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)." }
    $service = Get-Service -Name 'ForgeSecNetworkAgent' -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'ForgeSec service is not running after installation.' }
    $diagnostic = (& $agent doctor | Out-String | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Installed agent diagnostics failed.' }
    if ($RequireSigned -and $diagnostic.status -ne 'ready') {
        throw 'Production install did not leave Nmap, Npcap, and local data ready.'
    }
    $statusPath = Join-Path $env:ProgramData 'ForgeSec\NetworkAgent\public\status.json'
    $status = $null
    for ($attempt = 0; $attempt -lt 90; $attempt++) {
        if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
            try {
                $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
                $heartbeatAt = [DateTime]::Parse($status.last_heartbeat_at).ToUniversalTime()
                if ($status.status -eq 'online' -and $heartbeatAt -ge $installStartedAt.AddSeconds(-5)) { break }
            } catch { $status = $null }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $status -or $status.status -ne 'online' -or $heartbeatAt -lt $installStartedAt.AddSeconds(-5)) {
        throw 'No fresh authenticated heartbeat appeared after installation. Check the agent log and server enrollment status.'
    }
    Write-Host "Installed service and authenticated heartbeat verified at $($status.last_heartbeat_at)."
}

Write-Host "Installer package checks passed for version $Version."
