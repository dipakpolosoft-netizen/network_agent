param(
    [string] $Version = '',
    [switch] $RequireSigned,
    [switch] $SkipPackagedExecutionCheck,
    [switch] $Install,
    [string] $ServerUrl,
    [string] $EnrollmentToken
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$agent = Join-Path $script:BuilderRoot 'dist\agent\TelesecAgent.exe'
$tray = Join-Path $script:BuilderRoot 'dist\agent\TelesecTray.exe'
$installer = Join-Path $script:BuilderRoot "dist\installer\Telesec-Network-Agent-Setup-$Version.exe"
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
    $process = Start-Process -FilePath $installer -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART',
        "/SERVERURL=$ServerUrl", "/ENROLLMENTTOKEN=$EnrollmentToken"
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "Installer exited with code $($process.ExitCode)." }
    $service = Get-Service -Name 'TelesecNetworkAgent' -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'Telesec service is not running after installation.' }
}

Write-Host "Installer package checks passed for version $Version."
