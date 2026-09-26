param(
    [string] $Version = '',
    [switch] $Sign,
    [switch] $SkipPackagedExecutionCheck,
    [string] $CertificateThumbprint = $env:FORGESEC_SIGN_CERT_SHA1,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

. (Join-Path $PSScriptRoot '_common.ps1')

$sourceVersion = Get-AgentVersion
if (-not $Version) { $Version = $sourceVersion }
if ($Version -ne $sourceVersion) {
    throw "Requested version $Version does not match source version $sourceVersion."
}

$python = Join-Path $script:BuilderRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    py -3.12 -m venv (Join-Path $script:BuilderRoot '.venv')
}

Push-Location $script:BuilderRoot
try {
    Install-AgentLockedDependencies $python

    Reset-BuilderDirectory (Join-Path $script:BuilderRoot 'build\pyinstaller')
    Reset-BuilderDirectory (Join-Path $script:BuilderRoot 'dist\agent')
    & $python -m PyInstaller --noconfirm --clean `
        --distpath (Join-Path $script:BuilderRoot 'dist\agent') `
        --workpath (Join-Path $script:BuilderRoot 'build\pyinstaller') `
        (Join-Path $script:BuilderRoot 'pyinstaller\ForgeSecAgent.spec')
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }

    $agent = Join-Path $script:BuilderRoot 'dist\agent\ForgeSecAgent.exe'
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw 'Agent executable was not produced.' }
    $tray = Join-Path $script:BuilderRoot 'dist\agent\ForgeSecTray.exe'
    if (-not (Test-Path -LiteralPath $tray -PathType Leaf)) { throw 'Tray executable was not produced.' }
    if (-not $SkipPackagedExecutionCheck) {
        $reportedVersion = (& $agent --version).Trim()
        if ($LASTEXITCODE -ne 0 -or $reportedVersion -ne $Version) {
            throw "Packaged agent version check failed: $reportedVersion"
        }
    }
    if ($Sign) {
        Invoke-SignArtifact -Path $agent -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
        Invoke-SignArtifact -Path $tray -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $agent).Hash
    Write-Host "Built ForgeSecAgent.exe and ForgeSecTray.exe $Version (agent SHA256 $hash)"
}
finally {
    Pop-Location
}
