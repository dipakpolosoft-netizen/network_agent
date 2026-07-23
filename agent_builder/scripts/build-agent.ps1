param(
    [string] $Version = '',
    [switch] $Sign,
    [switch] $SkipPackagedExecutionCheck,
    [string] $CertificateThumbprint = $env:TELESEC_SIGN_CERT_SHA1,
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
    & $python -c "import PyInstaller, telesec_agent"
    if ($LASTEXITCODE -ne 0) {
        & $python -m pip install --disable-pip-version-check -e '.[build]'
        if ($LASTEXITCODE -ne 0) { throw 'Unable to install the agent build environment.' }
    }

    Reset-BuilderDirectory (Join-Path $script:BuilderRoot 'build\pyinstaller')
    Reset-BuilderDirectory (Join-Path $script:BuilderRoot 'dist\agent')
    & $python -m PyInstaller --noconfirm --clean `
        --distpath (Join-Path $script:BuilderRoot 'dist\agent') `
        --workpath (Join-Path $script:BuilderRoot 'build\pyinstaller') `
        (Join-Path $script:BuilderRoot 'pyinstaller\TelesecAgent.spec')
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }

    $agent = Join-Path $script:BuilderRoot 'dist\agent\TelesecAgent.exe'
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw 'Agent executable was not produced.' }
    $tray = Join-Path $script:BuilderRoot 'dist\agent\TelesecTray.exe'
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
    Write-Host "Built TelesecAgent.exe and TelesecTray.exe $Version (agent SHA256 $hash)"
}
finally {
    Pop-Location
}
