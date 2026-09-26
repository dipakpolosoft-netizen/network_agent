param(
    [string] $Version = '',
    [switch] $Development,
    [switch] $SkipPackagedExecutionCheck,
    [string] $CertificateThumbprint = $env:FORGESEC_SIGN_CERT_SHA1,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$production = -not $Development
if ($production -and $SkipPackagedExecutionCheck) {
    throw 'Production releases cannot skip packaged executable checks.'
}

$oemHash = $null
if ($production) {
    $prerequisites = Get-ProductionPackagePrerequisites $CertificateThumbprint
    if ($prerequisites.Issues.Count) {
        throw "Production release prerequisites:`n - $($prerequisites.Issues -join "`n - ")"
    }
    $oemHash = $prerequisites.OemHash
} else {
    Find-Iscc | Out-Null
}

$python = Join-Path $script:BuilderRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    py -3.12 -m venv (Join-Path $script:BuilderRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Unable to create the agent build environment.' }
}
Push-Location $script:BuilderRoot
try {
    Install-AgentLockedDependencies $python
    & $python -m ruff check src tests
    if ($LASTEXITCODE -ne 0) { throw 'Agent lint failed.' }
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Agent tests failed.' }

    & (Join-Path $PSScriptRoot 'build-agent.ps1') -Version $Version -Sign:$production -SkipPackagedExecutionCheck:$SkipPackagedExecutionCheck -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    & (Join-Path $PSScriptRoot 'build-installer.ps1') -Version $Version -Production:$production -Sign:$production -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    & (Join-Path $PSScriptRoot 'test-installer.ps1') -Version $Version -RequireSigned:$production -SkipPackagedExecutionCheck:$SkipPackagedExecutionCheck

    $installer = Join-Path $script:BuilderRoot "dist\installer\ForgeSec-Network-Agent-Setup-$Version.exe"
    $manifest = [ordered]@{
        schema_version = 1
        product = 'ForgeSec Network Agent'
        version = $Version
        channel = if ($production) { 'production' } else { 'development' }
        file = Split-Path $installer -Leaf
        size_bytes = (Get-Item -LiteralPath $installer).Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
        signed = (Get-AuthenticodeSignature -FilePath $installer).Status -eq 'Valid'
        includes_licensed_scanner = $production
        nmap_oem_sha256 = $oemHash
        created_at = [DateTime]::UtcNow.ToString('o')
    }
    $manifestPath = Join-Path $script:BuilderRoot 'dist\installer\release-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    & (Join-Path $PSScriptRoot 'publish-to-web.ps1') -Version $Version -RequireSigned:$production
    Write-Host "ForgeSec Network Agent $Version release completed."
}
finally {
    Pop-Location
}
