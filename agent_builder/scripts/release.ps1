param(
    [string] $Version = '',
    [switch] $Development,
    [switch] $SkipPackagedExecutionCheck,
    [string] $ExpectedCommit = '',
    [string] $CertificateThumbprint = $env:FORGESEC_SIGN_CERT_SHA1,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$production = -not $Development
if ($production -and $SkipPackagedExecutionCheck) {
    throw 'Production releases cannot skip packaged executable checks.'
}
if ($production -and $ExpectedCommit -notmatch '^[0-9A-Fa-f]{40}$') {
    throw 'Production releases require -ExpectedCommit with the reviewed 40-character Git SHA.'
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
    if ($production) {
        & $python (Join-Path $script:RepoRoot 'scripts\check_release_baseline.py') --expected-commit $ExpectedCommit
        if ($LASTEXITCODE -ne 0) { throw 'Production source freeze check failed.' }
    }
    Install-AgentLockedDependencies $python
    & $python -m ruff check src tests
    if ($LASTEXITCODE -ne 0) { throw 'Agent lint failed.' }
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Agent tests failed.' }

    & (Join-Path $PSScriptRoot 'build-agent.ps1') -Version $Version -Sign:$production -SkipPackagedExecutionCheck:$SkipPackagedExecutionCheck -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    & (Join-Path $PSScriptRoot 'build-installer.ps1') -Version $Version -Production:$production -Sign:$production -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    & (Join-Path $PSScriptRoot 'test-installer.ps1') -Version $Version -RequireSigned:$production -SkipPackagedExecutionCheck:$SkipPackagedExecutionCheck

    $installer = Join-Path $script:BuilderRoot "dist\installer\ForgeSec-Network-Agent-Setup-$Version.exe"
    $signature = Get-AuthenticodeSignature -FilePath $installer
    $signerThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { $null }
    if ($production -and ($signature.Status -ne 'Valid' -or $signerThumbprint -ne $CertificateThumbprint.Replace(' ', '').ToUpperInvariant())) {
        throw 'Production installer signer does not match the approved certificate.'
    }
    $manifest = [ordered]@{
        schema_version = 1
        product = 'ForgeSec Network Agent'
        version = $Version
        channel = if ($production) { 'production' } else { 'development' }
        file = Split-Path $installer -Leaf
        size_bytes = (Get-Item -LiteralPath $installer).Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
        signed = $signature.Status -eq 'Valid'
        source_commit = if ($production) { $ExpectedCommit.ToLowerInvariant() } else { $null }
        signer_thumbprint = $signerThumbprint
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
