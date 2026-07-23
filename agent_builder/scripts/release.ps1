param(
    [string] $Version = '',
    [switch] $Development,
    [switch] $SkipPackagedExecutionCheck,
    [string] $CertificateThumbprint = $env:TELESEC_SIGN_CERT_SHA1,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$production = -not $Development
if ($production -and -not $CertificateThumbprint) {
    throw 'Production releases require TELESEC_SIGN_CERT_SHA1 or CertificateThumbprint.'
}
if ($production -and $SkipPackagedExecutionCheck) {
    throw 'Production releases cannot skip packaged executable checks.'
}

$python = Join-Path $script:BuilderRoot '.venv\Scripts\python.exe'
Push-Location $script:BuilderRoot
try {
    & $python -m ruff check src tests
    if ($LASTEXITCODE -ne 0) { throw 'Agent lint failed.' }
    & $python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw 'Agent tests failed.' }

    & (Join-Path $PSScriptRoot 'build-agent.ps1') -Version $Version -Sign:$production -SkipPackagedExecutionCheck:$SkipPackagedExecutionCheck -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    & (Join-Path $PSScriptRoot 'build-installer.ps1') -Version $Version -Production:$production -Sign:$production -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
    & (Join-Path $PSScriptRoot 'test-installer.ps1') -Version $Version -RequireSigned:$production -SkipPackagedExecutionCheck:$SkipPackagedExecutionCheck
    & (Join-Path $PSScriptRoot 'publish-to-web.ps1') -Version $Version -RequireSigned:$production

    $installer = Join-Path $script:BuilderRoot "dist\installer\Telesec-Network-Agent-Setup-$Version.exe"
    $manifest = [ordered]@{
        product = 'Telesec Network Agent'
        version = $Version
        channel = if ($production) { 'production' } else { 'development' }
        file = Split-Path $installer -Leaf
        size_bytes = (Get-Item -LiteralPath $installer).Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
        signed = (Get-AuthenticodeSignature -FilePath $installer).Status -eq 'Valid'
        created_at = [DateTime]::UtcNow.ToString('o')
    }
    $manifest | ConvertTo-Json | Set-Content -Path (Join-Path $script:BuilderRoot 'dist\installer\release-manifest.json') -Encoding utf8
    Write-Host "Telesec Network Agent $Version release completed."
}
finally {
    Pop-Location
}
