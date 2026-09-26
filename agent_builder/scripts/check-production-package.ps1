param(
    [string] $CertificateThumbprint = $env:FORGESEC_SIGN_CERT_SHA1
)

. (Join-Path $PSScriptRoot '_common.ps1')

$prerequisites = Get-ProductionPackagePrerequisites $CertificateThumbprint
if ($prerequisites.Issues.Count) {
    Write-Host 'Production one-install package is not ready:' -ForegroundColor Yellow
    foreach ($issue in $prerequisites.Issues) { Write-Host " - $issue" }
    exit 1
}
Write-Host 'Production package prerequisites passed. Confirm OEM and Inno license terms before release.' -ForegroundColor Green
