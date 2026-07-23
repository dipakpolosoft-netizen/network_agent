param(
    [string] $Version = '',
    [switch] $RequireSigned
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$source = Join-Path $script:BuilderRoot "dist\installer\Telesec-Network-Agent-Setup-$Version.exe"
$destination = Join-Path $script:RepoRoot 'apps\web\public\downloads\agent\Telesec-Network-Agent-Setup.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Installer not found: $source" }
if ($RequireSigned -and (Get-AuthenticodeSignature -FilePath $source).Status -ne 'Valid') {
    throw 'Refusing to publish an installer without a valid Authenticode signature.'
}
New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
Copy-Item -LiteralPath $source -Destination $destination -Force
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash) {
    throw 'Published installer hash does not match its source.'
}
Write-Host "Published installer to $destination"
