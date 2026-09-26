param(
    [string] $Version = '',
    [switch] $RequireSigned
)

. (Join-Path $PSScriptRoot '_common.ps1')

if (-not $Version) { $Version = Get-AgentVersion }
$source = Join-Path $script:BuilderRoot "dist\installer\ForgeSec-Network-Agent-Setup-$Version.exe"
$manifestSource = Join-Path $script:BuilderRoot 'dist\installer\release-manifest.json'
$destination = Join-Path $script:RepoRoot 'apps\web\public\downloads\agent\ForgeSec-Network-Agent-Setup.exe'
$manifestDestination = Join-Path (Split-Path $destination -Parent) 'release.json'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Installer not found: $source" }
if (-not (Test-Path -LiteralPath $manifestSource -PathType Leaf)) { throw "Release manifest not found: $manifestSource" }
$manifest = Get-Content -LiteralPath $manifestSource -Raw | ConvertFrom-Json
$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
if ($manifest.schema_version -ne 1 -or $manifest.version -ne $Version -or $manifest.sha256 -ne $sourceHash -or $manifest.size_bytes -ne (Get-Item -LiteralPath $source).Length) {
    throw 'Release manifest does not match the installer artifact.'
}
if ($RequireSigned -and (Get-AuthenticodeSignature -FilePath $source).Status -ne 'Valid') {
    throw 'Refusing to publish an installer without a valid Authenticode signature.'
}
if ($RequireSigned -and ($manifest.channel -ne 'production' -or -not $manifest.signed -or -not $manifest.includes_licensed_scanner)) {
    throw 'Refusing to publish an incomplete production release manifest.'
}
New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
Copy-Item -LiteralPath $source -Destination $destination -Force
if ($sourceHash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash) {
    throw 'Published installer hash does not match its source.'
}
Copy-Item -LiteralPath $manifestSource -Destination $manifestDestination -Force
Write-Host "Published installer to $destination"
