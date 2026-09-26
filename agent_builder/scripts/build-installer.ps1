param(
    [string] $Version = '',
    [switch] $Production,
    [switch] $Sign,
    [string] $CertificateThumbprint = $env:FORGESEC_SIGN_CERT_SHA1,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

. (Join-Path $PSScriptRoot '_common.ps1')

$sourceVersion = Get-AgentVersion
if (-not $Version) { $Version = $sourceVersion }
if ($Version -ne $sourceVersion) { throw "Requested version $Version does not match source version $sourceVersion." }
if ($Production) {
    if (-not $Sign) { throw 'Production installer builds must be code-signed.' }
    $prerequisites = Get-ProductionPackagePrerequisites $CertificateThumbprint
    if ($prerequisites.Issues.Count) {
        throw "Production installer prerequisites:`n - $($prerequisites.Issues -join "`n - ")"
    }
}

$agent = Join-Path $script:BuilderRoot 'dist\agent\ForgeSecAgent.exe'
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
    throw 'Build the agent executable before building the installer.'
}
if ($Production) {
    $tray = Join-Path $script:BuilderRoot 'dist\agent\ForgeSecTray.exe'
    foreach ($artifact in @($agent, $tray)) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf) -or
            (Get-AuthenticodeSignature -FilePath $artifact).Status -ne 'Valid') {
            throw "Production installer input is missing or not validly signed: $artifact"
        }
    }
}

$isccArguments = @("/DAgentVersion=$Version")
if ($Production) {
    $dependency = Join-Path $script:BuilderRoot 'installer\dependencies\nmap-oem.exe'
    if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) {
        throw "Production dependency is missing: $dependency"
    }
    $isccArguments += '/DIncludeOemDependencies=1'
}

Reset-BuilderDirectory (Join-Path $script:BuilderRoot 'dist\installer')
$iscc = Find-Iscc
$isccArguments += (Join-Path $script:BuilderRoot 'installer\ForgeSecNetworkAgent.iss')
& $iscc $isccArguments
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }

$installer = Join-Path $script:BuilderRoot "dist\installer\ForgeSec-Network-Agent-Setup-$Version.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Installer was not produced.' }
if ($Sign) {
    Invoke-SignArtifact -Path $installer -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
}
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
Write-Host "Built $(Split-Path $installer -Leaf) (SHA256 $hash)"
