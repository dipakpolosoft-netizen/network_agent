param(
    [string] $Version = '',
    [switch] $Production,
    [switch] $Sign,
    [string] $CertificateThumbprint = $env:TELESEC_SIGN_CERT_SHA1,
    [string] $TimestampUrl = 'http://timestamp.digicert.com'
)

. (Join-Path $PSScriptRoot '_common.ps1')

$sourceVersion = Get-AgentVersion
if (-not $Version) { $Version = $sourceVersion }
if ($Version -ne $sourceVersion) { throw "Requested version $Version does not match source version $sourceVersion." }

$agent = Join-Path $script:BuilderRoot 'dist\agent\TelesecAgent.exe'
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
    throw 'Build the agent executable before building the installer.'
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
$isccArguments += (Join-Path $script:BuilderRoot 'installer\TelesecNetworkAgent.iss')
& $iscc $isccArguments
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed.' }

$installer = Join-Path $script:BuilderRoot "dist\installer\Telesec-Network-Agent-Setup-$Version.exe"
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) { throw 'Installer was not produced.' }
if ($Sign) {
    Invoke-SignArtifact -Path $installer -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl
}
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash
Write-Host "Built $(Split-Path $installer -Leaf) (SHA256 $hash)"
