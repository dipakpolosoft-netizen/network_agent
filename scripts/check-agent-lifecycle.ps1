param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preflight', 'Installed', 'Uninstalled')]
    [string] $Stage,
    [string] $InstallerPath = '',
    [string] $ReleaseMetadataPath = '',
    [string] $ApiUrl = '',
    [string] $InstallDir = '',
    [string] $ExpectedAgentId = '',
    [string] $ExpectedVersion = '',
    [string] $ExpectedCommit = '',
    [string] $ExpectedSha256 = '',
    [string] $ExpectedSignerThumbprint = '',
    [datetime] $NotBeforeUtc = [datetime]::MinValue,
    [switch] $RequireTray,
    [switch] $RequireProduction
)

$ErrorActionPreference = 'Stop'
$script:Failures = @()
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$dataRoot = Join-Path $env:ProgramData 'ForgeSec\NetworkAgent'
if (-not $InstallDir) { $InstallDir = Join-Path $env:ProgramFiles 'ForgeSec\NetworkAgent' }
if (-not $InstallerPath) {
    $repoInstaller = Join-Path $repoRoot 'apps\web\public\downloads\agent\ForgeSec-Network-Agent-Setup.exe'
    $InstallerPath = if (Test-Path -LiteralPath $repoInstaller -PathType Leaf) {
        $repoInstaller
    } else {
        Join-Path $PSScriptRoot 'ForgeSec-Network-Agent-Setup.exe'
    }
}
if (-not $ReleaseMetadataPath) {
    $ReleaseMetadataPath = Join-Path (Split-Path -Parent $InstallerPath) 'release.json'
}

function Assert-Check {
    param([bool] $Condition, [string] $Description)
    if ($Condition) {
        Write-Host "PASS $Description" -ForegroundColor Green
    } else {
        Write-Host "FAIL $Description" -ForegroundColor Red
        $script:Failures += $Description
    }
}

function Read-JsonOrNull {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
    catch { return $null }
}

function Get-ScannerPath {
    $discovered = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if ($discovered) { return $discovered.Source }
    foreach ($base in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if (-not $base) { continue }
        $candidate = Join-Path $base 'Nmap\nmap.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Get-RunEntry {
    $values = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    if ($values) { return $values.ForgeSecNetworkAgentTray }
    return $null
}

$service = Get-Service -Name 'ForgeSecNetworkAgent' -ErrorAction SilentlyContinue
$tray = Get-Process -Name 'ForgeSecTray' -ErrorAction SilentlyContinue
$runEntry = Get-RunEntry

if ($Stage -eq 'Preflight') {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    Assert-Check $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'PowerShell is elevated'
    Assert-Check ($null -eq $service) 'No ForgeSec service is installed'
    Assert-Check (-not (Test-Path -LiteralPath $InstallDir)) 'Install directory is absent'
    Assert-Check (-not (Test-Path -LiteralPath $dataRoot)) 'ProgramData agent directory is absent'
    Assert-Check ($null -eq $tray) 'No ForgeSec tray process is running'
    Assert-Check (-not $runEntry) 'No ForgeSec tray startup entry exists'
    if ($RequireProduction) {
        Assert-Check (-not (Get-Service -Name 'TelesecNetworkAgent' -ErrorAction SilentlyContinue)) 'No legacy Telesec service is installed'
        Assert-Check (-not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Telesec\NetworkAgent'))) 'No legacy Telesec data directory exists'
    }
    $nmapPresent = [bool](Get-ScannerPath)
    $npcapPresent = [bool](Get-Service -Name 'npcap' -ErrorAction SilentlyContinue)
    if ($RequireProduction) {
        Assert-Check (-not $nmapPresent) 'Nmap is absent before one-install setup'
        Assert-Check (-not $npcapPresent) 'Npcap is absent before one-install setup'
    } else {
        Assert-Check $nmapPresent 'Nmap is installed separately for the development pilot'
        Assert-Check $npcapPresent 'Npcap service is installed'
    }

    $release = Read-JsonOrNull $ReleaseMetadataPath
    $installerExists = Test-Path -LiteralPath $InstallerPath -PathType Leaf
    Assert-Check $installerExists 'Published installer is present'
    Assert-Check ($null -ne $release) 'release.json is present and valid'
    if ($installerExists -and $release) {
        $installer = Get-Item -LiteralPath $InstallerPath
        $hash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
        Assert-Check ($release.sha256 -eq $hash -and $release.size_bytes -eq $installer.Length) 'Installer matches release.json hash and size'
        if ($RequireProduction) {
            Assert-Check ($ExpectedSha256 -match '^[0-9A-Fa-f]{64}$' -and $hash -eq $ExpectedSha256) 'Installer matches the independently supplied build-host SHA-256'
            Assert-Check ($ExpectedCommit -match '^[0-9A-Fa-f]{40}$' -and $release.source_commit -eq $ExpectedCommit) 'Manifest matches the independently approved source commit'
            Assert-Check ($ExpectedSignerThumbprint -match '^[0-9A-Fa-f]{40}$') 'Approved signer thumbprint was supplied independently'
            Assert-Check ($release.schema_version -eq 1 -and $release.channel -eq 'production' -and $release.signed -and $release.includes_licensed_scanner -and $release.nmap_oem_sha256 -match '^[0-9A-Fa-f]{64}$' -and $release.source_commit -match '^[0-9A-Fa-f]{40}$') 'Manifest declares a frozen licensed production package'
            $signature = Get-AuthenticodeSignature -FilePath $InstallerPath
            Assert-Check ($signature.Status -eq 'Valid') 'Installer Authenticode signature is valid on this machine'
            Assert-Check ($signature.SignerCertificate -and $signature.SignerCertificate.Thumbprint -eq $ExpectedSignerThumbprint -and $release.signer_thumbprint -eq $ExpectedSignerThumbprint) 'Installer and manifest match the approved signer'
        } else {
            Assert-Check ($release.channel -eq 'development' -and -not $release.signed -and -not $release.includes_licensed_scanner) 'Package is clearly marked development-only'
        }
        if ($ExpectedVersion) {
            Assert-Check ($release.version -eq $ExpectedVersion) 'Manifest version matches expected release'
        }
        Write-Host "Package version $($release.version); SHA256 $hash"
    }

    if ($ApiUrl) {
        $uri = $null
        $validUrl = [Uri]::TryCreate($ApiUrl, [UriKind]::Absolute, [ref] $uri)
        $loopback = $validUrl -and $uri.IsLoopback
        $allowedUrl = $validUrl -and ($uri.Scheme -eq 'https' -or ($uri.Scheme -eq 'http' -and $loopback))
        if ($RequireProduction) {
            $allowedUrl = $validUrl -and $uri.Scheme -eq 'https' -and -not $loopback -and $uri.UserInfo -eq '' -and $uri.AbsolutePath -eq '/' -and $uri.Query -eq '' -and $uri.Fragment -eq ''
            Assert-Check $allowedUrl 'Production API URL is a non-loopback HTTPS origin'
        } else {
            Assert-Check $allowedUrl 'API URL uses HTTPS or same-machine loopback'
        }
        if ($allowedUrl) {
            try {
                $health = Invoke-RestMethod -Uri "$($uri.AbsoluteUri.TrimEnd('/'))/health" -TimeoutSec 8
                Assert-Check ($health.status -eq 'ok' -and $health.service -eq 'forgesec-api') 'API health responds from this pilot machine'
                if ($RequireProduction) {
                    $ready = Invoke-RestMethod -Uri "$($uri.AbsoluteUri.TrimEnd('/'))/ready" -TimeoutSec 8
                    Assert-Check ($ready.status -eq 'ready') 'Production storage is ready from this pilot machine'
                }
            } catch {
                Assert-Check $false "API health responds from this pilot machine: $($_.Exception.Message)"
            }
        }
    } else {
        Assert-Check $false 'ApiUrl is required to prove pilot-machine connectivity'
    }
}

if ($Stage -eq 'Installed') {
    Assert-Check ($service -and $service.Status -eq 'Running') 'ForgeSec Windows service is running'
    $installedAgent = Join-Path $InstallDir 'ForgeSecAgent.exe'
    $installedTray = Join-Path $InstallDir 'ForgeSecTray.exe'
    Assert-Check (Test-Path -LiteralPath $installedAgent -PathType Leaf) 'Installed agent executable is present'
    Assert-Check (Test-Path -LiteralPath $installedTray -PathType Leaf) 'Installed tray executable is present'
    if ($RequireProduction) {
        Assert-Check ($ExpectedSignerThumbprint -match '^[0-9A-Fa-f]{40}$') 'Approved signer thumbprint was supplied independently'
        foreach ($artifact in @($installedAgent, $installedTray)) {
            if (Test-Path -LiteralPath $artifact -PathType Leaf) {
                $signature = Get-AuthenticodeSignature -FilePath $artifact
                Assert-Check ($signature.Status -eq 'Valid' -and $signature.SignerCertificate -and $signature.SignerCertificate.Thumbprint -eq $ExpectedSignerThumbprint) "Installed signature matches approved signer: $(Split-Path $artifact -Leaf)"
            }
        }
        Assert-Check ([bool](Get-ScannerPath)) 'Nmap is installed by the one-install package'
        Assert-Check ([bool](Get-Service -Name 'npcap' -ErrorAction SilentlyContinue)) 'Npcap is installed by the one-install package'
    }
    Assert-Check (Test-Path -LiteralPath (Join-Path $dataRoot 'identity\identity.json') -PathType Leaf) 'Protected enrollment identity is present'
    Assert-Check ([bool]$runEntry) 'Tray startup entry is present'
    if ($RequireTray) { Assert-Check ([bool]$tray) 'Tray process is running in a signed-in user session' }

    $public = Read-JsonOrNull (Join-Path $dataRoot 'public\status.json')
    $private = Read-JsonOrNull (Join-Path $dataRoot 'state\status.json')
    $heartbeat = [datetime]::MinValue
    if ($public -and $public.last_heartbeat_at) {
        try { $heartbeat = [datetime]::Parse($public.last_heartbeat_at).ToUniversalTime() }
        catch { $heartbeat = [datetime]::MinValue }
    }
    Assert-Check ($public -and $public.status -eq 'online' -and $heartbeat -ge [datetime]::UtcNow.AddSeconds(-90)) 'Fresh authenticated online heartbeat is present'
    Assert-Check ($private -and $private.agent_id) 'Private status records an agent ID'
    if ($ExpectedAgentId) {
        Assert-Check ($private -and $private.agent_id -eq $ExpectedAgentId) 'Agent ID survived restart or upgrade'
    }
    if ($NotBeforeUtc -ne [datetime]::MinValue) {
        Assert-Check ($heartbeat -gt $NotBeforeUtc.ToUniversalTime()) 'Heartbeat is newer than the recorded lifecycle action'
    }
    if (Test-Path -LiteralPath $installedAgent -PathType Leaf) {
        $version = (& $installedAgent --version | Out-String).Trim()
        Assert-Check ($LASTEXITCODE -eq 0 -and [bool]$version) 'Installed executable responds with its version'
        if ($ExpectedVersion) { Assert-Check ($version -eq $ExpectedVersion) 'Installed version matches expected release' }
        $doctor = $null
        try { $doctor = (& $installedAgent doctor | Out-String | ConvertFrom-Json) } catch { $doctor = $null }
        Assert-Check ($LASTEXITCODE -eq 0 -and $doctor -and $doctor.status -eq 'ready') 'Installed agent doctor reports scanner ready'
        Write-Host "Installed version $version"
    }
    if ($private -and $private.agent_id) { Write-Host "Agent ID $($private.agent_id)" }
    if ($heartbeat -ne [datetime]::MinValue) { Write-Host "Last heartbeat UTC $($heartbeat.ToString('o'))" }
}

if ($Stage -eq 'Uninstalled') {
    Assert-Check ($null -eq $service) 'ForgeSec service is absent'
    Assert-Check ($null -eq $tray) 'ForgeSec tray process is absent'
    Assert-Check (-not $runEntry) 'Tray startup entry is absent'
    Assert-Check (-not (Test-Path -LiteralPath $InstallDir)) 'Install directory is removed'
    Assert-Check (-not (Test-Path -LiteralPath $dataRoot)) 'ProgramData identity, logs, and state are removed'
}

if ($script:Failures.Count -gt 0) {
    Write-Host "$($script:Failures.Count) lifecycle check(s) failed for $Stage." -ForegroundColor Red
    exit 1
}
Write-Host "All local $Stage checks passed. Confirm tray appearance and server-side state in the UI." -ForegroundColor Green
