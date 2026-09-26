Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BuilderRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:RepoRoot = (Resolve-Path (Join-Path $script:BuilderRoot '..')).Path

function Get-AgentVersion {
    $source = Get-Content (Join-Path $script:BuilderRoot 'src\forgesec_agent\__init__.py') -Raw
    $match = [regex]::Match($source, '__version__\s*=\s*"(?<version>\d+\.\d+\.\d+)"')
    if (-not $match.Success) {
        throw 'Unable to read the ForgeSec agent version.'
    }
    return $match.Groups['version'].Value
}

function Reset-BuilderDirectory([string] $Path) {
    $root = [IO.Path]::GetFullPath($script:BuilderRoot).TrimEnd('\') + '\'
    $target = [IO.Path]::GetFullPath($Path)
    if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to reset a directory outside agent_builder: $target"
    }
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
}

function Find-Iscc {
    $candidates = @(
        $env:FORGESEC_ISCC_PATH,
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe'
    ) | Where-Object { $_ }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'Inno Setup 6 compiler was not found. Install it or set FORGESEC_ISCC_PATH.'
}

function Find-SignTool {
    if ($env:FORGESEC_SIGNTOOL_PATH -and (Test-Path -LiteralPath $env:FORGESEC_SIGNTOOL_PATH -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $env:FORGESEC_SIGNTOOL_PATH).Path
    }
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    $kits = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($kits) {
        return $kits.FullName
    }
    throw 'signtool.exe was not found. Install the Windows SDK or set FORGESEC_SIGNTOOL_PATH.'
}

function Install-AgentLockedDependencies([string] $Python) {
    $lock = Join-Path $script:BuilderRoot 'requirements.lock'
    if (-not (Test-Path -LiteralPath $lock -PathType Leaf)) {
        throw 'Agent requirements.lock is missing.'
    }
    & $Python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r $lock
    if ($LASTEXITCODE -ne 0) { throw 'Agent locked dependency install failed.' }
    & $Python -m pip install --disable-pip-version-check --no-deps --no-build-isolation $script:BuilderRoot
    if ($LASTEXITCODE -ne 0) { throw 'Agent source package install failed.' }
}

function Get-ProductionPackagePrerequisites([string] $CertificateThumbprint) {
    $issues = [System.Collections.Generic.List[string]]::new()
    $python = Join-Path $script:BuilderRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        $issues.Add('Agent build environment is missing at agent_builder\.venv.')
    }
    try { Find-Iscc | Out-Null } catch { $issues.Add('Inno Setup 6 compiler is missing.') }
    try { Find-SignTool | Out-Null } catch { $issues.Add('Windows SDK signtool.exe is missing.') }

    $thumbprint = $CertificateThumbprint.Replace(' ', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
        $issues.Add('Set FORGESEC_SIGN_CERT_SHA1 to a 40-character code-signing certificate thumbprint.')
    } else {
        $certificate = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $thumbprint -and $_.HasPrivateKey -and $_.NotAfter.ToUniversalTime() -gt [DateTime]::UtcNow } |
            Select-Object -First 1
        if (-not $certificate) {
            $issues.Add('The code-signing certificate is missing, expired, or has no private key.')
        }
    }

    $dependency = Join-Path $script:BuilderRoot 'installer\dependencies\nmap-oem.exe'
    $oemHash = $null
    if (-not (Test-Path -LiteralPath $dependency -PathType Leaf)) {
        $issues.Add('Licensed Nmap OEM installer is missing at installer\dependencies\nmap-oem.exe.')
    } else {
        $oemHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dependency).Hash
    }
    $expectedHash = $env:FORGESEC_NMAP_OEM_SHA256
    if ($expectedHash -notmatch '^[0-9A-Fa-f]{64}$') {
        $issues.Add('Set FORGESEC_NMAP_OEM_SHA256 to the supplier-verified 64-character hash.')
    } elseif ($oemHash -and $oemHash -ne $expectedHash) {
        $issues.Add('The Nmap OEM installer hash does not match the supplier-verified hash.')
    }

    return [pscustomobject]@{ Issues = @($issues.ToArray()); OemHash = $oemHash }
}

function Invoke-SignArtifact {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $CertificateThumbprint,
        [string] $TimestampUrl = 'http://timestamp.digicert.com'
    )
    if (-not $CertificateThumbprint.Trim()) {
        throw 'A code-signing certificate thumbprint is required.'
    }
    $signTool = Find-SignTool
    & $signTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Path
    if ($LASTEXITCODE -ne 0) {
        throw "Code signing failed for $Path"
    }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid') {
        throw "The Authenticode signature is not valid: $($signature.Status)"
    }
}
