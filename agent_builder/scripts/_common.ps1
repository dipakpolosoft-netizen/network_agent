Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BuilderRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:RepoRoot = (Resolve-Path (Join-Path $script:BuilderRoot '..')).Path

function Get-AgentVersion {
    $source = Get-Content (Join-Path $script:BuilderRoot 'src\telesec_agent\__init__.py') -Raw
    $match = [regex]::Match($source, '__version__\s*=\s*"(?<version>\d+\.\d+\.\d+)"')
    if (-not $match.Success) {
        throw 'Unable to read the Telesec agent version.'
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
        $env:TELESEC_ISCC_PATH,
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
    throw 'Inno Setup 6 compiler was not found. Install it or set TELESEC_ISCC_PATH.'
}

function Find-SignTool {
    if ($env:TELESEC_SIGNTOOL_PATH -and (Test-Path -LiteralPath $env:TELESEC_SIGNTOOL_PATH)) {
        return (Resolve-Path -LiteralPath $env:TELESEC_SIGNTOOL_PATH).Path
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
    throw 'signtool.exe was not found. Install the Windows SDK or set TELESEC_SIGNTOOL_PATH.'
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
