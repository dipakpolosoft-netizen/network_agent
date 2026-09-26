param(
    [switch] $SkipAgent,
    [switch] $SkipWebBuild,
    [switch] $IncludeSmoke
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$apiRoot = Join-Path $repoRoot 'services\api'
$agentRoot = Join-Path $repoRoot 'agent_builder'
$webRoot = Join-Path $repoRoot 'apps\web'
$apiPython = Join-Path $apiRoot '.venv\Scripts\python.exe'
$agentPython = Join-Path $agentRoot '.venv\Scripts\python.exe'
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source

function Invoke-VerifyStep {
    param(
        [string] $Name,
        [scriptblock] $Script
    )
    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    $global:LASTEXITCODE = 0
    & $Script
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

if (-not (Test-Path -LiteralPath $apiPython -PathType Leaf)) {
    throw 'API venv missing: services\api\.venv\Scripts\python.exe'
}
if (-not $SkipAgent -and -not (Test-Path -LiteralPath $agentPython -PathType Leaf)) {
    throw 'Agent venv missing: agent_builder\.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath (Join-Path $webRoot 'node_modules'))) {
    throw 'Web dependencies missing: run npm install in apps\web'
}

Invoke-VerifyStep 'Shared schema validation' {
    & $apiPython (Join-Path $repoRoot 'shared\schemas\validate_schemas.py')
}

Invoke-VerifyStep 'Pilot plan validator tests' {
    & $apiPython -m unittest discover -s (Join-Path $repoRoot 'scripts') -p 'test_*pilot*.py'
}

Invoke-VerifyStep 'Final acceptance gate tests' {
    & $apiPython -m unittest discover -s (Join-Path $repoRoot 'scripts') -p 'test_final_acceptance.py'
}

Invoke-VerifyStep 'Release baseline gate tests' {
    & $apiPython -m unittest discover -s (Join-Path $repoRoot 'scripts') -p 'test_release_baseline.py'
}

Invoke-VerifyStep 'API lint' {
    Push-Location $apiRoot
    try { & $apiPython -m ruff check --no-cache src tests }
    finally { Pop-Location }
}

Invoke-VerifyStep 'API tests' {
    Push-Location $apiRoot
    try { & $apiPython -m pytest }
    finally { Pop-Location }
}

if (-not $SkipAgent) {
    Invoke-VerifyStep 'Agent lint' {
        Push-Location $agentRoot
        try { & $agentPython -m ruff check --no-cache src tests }
        finally { Pop-Location }
    }

    Invoke-VerifyStep 'Agent tests' {
        Push-Location $agentRoot
        try { & $agentPython -m pytest }
        finally { Pop-Location }
    }
}

Invoke-VerifyStep 'Web typecheck' {
    Push-Location $webRoot
    try { & $npm run typecheck }
    finally { Pop-Location }
}

if (-not $SkipWebBuild) {
    Invoke-VerifyStep 'Web production build' {
        Push-Location $webRoot
        try { & $npm run build }
        finally { Pop-Location }
    }
}

$installer = Join-Path $repoRoot 'apps\web\public\downloads\agent\ForgeSec-Network-Agent-Setup.exe'
$releaseInfo = Join-Path $repoRoot 'apps\web\public\downloads\agent\release.json'
Invoke-VerifyStep 'Published installer artifact' {
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
        throw "Published installer missing: $installer"
    }
    if (-not (Test-Path -LiteralPath $releaseInfo -PathType Leaf)) {
        throw "Published release metadata missing: $releaseInfo"
    }
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $installer
    $release = Get-Content -LiteralPath $releaseInfo -Raw | ConvertFrom-Json
    if ($release.schema_version -ne 1 -or $release.sha256 -ne $hash.Hash -or $release.size_bytes -ne (Get-Item -LiteralPath $installer).Length) {
        throw 'Published release metadata does not match the installer.'
    }
    if ($release.channel -eq 'production' -and (-not $release.signed -or -not $release.includes_licensed_scanner)) {
        throw 'Production release metadata is incomplete.'
    }
    Write-Host "Installer SHA256 $($hash.Hash)"
    Write-Host "Channel $($release.channel), scanner included $($release.includes_licensed_scanner)"
}

if ($IncludeSmoke) {
    Invoke-VerifyStep 'Integrated control-plane smoke test' {
        & $apiPython -c "import fastapi, uvicorn, psutil" 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw 'Smoke test requires fastapi, uvicorn, and psutil in the API venv. Install agent dependencies into services\api\.venv or run without -IncludeSmoke.'
        }
        $previousPythonPath = $env:PYTHONPATH
        try {
            $env:PYTHONPATH = @(
                (Join-Path $apiRoot 'src'),
                (Join-Path $agentRoot 'src'),
                $previousPythonPath
            ) -join ';'
            & $apiPython (Join-Path $agentRoot 'scripts\smoke_control_plane.py')
        } finally {
            $env:PYTHONPATH = $previousPythonPath
        }
    }
}

Write-Host ""
Write-Host 'ForgeSec local verification completed.' -ForegroundColor Green
