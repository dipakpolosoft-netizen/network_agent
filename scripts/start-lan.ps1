param(
    [string] $LanIp = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$apiRoot = Join-Path $repoRoot 'services\api'
$webRoot = Join-Path $repoRoot 'apps\web'
$runRoot = Join-Path $repoRoot '.tmp\lan-runtime'
$python = Join-Path $apiRoot '.venv\Scripts\python.exe'
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'API environment is missing. Create services\api\.venv and install the project first.'
}
if (-not (Test-Path -LiteralPath (Join-Path $webRoot 'node_modules'))) {
    throw 'Web dependencies are missing. Run npm install in apps\web first.'
}

$adapter = Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway } |
    Select-Object -First 1
if (-not $adapter) {
    throw 'No active IPv4 adapter with a default gateway was found.'
}
$detectedIp = $adapter.IPv4Address.IPAddress | Select-Object -First 1
if (-not $LanIp) {
    $LanIp = $detectedIp
}
$localAddress = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $LanIp -ErrorAction SilentlyContinue
if (-not $localAddress) {
    throw "$LanIp is not assigned to this computer. Detected address: $detectedIp"
}

$existing = Get-CimInstance Win32_Process | Where-Object {
    ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) -or
    ($_.CommandLine -and $_.CommandLine.Contains($repoRoot) -and $_.CommandLine -match 'next|uvicorn')
}
$existing | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

$webListener = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
if ($webListener) {
    throw "Web port 3000 is occupied by PID $($webListener.OwningProcess)."
}
$apiListener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
$reuseApi = $false
$apiPid = $null
if ($apiListener) {
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:8000/health' -TimeoutSec 3
        $reuseApi = $health.status -eq 'ok' -and $health.service -eq 'telesec-api'
    } catch {
        $reuseApi = $false
    }
    if (-not $reuseApi) {
        throw "API port 8000 is occupied by an unknown process (PID $($apiListener.OwningProcess))."
    }
    $apiPid = $apiListener.OwningProcess
}

New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$env:TELESEC_ENV = 'development'
$env:TELESEC_API_HOST = '127.0.0.1'
$env:TELESEC_API_PORT = '8000'
$env:TELESEC_WEB_ORIGIN = "http://${LanIp}:3000"
$env:TELESEC_API_PROXY_URL = 'http://127.0.0.1:8000'
$env:TELESEC_LAN_IP = $LanIp
Remove-Item Env:NEXT_PUBLIC_TELESEC_API_URL -ErrorAction SilentlyContinue
$env:NEXT_PUBLIC_TELESEC_AGENT_SERVER_URL = 'http://127.0.0.1:8000'

if (-not $reuseApi) {
    $api = Start-Process -FilePath $python -ArgumentList @(
        '-m', 'uvicorn', 'telesec_api.main:app',
        '--host', '127.0.0.1', '--port', '8000'
    ) -WorkingDirectory $apiRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runRoot 'api.out.log') `
        -RedirectStandardError (Join-Path $runRoot 'api.err.log')
    $apiPid = $api.Id
}

$web = Start-Process -FilePath $npm -ArgumentList @(
    'run', 'dev', '--', '--hostname', '0.0.0.0', '--port', '3000'
) -WorkingDirectory $webRoot -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $runRoot 'web.out.log') `
    -RedirectStandardError (Join-Path $runRoot 'web.err.log')

@{
    api_pid = $apiPid
    web_pid = $web.Id
    lan_ip = $LanIp
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $runRoot 'processes.json') -Encoding utf8

$deadline = (Get-Date).AddSeconds(45)
do {
    Start-Sleep -Milliseconds 500
    try {
        $apiReady = (Invoke-WebRequest 'http://127.0.0.1:8000/health' -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200
    } catch {
        $apiReady = $false
    }
    try {
        $webReady = (Invoke-WebRequest "http://${LanIp}:3000/network-agent" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200
    } catch {
        $webReady = $false
    }
} until (($apiReady -and $webReady) -or (Get-Date) -ge $deadline)

if (-not $apiReady -or -not $webReady) {
    throw "Telesec did not become ready. Check logs in $runRoot"
}

Write-Output "Telesec dashboard: http://${LanIp}:3000/network-agent"
Write-Output 'Telesec API: private loopback proxy target on 127.0.0.1:8000'
