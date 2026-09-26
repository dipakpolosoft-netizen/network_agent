param(
    [string] $LanIp = '',
    [string] $RemoteAddress = ''
)

$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from PowerShell opened with Run as administrator.'
}

$adapter = Get-NetIPConfiguration |
    Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway } |
    Select-Object -First 1
if (-not $adapter) {
    throw 'No active IPv4 adapter with a default gateway was found.'
}
$address = $adapter.IPv4Address | Select-Object -First 1
if (-not $LanIp) {
    $LanIp = $address.IPAddress
}
$localAddress = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $LanIp -ErrorAction SilentlyContinue
if (-not $localAddress) {
    throw "$LanIp is not assigned to this computer."
}

if (-not $RemoteAddress) {
    $bytes = [Net.IPAddress]::Parse($LanIp).GetAddressBytes()
    $remaining = [int] $localAddress.PrefixLength
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bits = [Math]::Min(8, $remaining)
        $mask = if ($bits -eq 0) { 0 } else { (0xff -shl (8 - $bits)) -band 0xff }
        $bytes[$index] = $bytes[$index] -band $mask
        $remaining -= $bits
    }
    $network = [Net.IPAddress]::new($bytes).ToString()
    $RemoteAddress = "$network/$($localAddress.PrefixLength)"
}

$ruleName = 'ForgeSec-Web-LAN'
$broadNodeRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    Where-Object {
        $application = $_ | Get-NetFirewallApplicationFilter
        $application.Program -and
        [System.IO.Path]::GetFileName($application.Program) -ieq 'node.exe'
    }
$broadNodeRules | Disable-NetFirewallRule
Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
New-NetFirewallRule `
    -Name $ruleName `
    -DisplayName 'ForgeSec Web Dashboard (LAN)' `
    -Description 'Allows the ForgeSec dashboard only from the configured local network.' `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalAddress $LanIp `
    -LocalPort 3000 `
    -RemoteAddress $RemoteAddress `
    -Profile Any `
    -EdgeTraversalPolicy Block | Out-Null

Write-Output "Allowed http://${LanIp}:3000 from $RemoteAddress only."
if ($broadNodeRules) {
    Write-Output "Disabled $(@($broadNodeRules).Count) broad inbound Node.js firewall rule(s)."
}
