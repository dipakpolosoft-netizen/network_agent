# Step 19: Clean-machine production release pilot

This is a **real acceptance test on a disposable Windows x64 VM**, not a build or a simulation. Do not run it on the ForgeSec build workstation or an employee PC. Preserve a clean VM snapshot and a written approval for one pilot site, one exact connected subnet, and one known target. Follow the [pilot baseline](pilot-baseline.md) for exclusions and scan limits.

## Entry gates

- The production control plane is reachable from the VM at a trusted HTTPS hostname. `GET /health` must work without disabling certificate validation. A loopback URL on the server is not a remote probe URL.
- The downloaded installer and `release.json` are from the production release. The manifest must report `channel: production`, `signed: true`, and `includes_licensed_scanner: true`, with matching size and SHA-256. A development package cannot pass this pilot.
- The VM has no ForgeSec or legacy Telesec service/data and **no Nmap or Npcap before installation**. This is how the test proves the single setup installed scanner dependencies.
- The VM operator has administrator access, a signed-in desktop session for observing the tray, and a snapshot identifier. Keep the enrollment token out of shell history, transcripts, screenshots, and result files.

## 1. Download and preflight on the VM

Transfer `scripts/check-agent-lifecycle.ps1` to a local folder on the VM. In elevated PowerShell, download the installer and release metadata over the same HTTPS origin. Replace the hostname and expected version with the actual release values:

```powershell
$base = 'https://scan.your-real-domain.com'
$installer = Join-Path $PWD 'ForgeSec-Network-Agent-Setup.exe'
Invoke-WebRequest "$base/downloads/agent/ForgeSec-Network-Agent-Setup.exe" -OutFile $installer
Invoke-WebRequest "$base/downloads/agent/release.json" -OutFile (Join-Path $PWD 'release.json')
.\check-agent-lifecycle.ps1 -Stage Preflight -RequireProduction `
  -InstallerPath $installer -ReleaseMetadataPath .\release.json `
  -ApiUrl $base -ExpectedVersion '<release-version>'
```

Stop on any failed check. Compare the hash to the build host's `dist\installer\release-manifest.json` through a separate trusted channel. Check the certificate publisher and validity in Windows Properties as well as the preflight's Authenticode result. Record VM snapshot, Windows build, installer hash/version, certificate publisher, and the approved site/CIDR. Do not erase residual files to make an unclean VM pass; restore the snapshot or use a new VM.

## 2. Install and observe

Create a fresh, site-bound enrollment token in the dashboard immediately before setup. Run the installer **interactively** from the elevated shell. Enter the HTTPS URL and token in its wizard, not in command-line arguments:

```powershell
$started = (Get-Date).ToUniversalTime()
$setup = Start-Process -FilePath $installer -Wait -PassThru
$setup.ExitCode
Start-Sleep -Seconds 45
.\check-agent-lifecycle.ps1 -Stage Installed -RequireProduction -RequireTray `
  -ExpectedVersion '<release-version>' -NotBeforeUtc $started
```

Require exit code 0. Observe the ForgeSec logo and readable text on welcome, enrollment, progress, and finish screens. Check the visible tray icon in the signed-in desktop, not only its process. The installed check requires signed agent/tray binaries, Nmap, Npcap, protected identity, service, scanner-ready diagnostics, and a fresh online heartbeat. If heartbeat is delayed, wait up to 90 seconds and rerun; do not issue a second enrollment token unless the first enrollment has genuinely failed.

In **Agent fleet**, confirm the same agent ID, site, hostname/IP, Nmap version, Npcap readiness, and current heartbeat. Verify that no discovery or scan launched automatically.

## 3. Exercise one authorized workflow

Discover only the approved connected pilot segment. Confirm the probe itself and one known test device are visible, with honest hostname/vendor/OS uncertainty where evidence is absent. Run one `inventory` or `standard` scan on the known target. Confirm progress, final report, JSON/PDF downloads, asset observation, and audit entries. Record discovery ID, scan ID, target IP, observed ports, and any mismatch against the baseline. Do not use `Scan all`, `full_tcp`, or an unapproved subnet merely to complete this gate.

## 4. Restart, upgrade, and uninstall

Record the agent ID from the local status, restart the service, and confirm a newer heartbeat and unchanged ID:

```powershell
$agentId = (Get-Content "$env:ProgramData\ForgeSec\NetworkAgent\state\status.json" -Raw | ConvertFrom-Json).agent_id
$restarted = (Get-Date).ToUniversalTime()
Restart-Service ForgeSecNetworkAgent
Start-Sleep -Seconds 45
.\check-agent-lifecycle.ps1 -Stage Installed -RequireProduction -RequireTray `
  -ExpectedAgentId $agentId -ExpectedVersion '<release-version>' -NotBeforeUtc $restarted
```

An upgrade test requires a **newer signed production release**, not a reinstall of the same version or a development build. Install it over the first release without `/RESETAGENTDATA=1`; verify the same agent ID and site, new version, new heartbeat, and working tray. If a newer release is unavailable, mark upgrade **not tested**; do not report the whole lifecycle gate as passed.

Uninstall **ForgeSec Network Agent** through Windows Installed Apps, then run:

```powershell
.\check-agent-lifecycle.ps1 -Stage Uninstalled -RequireProduction
```

Confirm the tray icon is gone and local service, startup entry, application files, identity, logs, and state are removed. Nmap/Npcap are currently separate system-wide dependencies and the ForgeSec uninstaller does **not** remove them; record this explicitly and decide whether it meets your customer uninstall policy. Do not manually delete ForgeSec leftovers to hide a failure. The server retains audit/inventory/scan history; confirm the probe goes offline, revoke its credential as an administrator, and check the revocation event. Restore the clean VM snapshot before a fresh-enrollment repeat.

## Exit gate

Record pass/fail and evidence for package signature/hash, clean preflight, HTTPS trust, interactive branding, bundled dependency installation, authenticated heartbeat, tray, approved discovery and scan, report, restart, newer-version upgrade, uninstall cleanup, and server revocation. **Step 19 remains incomplete if a signed production package, live HTTPS control plane, clean VM, or any required observation is missing.** Keep the enrollment token and credential out of the evidence record. Promote the release only after reviewing every failure and the [one-install release gate](one-install-pilot.md).
