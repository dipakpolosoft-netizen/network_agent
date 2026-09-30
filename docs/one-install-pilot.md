# One-install Windows probe pilot (Step 13)

Complete the [pilot baseline and authorization](pilot-baseline.md) first. Use the [agent lifecycle pilot](agent-lifecycle-pilot.md) for the development install, restart, upgrade, uninstall, and revocation checks. Use a disposable Windows x64 pilot machine, an approved test site, and an exact authorized subnet. The ForgeSec download installs one Windows service and a tray app. It never installs Nuclei, Greenbone, or SSH inventory on that machine. Those optional workers remain central and require their own network route.

## Release gates

A **production one-install** setup must include a licensed Nmap OEM installer (which includes Npcap OEM), be Authenticode-signed, and reach the ForgeSec API over trusted HTTPS. [Nmap's OEM terms](https://nmap.org/oem/) govern redistribution. Also confirm your organization's [Inno Setup commercial license](https://jrsoftware.org/ishelp/topic_purchase.htm) before customer distribution. Do not place the free Nmap installer in `installer\dependencies` or publish a development build as a complete customer installer.

Place the licensed file at `agent_builder\installer\dependencies\nmap-oem.exe`. Verify its SHA-256 from your trusted supplier record, then set the expected hash and signing certificate thumbprint in the release terminal:

```powershell
cd C:\Users\USER\Desktop\forge-sec-network-agent\network_agent\agent_builder
.\scripts\check-production-package.ps1
Get-FileHash .\installer\dependencies\nmap-oem.exe -Algorithm SHA256
$env:FORGESEC_NMAP_OEM_SHA256 = '<supplier-verified-sha256>'
$env:FORGESEC_SIGN_CERT_SHA1 = '<code-signing-certificate-thumbprint>'
.\scripts\check-production-package.ps1
$reviewedCommit = '<reviewed-40-character-git-sha>'
.\scripts\release.ps1 -ExpectedCommit $reviewedCommit
```

The first preflight lists missing inputs; it is expected to fail until they are supplied. Set `FORGESEC_SIGNTOOL_PATH` to the Windows SDK `signtool.exe` path if it is not on `PATH`. Confirm your organization's Inno Setup commercial license before running the production release; a compiler that prints `Non-commercial use only` is not sufficient evidence for commercial distribution. The production release runs the source freeze gate against `$reviewedCommit` and refuses a changed worktree. It checks the compiler, signing tool/certificate, OEM file and its supplier-verified hash **before** rebuilding. Direct `build-installer.ps1 -Production` calls also require signing, the same prerequisites, and already-signed agent/tray inputs. The release then lints/tests the probe, builds the service and tray executables, compiles and signs the setup, checks packaged execution, writes the source commit and actual installer signer into `dist\installer\release-manifest.json`, and publishes the installer and `release.json` beside the dashboard download. Keep the manifest and OEM supplier/license record with your release evidence. The OEM binary itself must not be committed to Git.

For a development-only pilot without OEM rights or signing, run `.\scripts\release.ps1 -Development`. This creates an unsigned setup that **does not install Nmap/Npcap**. Install those separately from the official source before trying discovery. Do not give that build to customers as a one-install release.

## Pilot the published download

1. Start API and web as described in [deployment](deployment.md). For a remote pilot, set `NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL` to the probe-facing HTTPS ingress **before building the web app**. The enrollment dialog must show that reachable URL, not `127.0.0.1` on the pilot machine. Sign in as an administrator, create a **pilot site**, and approve only the pilot CIDR and needed profiles. Create one one-time probe enrollment token for that site. Use a pilot Windows host on that subnet, not the central server unless that is intentionally your test topology.
2. In an elevated PowerShell on the pilot host, download the exact installer shown in the dashboard. Compare it with the release manifest hash from the build host. This checks the published artifact, not merely the local `dist` copy:

```powershell
$dashboard = 'https://<forgesec-dashboard-host>'
$download = Join-Path $env:TEMP 'ForgeSec-Network-Agent-Setup.exe'
Invoke-WebRequest "$dashboard/downloads/agent/ForgeSec-Network-Agent-Setup.exe" -OutFile $download -UseBasicParsing
(Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
```

3. Compare the displayed hash to `dist\installer\release-manifest.json` (`sha256`) obtained through a separate trusted channel from the build owner, not only to the public `release.json`. Also compare the actual Authenticode signer to the approved certificate thumbprint and require the manifest's `source_commit` to equal the reviewed commit. The manifest must say `channel: production`, `signed: true`, and `includes_licensed_scanner: true` for a real one-install pilot. Reject a mismatch or development channel. The enrollment dialog also displays the package channel.
4. On a clean pilot VM, run the installer interactively to inspect ForgeSec branding, enrollment page, progress, finish state, and tray appearance. Paste the probe-facing API HTTPS URL and the one-time token into the wizard, not a shell command. Follow the [clean-machine release pilot](clean-machine-release-pilot.md) to run `check-agent-lifecycle.ps1` before and after installation. `test-installer.ps1` is a **build-host** package check: it expects local `dist\agent` binaries and cannot validate a VM that has only the downloaded setup. Use a new token and a clean VM snapshot for each install attempt. A one-time token in a silent installer command line may be visible briefly to local administrators; use protected secret handling if you separately test unattended deployment.

5. In the dashboard, confirm the probe appears under **Network Scanner > Agent fleet** with the correct site, IP/subnet, online heartbeat, Nmap version, and Npcap available. Verify the tray reports the same posture after interactive install or the next user sign-in. No discovery should have started automatically.
6. Run discovery of **one approved pilot segment**. Check the probe itself and a known test device. Scan **one selected test device** with an approved `inventory` or `standard` profile. Confirm progress, report view, JSON/PDF download, and asset evidence. Do not use `full_tcp`, Greenbone, or a broad subnet merely to exercise the installer.
7. Test upgrade separately: create a new installer of the same channel with a later version, install over the pilot copy, and confirm the agent ID/identity persists without `/RESETAGENTDATA=1`. Test fresh re-enrollment only on a separate disposable VM or after deliberate identity reset.
8. Uninstall on the pilot host. Confirm the service and tray are gone, the Run entry is removed, and `%ProgramData%\ForgeSec\NetworkAgent` is removed. The server keeps its audit/inventory record and will mark the probe offline; an administrator should **revoke** that identity in Agent fleet. Uninstall does not erase server-side scan history or other devices' data.

## Decision record

Record installer version, channel, size and SHA-256; OEM Nmap/Npcap versions and license reference; certificate publisher/validity; pilot Windows version and site CIDR; first heartbeat time; report ID; upgrade result; uninstall/revoke result; and any failed prerequisites. Use the [Step 19 clean-machine release pilot](clean-machine-release-pilot.md) and do not promote a build until every required observation passes. A packaged executable test or fixture smoke test is useful but is **not** a substitute for the elevated install, HTTPS enrollment, scanner dependency, tray, and uninstall pilot on a separate machine.
