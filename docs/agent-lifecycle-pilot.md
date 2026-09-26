# Step 15: Real Windows agent lifecycle pilot

This is a real-machine acceptance test, not an automated scan. Complete the
[Step 14 pilot baseline](pilot-baseline.md) first. Use a disposable Windows x64
VM/PC with administrator access and a known clean snapshot. Never run the
uninstall or fresh-enrollment path on a machine with agent data you intend to
keep. The checker in `scripts/check-agent-lifecycle.ps1` is read-only except
for its optional `GET /health` request; it does not install, stop, or delete
anything.

## 1. Prepare the pilot host

Install Nmap and Npcap separately from the official Windows release on the
pilot machine. The current ForgeSec development setup does **not** include
them. Verify the probe-facing API URL from this machine, with normal TLS
certificate verification. A URL using `127.0.0.1` works only when API and
probe are deliberately on the same computer. Record the VM snapshot ID,
Windows build, API URL, package channel/version/hash, and approved site.

Transfer `scripts/check-agent-lifecycle.ps1` to the pilot host along with the
downloaded installer and `release.json`. In **elevated PowerShell** on that
host, from the directory containing those files:

```powershell
$api = 'https://<probe-facing-api-host>'
.\check-agent-lifecycle.ps1 -Stage Preflight `
  -InstallerPath .\ForgeSec-Network-Agent-Setup.exe `
  -ReleaseMetadataPath .\release.json -ApiUrl $api
```

All checks must pass. A failing clean-state check means stop and investigate;
do not delete an existing ProgramData directory just to pass the test. A
development package must show `signed: false` and
`includes_licensed_scanner: false`, with a matching hash and size. If this
script is unavailable on the VM, check the same service, directories,
dependencies, hash, and `GET /health` manually before proceeding.

## 2. Install and enroll interactively

In the dashboard, create/select the authorized pilot site and its exact
approved network. Create a **new** site-bound, one-time token immediately
before installation; the default token life is 15 minutes. Do not write the
token in a plan file, command line, transcript, or screenshot. Run the setup
interactively from elevated PowerShell so the wizard prompts for the API URL
and token without placing them in process arguments:

```powershell
Start-Process -FilePath .\ForgeSec-Network-Agent-Setup.exe -Wait
.\check-agent-lifecycle.ps1 -Stage Installed -RequireTray -ExpectedVersion '0.1.0'
```

If the heartbeat is not fresh immediately, wait up to 90 seconds and rerun
the installed check. Inspect the ForgeSec logo and text in welcome,
enrollment, progress, and finish pages. Check the tray icon visually in the
signed-in user session; a running tray process alone does not prove the icon
is visible. In **Network Scanner > Agent fleet**, match the site, hostname,
IP/segment, Nmap version, Npcap readiness, and online heartbeat. No discovery
should start automatically.

The checker prints the agent ID from protected local state without revealing
the credential. Record that ID outside the repository for the restart and
upgrade comparison. Preserve any installation logs, but review them for
secrets before sharing them.

## 3. Restart and upgrade

In elevated PowerShell on the pilot host:

```powershell
$agentId = (Get-Content "$env:ProgramData\ForgeSec\NetworkAgent\state\status.json" -Raw | ConvertFrom-Json).agent_id
$restartAt = (Get-Date).ToUniversalTime()
Restart-Service ForgeSecNetworkAgent
Start-Sleep -Seconds 45
.\check-agent-lifecycle.ps1 -Stage Installed -RequireTray `
  -ExpectedAgentId $agentId -ExpectedVersion '0.1.0' -NotBeforeUtc $restartAt
```

Verify the tray moves through its disconnected/online state and the dashboard
receives a newer heartbeat. Restart must retain the same agent ID.

An **upgrade** requires a genuinely newer development installer of the same
channel. Reinstalling `0.1.0` does not prove upgrade behavior. Before running
the newer installer, record its version/hash, the current agent ID, and UTC
time. Run it interactively **without** `/RESETAGENTDATA=1` and without a new
token; then check the new version and retained identity:

```powershell
$upgradeAt = (Get-Date).ToUniversalTime()
Start-Process -FilePath '.\ForgeSec-Network-Agent-Setup-<new-version>.exe' -Wait
Start-Sleep -Seconds 45
.\check-agent-lifecycle.ps1 -Stage Installed -RequireTray `
  -ExpectedAgentId $agentId -ExpectedVersion '<new-version>' -NotBeforeUtc $upgradeAt
```

Confirm the identity and site remain unchanged. If no newer installer exists,
mark the upgrade item **not tested**, not passed.

## 4. Uninstall and revoke

On the disposable pilot machine, uninstall **ForgeSec Network Agent** from
Windows Installed Apps. Wait for Setup to finish, then run:

```powershell
.\check-agent-lifecycle.ps1 -Stage Uninstalled
```

Check that the service, tray process/icon, startup entry, install directory,
and `%ProgramData%\ForgeSec\NetworkAgent` are gone. Nmap and Npcap were
installed separately for this development pilot and are **not** removed by
ForgeSec uninstall; follow their own uninstall procedures only if the pilot
VM is being retired. Do not manually delete ForgeSec data to hide an
uninstaller failure.

The API intentionally keeps the probe record, audit events, assets, and scan
history. In **Agent fleet**, confirm the old probe becomes offline, then use
**Revoke** as an administrator and check the revocation activity event. The
removed identity must not be accepted for future authenticated work. If you
want a fresh install test, restore a clean VM snapshot and create a new token.

## Exit gate

Record pass/fail and evidence for: clean preflight, interactive branding,
enrollment, fresh heartbeat, service, tray icon, scanner readiness, restart
with same ID, **new-version** upgrade with same ID, uninstall cleanup, and
server-side revocation. Step 15 passes only after every item has been observed
on the disposable machine. Package diagnostics and simulated API tests do
not substitute for this lifecycle pilot.
