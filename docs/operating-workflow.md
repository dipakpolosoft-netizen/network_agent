# ForgeSec operating workflow (Step 12)

This is the operator path through the current product. The Windows probe discovers and scans its **approved local network**. Optional Nuclei, Greenbone, and SSH inventory workers run on **central infrastructure** and need their own route to a selected target; the probe's outbound HTTPS connection is not a scan tunnel. Do not run discovery or checks without authorization for the exact site and network.

## 1. Start and sign in

Use the [deployment guide](deployment.md) to start the API and web app, bootstrap the first administrator, and configure HTTPS for non-loopback operator access. For local development, use separate PowerShell terminals:

```powershell
cd C:\Users\USER\Desktop\forge-sec-network-agent\network_agent\services\api
.\.venv\Scripts\python.exe -m uvicorn forgesec_api.main:app --host 127.0.0.1 --port 8000
```

```powershell
cd C:\Users\USER\Desktop\forge-sec-network-agent\network_agent\apps\web
npm run dev -- --hostname 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000/login`. If port 3000 is in use, use another port and open its URL. Local development persists under `services/api/runtime-data`; production uses PostgreSQL as described in [deployment](deployment.md).

## 2. Define a site and authorized scope

In **Network Scanner > Sites and approved networks**, create or select a site, then approve only the CIDR(s), exclusions, and scan profiles that the site owner authorized. `full_tcp` is required for optional Greenbone and SSH inventory jobs. A scope removal blocks queued jobs and future lease renewal; it does not instantly undo traffic already sent by a running external scanner.

## 3. Enroll and check the probe

Use **Add probe** to create a one-time enrollment token for that site, download the published Windows installer, and install it on a Windows machine connected to the approved network. The probe needs Nmap and Npcap for discovery and host scans. Wait for its authenticated heartbeat and check its network, site, and tool posture in **Agent fleet**. A `401` heartbeat means the installed probe credential is not accepted; check enrollment/revocation and use a new token if needed, not a shared worker credential. For a first real-network comparison against known devices, use the [discovery and scan pilot](discovery-scan-pilot.md).

For customer one-install packaging and a controlled Windows pilot, follow the [release and pilot checklist](one-install-pilot.md). A development installer does not bundle the scanner dependencies.

The probe reports its own host and interface state in heartbeat data; remote device names, OS, and vendors are observations, not guaranteed complete facts. Installing one probe does not inventory every endpoint internally.

## 4. Discover and scan

In **Network Scanner**, select the online probe and an approved scope. Start discovery and watch its progress. Review the discovered hosts, choose authorized targets, select a scan profile, and start a host scan. `full_tcp` is a focused all-TCP-port option and may take substantially longer than `standard`; use it selectively. Scan jobs can be cancelled from the scanner.

Discovery stores host/IP, available MAC/vendor, hostname and SNMP clues, classification, latency, and first/last seen. A host scan stores observed ports, services/versions, OS guesses, and exposure flags. Firewalls, host policies, credentials, and routing affect visibility. Neither discovery nor a port scan guarantees that every device or vulnerability was found.

## 5. Review evidence and enrich an asset

Use **Scan History** for probe report progress, changes, and JSON/PDF downloads. Open a report to inspect its actual host evidence. **Assets** merges durable device identity and observations; use an asset's evidence history to distinguish a new observation from an older scan. An observed service CPE can be checked against central NVD data, but a version match remains a candidate until validated.

For optional central checks, open **Settings > Workers** as an administrator. Choose the site and **one** implemented capability, provision the worker, and copy its one-time ForgeSec credential. Deploy the corresponding central process using the [Nuclei](nuclei-worker.md), [Greenbone](greenbone-worker.md), or [SSH inventory](ssh-inventory-worker.md) runbook. Engine binaries, Greenbone installation, GMP credentials, and SSH private keys are configured **on the worker host**, never in the browser or probe. The worker must heartbeat online for its capability before the asset action is enabled.

From the asset drawer, an authorized operator can request a bounded Nuclei web check on an observed HTTP port. An administrator can request a single-host Greenbone assessment or read-only Linux SSH inventory when their stricter prerequisites are met. Watch progress and stop jobs from the asset. **Scan History > Central jobs** shows recent site jobs and links back to their asset evidence. Raw Greenbone reports remain in Greenbone; ForgeSec stores reduced findings. SSH inventory stores bounded OS/package facts, not a vulnerability verdict.

## 6. Follow up and recover

Record the owner and criticality on important assets. Compare later scan reports for opened/closed ports and new/resolved exposure observations. Confirm suspected vulnerabilities with the authorized scanner and the system owner before remediation. This release does not have a ticketing, exception, or automatic remediation engine; track decisions in the organization's existing change system.

If a probe is lost, revoke it from **Agent fleet** and enroll a replacement. If a central worker credential is lost, revoke it in **Settings > Workers** and provision a new identity. Revocation prevents new authenticated work, but an in-flight external Greenbone task may need manual inspection in Greenbone if its worker crashed. Follow the [deployment backup instructions](deployment.md) for PostgreSQL and do not treat downloaded reports as the only copy of evidence.

## Verification

From the repository root, run the local verification script after installing dependencies and publishing the installer:

```powershell
.\scripts\verify-local.ps1
```

Use `-IncludeSmoke` when the API venv has the agent's runtime dependencies. The smoke test exercises enrollment, authenticated heartbeat, discovery, host scanning, and report storage with fixtures in a temporary data directory. Automated central-worker tests use fake engines/SSH; a real Greenbone or SSH run still requires a separate authorized test target and verified network route. Do not point a test at production infrastructure just to make the UI show a completed badge.
