# ForgeSec operating workflow

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

In **Network Scanner > Sites and approved networks**, create or select a site, then record the network owner, written approval reference, approver, UTC expiry date, exact CIDR, exclusions, and allowed profiles. Explicitly acknowledge public-range authorization where applicable. Enrollment and heartbeat do not require network approval, but discovery, diagnostics, scans, and central worker jobs do. Older scopes without these details show **Needs review** and cannot run jobs; expired scopes are also inactive until renewed. `full_tcp` is required for optional Greenbone and SSH inventory jobs. A scope removal blocks queued jobs and future lease renewal; it does not instantly undo traffic already sent by a running external scanner.

## 3. Enroll and check the probe

Use **Add probe** to create a one-time enrollment token for that site, download the published Windows installer, and install it on a Windows machine connected to the approved network. The probe needs Nmap and Npcap for discovery and host scans. Wait for its authenticated heartbeat and check its network, site, and tool posture in **Agent fleet**. A `401` heartbeat means the installed probe credential is not accepted; check enrollment/revocation and use a new token if needed, not a shared worker credential. For a first real-network comparison against known devices, use the [discovery and scan pilot](discovery-scan-pilot.md).

For customer one-install packaging and a controlled Windows pilot, follow the [release and pilot checklist](one-install-pilot.md). A development installer does not bundle the scanner dependencies.

The probe reports its own host and interface state in heartbeat data; remote device names, OS, and vendors are observations, not guaranteed complete facts. Installing one probe does not inventory every endpoint internally.

## 4. Discover and scan

In **Network Scanner**, choose the site and its online probe, then approve a connected network. Use **Discover selected** beside the approved scope; the confirmation dialog records the exact run boundary. Review discovered hosts, choose authorized targets, then select one of the profiles approved for every selected target's network. Unapproved choices are disabled. Start the scan from the target toolbar and watch or cancel it there. The [scan-profile reference](scan-profiles.md) gives the exact requested TCP/UDP coverage and timeouts. `full_tcp` is a separately confirmed, one-target all-TCP-port escalation; it is not an all-UDP scan or a guarantee of complete service detection.

Discovery stores host/IP, available MAC/vendor, hostname and SNMP clues, classification, latency, and first/last seen. A host scan stores observed ports, services/versions, OS guesses, and exposure flags. Firewalls, host policies, credentials, and routing affect visibility. Neither discovery nor a port scan guarantees that every device or vulnerability was found.

## 5. Review evidence and enrich an asset

Use **Scan History** for probe report progress, changes, and each run's JSON/PDF downloads. Queued, running, failed, and cancelled runs remain clearly labeled. Open a report to inspect its actual host evidence. **Assets** opens on the selected site and merges durable device identity and observations; its evidence history distinguishes a new observation from an older scan. An observed service CPE can be checked against central NVD data, but a version match remains a candidate until validated.

Each new discovery and scan keeps its site and probe identity from job creation. A completed discovery compares responding IPs only with a previous completed run of the same probe, site, scope, mode, and known-host checks. "Not observed this time" is not an offline verdict. Scan port and exposure changes require two complete runs with the same site, probe, profile, scan plan, and selected target IPs. Changing the selection or getting a partial result yields no scan baseline. The asset timeline links every saved scan observation to its report and shows per-device confirmed-open port changes against a comparable earlier result; incomplete results do not erase the last complete port sample. Older records without a saved site ID cannot be assigned to a site retroactively with certainty, so they do not qualify for these new comparisons or an asset backfill.

For optional central checks, open **Settings > Workers** as an administrator. Choose the site and **one** implemented capability, provision the worker, and copy its one-time ForgeSec credential. Deploy the corresponding central process using the [Nuclei](nuclei-worker.md), [Greenbone](greenbone-worker.md), or [SSH inventory](ssh-inventory-worker.md) runbook. Engine binaries, Greenbone installation, GMP credentials, and SSH private keys are configured **on the worker host**, never in the browser or probe. The worker must heartbeat online for its capability before the asset action is enabled.

From the asset drawer, an authorized operator can request a bounded Nuclei web check on an observed HTTP port. An administrator can request a single-host Greenbone assessment or read-only Linux SSH inventory when their stricter prerequisites are met. Watch progress and stop jobs from the asset. **Scan History > Central jobs** shows recent site jobs and links back to their asset evidence. Raw Greenbone reports remain in Greenbone; ForgeSec stores reduced findings. SSH inventory stores bounded OS/package facts, not a vulnerability verdict. The [finding review](finding-review.md) panel keeps these sources separate and records audited review dispositions.

## 6. Follow up and recover

Record the owner and criticality on important assets. Compare later scan reports for newly confirmed open ports, ports no longer confirmed open, and new/resolved exposure observations. `open|filtered` is ambiguous, not confirmed open. The probe's `--open` scans do not preserve closed-port evidence, so a missing previously open port is **not** proof it closed; a timeout or failed host scan is also not a clean result. Confirm suspected vulnerabilities with the authorized scanner and the system owner before remediation. ForgeSec records observation-level reviews but does not create tickets or automatically remediate; track implementation work in the organization's existing change system.

If a probe is lost, revoke it from **Agent fleet** and enroll a replacement. If a central worker credential is lost, revoke it in **Settings > Workers** and provision a new identity. Revocation prevents new authenticated work, but an in-flight external Greenbone task may need manual inspection in Greenbone if its worker crashed. Follow the [deployment backup instructions](deployment.md) for PostgreSQL and do not treat downloaded reports as the only copy of evidence.

For export contents, access, backup, uninstall, and deletion boundaries, follow the [evidence lifecycle](evidence-retention.md). JSON and PDF downloads fetch the current saved scan when clicked; a running scan can still change afterward.

## Verification

From the repository root, run the local verification script after installing dependencies and publishing the installer:

```powershell
.\scripts\verify-local.ps1
```

Use `-IncludeSmoke` when the API venv has the agent's runtime dependencies. The smoke test exercises enrollment, authenticated heartbeat, discovery, host scanning, and report storage with fixtures in a temporary data directory. Automated central-worker tests use fake engines/SSH; a real Greenbone or SSH run still requires a separate authorized test target and verified network route. Do not point a test at production infrastructure just to make the UI show a completed badge.

For Step 17's desktop/mobile operator acceptance path, use the [workflow validation checklist](operator-workflow-validation.md). It separates UI behavior from an approved field scan.
