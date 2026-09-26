# Step 16: Discovery and scan accuracy pilot

Run this only after the [approved pilot baseline](pilot-baseline.md) passes
validation and the [agent lifecycle pilot](agent-lifecycle-pilot.md) has an
enrolled, online Windows probe. The first test uses **one** connected,
approved segment of at most 256 addresses and **one** known non-probe target.
The comparison script reads saved JSON only; it sends no network traffic.

## 1. Check the starting state

Confirm in **Network Scanner > Agent fleet** that the probe belongs to the
planned site, its reported local IP/connected network include the planned
discovery segment, its heartbeat is online, and Nmap/Npcap are ready. Under
**Sites and approved networks**, compare the exact CIDR, exclusions, and
profiles to `docs/pilot-plan.local.json`. Do not turn on `Scan all` or approve
a broad network simply to make a segment selectable. A public/nonprivate
range needs its separate written approval and UI confirmation.

Choose two or three known devices with confirmed IPs for the baseline. At
least the device selected for the host scan should expose a known TCP port
covered by the chosen profile. `inventory` checks Nmap's top 200 ports;
`standard` checks its top 1000. Neither is an all-port scan. Record any host
firewall rules or routing that may make an otherwise powered-on device
invisible.

## 2. Discover one segment

Select the planned probe and the **selected** planned segment in **Network
Scanner**. Confirm authorization and start discovery once. Record the
discovery ID, start/completion times, scope, progress events, found count,
error/partial status, and a screenshot of the resulting device list. Wait for
`completed`; do not rerun against other segments to hide a missed baseline
device. Compare each known IP, hostname if available, MAC/vendor if available,
and device classification. Unknown hostname or device type is a review item,
not proof that the host is absent. Any unexpected device requires independent
confirmation before calling it a false positive.

## 3. Scan one known target

Select **one** authorized, discovered non-probe device. Use the approved
`inventory` or `standard` profile and start the scan. Record scan ID,
progress/queue transitions, completion state, target IP, open ports, service
names and versions, OS guesses, and any errors. Do not treat service versions,
OS guesses, CPE/CVE matches, or device role as verified facts without
independent confirmation. If the selected host times out or a known port is
missing, preserve the result and investigate profile coverage, target
firewall, routing, and scan logs before changing settings.

Open the finished report in **Scan History** and check that the target,
profile, counts, JSON download, PDF download, and asset observation agree
with the evidence. Test cancellation only on another separately authorized
small job; record whether its final state and report clearly show partial or
cancelled work. Do not use `full_tcp`, Greenbone, or broad multi-segment jobs
for this first accuracy gate.

## 4. Compare saved evidence offline

Download the scan JSON from its report. For discovery JSON, open the signed-in
dashboard URL `/api/discoveries/<discovery-id>` and save the JSON response.
The record must contain `discovery_id` at its top level. In local JSON mode,
the same record is available under
`services/api/runtime-data/discoveries/<discovery-id>.json`; production
PostgreSQL does not provide that filesystem shortcut. Keep exported evidence
in a local protected folder, not source control.

From the repository root, with actual paths substituted:

```powershell
.\services\api\.venv\Scripts\python.exe .\scripts\evaluate_pilot_scan.py `
  --plan .\docs\pilot-plan.local.json `
  --discovery .\.tmp\pilot-discovery.json `
  --scan .\.tmp\forgesec-scan-<scan-id>.json
```

Without `--plan`, the command performs only a structural audit. It checks
discovery/scan linkage, selected targets, out-of-scope IPs, and result
consistency, but **cannot** say whether devices or ports were correctly
detected. With a valid plan, every `FAIL` and `REVIEW` needs investigation.
The evaluator requires a completed single-segment discovery and completed
single-target scan, checks all known IPs, and checks the expected open TCP
ports of the scanned target. If a known port falls outside the selected
profile, change the planned test target or obtain explicit authorization
for a different profile; do not silently broaden the scan.

## Exit gate

Step 16 passes when the approved single segment completes, all baseline
devices are accounted for, the selected host's known test port is observed
or its discrepancy is resolved, the scan completes with matching target and
profile, the JSON/PDF and asset evidence agree, and progress/error states
are understandable. Record unresolved misses and classification uncertainty
as findings. A prior scan, even one with many results, cannot substitute for
this current authorized comparison.
