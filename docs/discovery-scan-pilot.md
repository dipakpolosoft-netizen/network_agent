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
least one device must expose a known open TCP port; select that device for
the host scan. The port must be covered by the chosen profile. `inventory`
checks Nmap's top 200 ports;
`standard` checks its top 1000. Neither is an all-port scan. Record any host
firewall rules or routing that may make an otherwise powered-on device
invisible.

Before this accuracy pilot, validate the known-device baseline separately:

```powershell
python .\scripts\check_pilot_plan.py .\docs\pilot-plan.local.json --mode accuracy
```

## 2. Discover one segment

Select the planned probe and the **selected** planned segment in **Network
Scanner**. Enter the two or three baseline IPs in **Known hosts to verify**,
confirm authorization, and start discovery once. This field is optional for
ordinary discovery but required for this first accuracy pilot.
Only missing named IPs receive a bounded TCP/ICMP follow-up; it is not a
port or vulnerability scan. Nmap's normal local-segment discovery may use
ARP, while the targeted pass explicitly uses IP probes
([Nmap host discovery](https://nmap.org/book/man-host-discovery.html)).
Do not interpret a non-response as proof a device is offline. Record the
method, reason, timestamp, and result for every known IP; a targeted recovery
is an initial-discovery miss that needs explanation.

Record the discovery ID, start/completion times, scope, progress events,
found count, error/partial status, and a screenshot of the resulting device
list. Wait for `completed`; do not rerun against other segments to hide a
missed baseline device. Compare each known IP, hostname if available,
MAC/vendor if available,
and device classification. Unknown hostname or device type is a review item,
not proof that the host is absent. Any unexpected device requires independent
confirmation before calling it a false positive.

If Nmap times out, complete host records already observed may still be saved.
The scope remains failed and the discovery is **partial**, not evidence of full
segment coverage. Review the initially observed versus recovered known-host
counts and keep no-response hosts as unconfirmed; investigate the timeout
before repeating the approved segment.

For the device-identity gate, compare the saved hostname, MAC, vendor, role
estimate, and last-seen time with independent records for known PCs,
servers, switches, routers, and firewalls across authorized pilots where
available. A MAC vendor is not
proof of a device role; a generic open web/SSH port or OS family is not
proof of a server. Record conflicting or missing clues as Unknown/uncertain
instead of forcing a type. Recheck one known device after a later scan to
confirm a weak result has not erased a stronger earlier identity.
If a DNS, NetBIOS, or SNMP lookup fails, the already discovered IP must remain
visible with its original discovery method and last-seen time; missing identity
fields and an Unknown role are preferable to losing the host record.

## 3. Scan one known target

Select **one** authorized, discovered non-probe device. Use the approved
`inventory` or `standard` profile and start the scan. Record scan ID,
progress/queue transitions, completion state, target IP, confirmed-open ports
and any `open|filtered` or filtered observations, service
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

Compare the probe shown in Scanner, Assets > Topology, Scan History, and the
report's scan-origin section. The saved JSON and PDF should name the same
probe ID, hostname, OS, version, queued-snapshot IP/subnet, and heartbeat as the
report. The live Scanner and Topology views may show a newer heartbeat or IP;
do not overwrite historical scan-origin facts with them. A legacy report
using the latest probe record must say that its scan-time IP is unverified.
The probe must not appear as a scanned asset or count as a target.

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

Without `--plan`, the command performs a structural audit. It checks
discovery/scan linkage, selected targets, out-of-scope IPs, duplicate port
rows, and whether the saved summary matches the raw port states, but **cannot**
say whether devices or ports were correctly
detected. With a valid plan, every `FAIL` and `REVIEW` needs investigation.
The evaluator requires a completed single-segment discovery and completed
single-target scan of the device with a known open TCP port. It checks all
known IPs, saved known-host outcomes when requested, the selected target's
expected open TCP ports, and summary counts
against raw `open`, `open|filtered`, and `filtered` port states. It also checks
the saved authorization flag, exact completed scope, and requested port plan;
it rejects a broadened or missing first-pilot plan. A report from
an API that predates those separate counters cannot pass this gate. If a known
port falls outside the selected profile, change the planned test target or obtain explicit authorization
for a different profile; do not silently broaden the scan.

For Step 9, compare one completed host result against the exact raw Nmap XML
saved on the same probe. Get the scan JSON from the report; find the selected
`device_id` in its `targets` and `results`. On that probe, run from the repo
root (substitute the scan and device IDs):

```powershell
.\agent_builder\.venv\Scripts\python.exe .\agent_builder\scripts\verify-host-evidence.py `
  --scan .\.tmp\forgesec-scan-<scan-id>.json `
  --xml "$env:ProgramData\ForgeSec\NetworkAgent\scans\<scan-id>\raw\<device-id>.xml" `
  --device-id "<device-id>"
```

The read-only verifier checks the XML SHA-256, selected IP, hostname source,
port states and fingerprints, OS estimates, and role estimate against the
exported result. For a one-target scan, it also checks the report's host and
port-state totals against that XML. New probe results include this fingerprint;
older results without it cannot pass this exact-byte check. The raw XML remains on the probe
and can contain sensitive service data. Run the check from an authorized
elevated shell if the installed probe's scan-data ACL blocks your account;
do not relax that ACL or commit XML to source control. A matching hash proves
the export corresponds to these XML bytes, not that Nmap identified the real
device or version correctly. Compare
important claims with the known-device baseline separately.

## Exit gate

Step 16 passes when the approved single segment completes, all baseline
devices are accounted for, the selected host's known test port is observed
or its discrepancy is resolved, the scan completes with matching target and
profile, the JSON/PDF and asset evidence agree, and progress/error states
are understandable. Record unresolved misses and classification uncertainty
as findings. A prior scan, even one with many results, cannot substitute for
this current authorized comparison.
