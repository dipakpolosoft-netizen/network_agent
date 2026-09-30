# Step 14: Pilot baseline and authorization

Complete the authorization before scanning on a real network. Enrollment and
heartbeats may happen before approval, but they never authorize a scan. This
document and validator do not create a site, issue a token, or start discovery.
Keep the filled plan locally because site
names, device addresses, and approval references may be sensitive.

## 1. Confirm the pilot boundary

Choose one disposable Windows x64 VM or PC that can reach both the approved
local network and the ForgeSec API. Record its expected IPv4 address. Choose
one site name and owner. Obtain written authorization that identifies the exact
approved CIDR, excluded addresses, permitted profiles, approver, reference,
and expiry. Choose only one connected discovery segment with at most 256
addresses for the first test. Discovery does not cross a router automatically;
the selected segment must appear in the enrolled probe's reported options.
Individual excluded hosts or smaller CIDRs may be inside that segment; they must
be omitted from probe traffic and uploaded evidence. A segment whose usable
addresses are all excluded is not a valid discovery pilot. Verify exclusion
behavior with an approved packet capture, not only with an API rejection.

The `172.168.x.x` examples from earlier screenshots are **not** RFC1918 private
space; do not assume they are authorized. A public/nonprivate range needs
explicit approval and the application's public-range confirmation. Never infer
approval from an `ipconfig` output. Do not use `Scan all` or `full_tcp` for the
first baseline test.

For the later accuracy pilot, record two or three known devices on that segment: expected IP, device type,
and known TCP ports. At least one device must have a known open TCP port and
must be the target of the first scan. An empty port list for another device
means the port expectation is unknown, not that all ports are closed. Avoid
relying on vendor, hostname, or OS detection as a guaranteed result. Keep a separate note of any firewall or
host-discovery restrictions that could explain a missed device.
These two or three entries are comparison samples, not a discovery or scan limit.
For the authorization-only gate, use `"known_devices": []` until those facts
are available; do not fill it with made-up targets.

## 2. Fill and validate the local plan

From the repository root in PowerShell:

```powershell
Copy-Item .\docs\pilot-plan.example.json .\docs\pilot-plan.local.json
notepad .\docs\pilot-plan.local.json
python .\scripts\check_pilot_plan.py .\docs\pilot-plan.local.json
```

The default authorization check does not require `known_devices`; leave it
empty or omit it until the accuracy pilot. Before comparing discovery or scans
with reality, add the known devices and run:

```powershell
python .\scripts\check_pilot_plan.py .\docs\pilot-plan.local.json --mode accuracy
```

`pilot-plan.local.json` is ignored by Git. The validator uses only the local
file and standard-library IP/URL parsing; it sends no packets. `confirmed`
must become `true` only after the approval is recorded. For a separate probe
machine, `agent_api_url` must be its reachable HTTPS origin, never
`http://127.0.0.1:8000` on the server. The dashboard URL may be a local
loopback development URL for a browser on the server. No password or token
belongs in this file.

## 3. Record local release and service readiness

Check the published package metadata without installing it:

```powershell
Get-Content .\apps\web\public\downloads\agent\release.json
Get-FileHash .\apps\web\public\downloads\agent\ForgeSec-Network-Agent-Setup.exe -Algorithm SHA256
```

Compare the hash and size with `release.json`. A `development` package is
unsigned and does not install Nmap/Npcap; obtain those separately from their
official source for a development pilot. Do not represent it as a customer
one-install package. Use the [one-install pilot](one-install-pilot.md) for the
later production release gate.

The server's `GET /health` response is useful for a read-only API check. Test
the API URL **from the pilot machine** before enrollment, using normal TLS
certificate validation. A successful response from the server itself does not
prove the pilot machine can connect. The one-time enrollment token expires
quickly (15 minutes by default); generate it under the chosen site shortly
before Step 15, and keep it out of the plan file and shell history.

## Exit gate

The authorization gate passes only with a genuine written approval, the exact
CIDR and exclusions, a future expiry, and explicit public-range approval where
needed. The accuracy gate additionally needs two or three expected devices.
Create the site and exact approval in the UI before any network operation.
The probe-facing API URL must be reachable from the chosen Windows machine.
None of these checks authorizes a broader scan.
