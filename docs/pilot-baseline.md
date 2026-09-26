# Step 14: Pilot baseline and authorization

Complete this before installing or scanning on a real network. This step is
planning and read-only validation only; it does not create a site, issue an
enrollment token, or start discovery. Keep the filled plan locally because site
names, device addresses, and approval references may be sensitive.

## 1. Confirm the pilot boundary

Choose one disposable Windows x64 VM or PC that can reach both the approved
local network and the ForgeSec API. Record its expected IPv4 address. Choose
one site name and owner. Obtain written authorization that identifies the exact
approved CIDR, excluded addresses, permitted profiles, approver, reference,
and expiry. Choose only one connected discovery segment with at most 256
addresses for the first test. Discovery does not cross a router automatically;
the selected segment must appear in the enrolled probe's reported options.

The `172.168.x.x` examples from earlier screenshots are **not** RFC1918 private
space; do not assume they are authorized. A public/nonprivate range needs
explicit approval and the application's public-range confirmation. Never infer
approval from an `ipconfig` output. Do not use `Scan all` or `full_tcp` for the
first baseline test.

Record two or three known devices on that segment: expected IP, device type,
and any known TCP ports. An empty port list means the port expectation is
unknown, not that all ports are closed. Avoid relying on vendor, hostname, or
OS detection as a guaranteed result. Keep a separate note of any firewall or
host-discovery restrictions that could explain a missed device.

## 2. Fill and validate the local plan

From the repository root in PowerShell:

```powershell
Copy-Item .\docs\pilot-plan.example.json .\docs\pilot-plan.local.json
notepad .\docs\pilot-plan.local.json
python .\scripts\check_pilot_plan.py .\docs\pilot-plan.local.json
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

Step 14 is complete only when the filled plan passes validation, the written
authorization is on record, the chosen Windows machine and segment match,
two or three expected devices are recorded, and the probe-facing API URL is
reachable from that machine. Then create the site and exact approval in the UI,
and proceed to Step 15. None of these checks authorizes a broader scan.
