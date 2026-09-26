# Step 26: V1 architecture and scope decision (FS-ADR-001)

**Decision:** ForgeSec v1 uses a hybrid, site-scoped scanner architecture. This adopts the codebase's existing execution boundary; it is not a claim that a customer has approved installation or scanning. Obtain written approval for each deployment and target before activating a probe or worker. The v1 *full-suite release* includes validation of all three implemented central worker integrations. A customer may leave a worker unprovisioned when it has no authorized route or target, but must not present that customer's unavailable capability as working.

## Placement and network paths

| Component | Runs on | Executes or stores | Required path |
| --- | --- | --- | --- |
| Next.js UI and FastAPI control plane | Dedicated ForgeSec/customer deployment | Operator access, policy, jobs, reports | Trusted HTTPS for browsers, probes, and workers |
| PostgreSQL | Same protected customer deployment | Users, sites, probes, assets, reports, worker evidence, activity | Private API-to-database path only |
| Windows probe and tray | One or more approved customer Windows hosts | Connected-network discovery, selected host scans, local status | Outbound HTTPS to API; local route to approved targets |
| Licensed Nmap/Npcap OEM | Installed by the production probe setup | Probe-side host discovery and port/service scans | Runs locally with the probe, not in the API container |
| SNMPv2c/LLDP enrichment | Windows probe | Read-only device facts and observed physical neighbors | Approved UDP/161 access to discovered devices |
| NVD lookup | Central API | CPE-to-CVE candidate correlation and cache | Outbound provider access when an operator requests refresh |
| Nuclei worker | ForgeSec-managed central worker host | One bundled read-only HTTP-header check | HTTPS to API **and** direct route to observed target HTTP port |
| Greenbone worker and scanner | Separate managed central Linux infrastructure | Authorized uncredentialed, single-IP advanced assessment | HTTPS to API, protected GMP socket, and scanner-to-target route |
| SSH inventory worker | Separate managed central Linux host | Read-only Linux OS/package sample | HTTPS to API and direct SSH route to approved Linux target |

The probe's outbound HTTPS connection is **not** a tunnel or proxy for central workers. A worker that cannot route to the target must fail/appear unavailable; it must not infer a clean result. Do not silently move Greenbone, Nuclei, or SSH keys onto the customer probe. If a customer forbids Nmap/Npcap on the Windows host, or cannot provide an authorized route to a central scanner, this architecture does not meet that customer's full-suite requirement. A central-only design would require a separate reviewed VPN/routing or relay project before packaging.

## V1 operator workflow

1. An admin creates one customer's deployment and a site with written CIDR, exclusion, profile, and expiry approval. A site is an authorization boundary for jobs, **not** a tenant. Keep unrelated customers in separate API/database deployments.
2. The signed one-install Windows package installs the ForgeSec service/tray and licensed Nmap/Npcap. A site-bound one-time token enrolls the probe; its credential is DPAPI-protected locally and only a hash is stored by the API. The probe heartbeats and reports connected networks. It starts no scan automatically.
3. An operator chooses an approved connected segment. The API and probe recheck scope. The probe discovers reachable hosts and uploads bounded evidence. The operator reviews device identity and chooses targets; unknown hostname/OS/vendor remains unknown.
4. The probe scans only selected, approved devices. `inventory` checks the top 200 TCP ports, `standard` the top 1,000, `network_services` a fixed TCP/UDP set, and `full_tcp` attempts all TCP ports. `full_tcp` is not all-UDP or a guarantee of every open port. One probe runs at most three host Nmap processes concurrently. Progress, cancellation, partial/failure states, and actual observations are retained.
5. The API persists discoveries, scans, asset observations, reports, and activity in PostgreSQL for production. Local JSON mode is for development/pilots. The UI shows evidence-backed inventory, device depth, topology, Scan History, and JSON/PDF reports.
6. An operator may explicitly correlate observed service CPEs with NVD. A CVE match is a **candidate**, not proof of exploitability. A recent scanned asset may be submitted to the controlled Nuclei check, the admin-approved Greenbone assessment, or Linux SSH inventory only after its worker, route, scope, and target prerequisites pass. Greenbone keeps its full raw report; ForgeSec stores reduced findings.
7. Operators compare changes over time and validate findings with device owners. Probe and worker identities can be revoked. Uninstall removes local ForgeSec components but does not erase server-side evidence.

## Full-suite release boundary

The release candidate must demonstrate the Windows probe, approved discovery and selected scan, report/export, durable assets, SNMP/LLDP topology on suitable managed devices, NVD candidate correlation, the fixed Nuclei template, one controlled Greenbone single-IP run, and one read-only SSH inventory on an authorized Linux test host. Test these in a lab or approved pilot with known ground truth; do not broaden a real customer's scope just to satisfy a gate. Each central worker requires a real engine/host and target route. Automated fake-engine tests do not count as a live pilot. The Step 25 acceptance worksheet requires a `pass` evidence reference for each of the three worker integrations for the v1 full-suite release.

The release also requires per-customer HTTPS/PostgreSQL isolation, off-host backup and restore rehearsal, a licensed and signed one-install package, clean-machine install/upgrade/uninstall/revocation, security negative-path checks, and post-deploy hash/health verification. See [final acceptance](final-acceptance-release.md). Until these pass, code capability is **implemented but not production-accepted**.

## Explicit exclusions and change triggers

V1 does not promise discovery across unconnected routed networks, every host/port/UDP service, complete OS/software inventory, verified vulnerability status for every device, exploit execution, arbitrary Nuclei/NSE templates, credentialed Greenbone targets, SNMPv3/CDP/bridge-table topology, Windows WinRM inventory, Wazuh/osquery/NetBox integration, per-site user RBAC, MFA/SSO, shared-database multitenancy, or automatic remediation. Linux SSH inventory is a bounded sample, not patch-state proof. Keep one API worker per customer deployment under current scaling limits.

Reopen FS-ADR-001 before implementation if customer policy prohibits the probe's Nmap/Npcap installation, if a central-only scanner is required with no route, if Greenbone must run through the probe connection, if multiple customers must share a database, or if the release promise expands to the excluded capabilities. Such changes need a new security/network design and acceptance plan, not only a UI toggle.

**Step 26 done when:** this decision is the reference for the Step 27 release baseline and Step 25 full-suite acceptance gate. Site-specific approval, target routes, licenses, and real-machine results are deliberately left for later steps; no network scan or production deployment is performed here.
