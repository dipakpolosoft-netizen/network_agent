# ForgeSec architecture

The [v1 architecture and scope decision](v1-architecture-scope.md) is the release contract for tool placement and full-suite acceptance. This page describes the current component design.

## Runtime components

ForgeSec has the Next.js operator interface, FastAPI control plane, PostgreSQL database in container deployments, one native Windows probe service per authorized site/network, and a per-user tray companion. The probe makes outbound HTTP(S) requests only. Nmap and Npcap run on the Windows probe, never in the web or API containers. Closing the tray does not stop the service.

The control plane also has a separate, site-bound **central scanner worker interface**. Administrators provision worker identities and permitted capabilities; workers heartbeat, poll for approved jobs, renew short leases, and upload bounded evidence. A server-side [Nuclei process](nuclei-worker.md) can run one bundled HTTP header check against an observed HTTP port. A separate optional [Greenbone worker](greenbone-worker.md) can control an existing central Greenbone installation for an admin-approved single-host assessment. An optional [SSH inventory worker](ssh-inventory-worker.md) reads Linux OS and package facts using a site-specific key held only on the central worker. None of these add a heavy scanner to the Windows probe; probe discovery and scans remain unchanged.

Human operators sign in with revocable server-side sessions. The first administrator is created interactively; admins can add operators and read-only viewers. Passwords use salted PBKDF2-HMAC-SHA256, and mutating dashboard API requests require a session CSRF token. Roles are global to this control plane, not yet per-site or per-organization. Probe identity is separate: the dashboard creates a short-lived, single-use enrollment token, the probe exchanges it for a random machine credential, and only a hash of that credential is stored by the API. The Windows probe protects its credential with DPAPI.

For multiple customers, the supported boundary is a [separate bound deployment and database per customer](multi-customer-scale.md). A customer label is checked at startup but is not an in-app tenant permission. Do not share one control plane among unrelated customers.

## Data flow

1. An operator creates a site, records its owner, and approves exact CIDRs, exclusions, and allowed scan profiles. An enrollment token is bound to that site.
2. Setup installs licensed Npcap/Nmap packages when they are absent, writes a protected bootstrap file, installs one Windows service, and starts it.
3. The service consumes the token, stores its DPAPI-protected machine credential, and sends heartbeats.
4. The probe reports connected discovery segments. Only segments contained in the site's saved approval are selectable. After explicit authorization, the API queues discovery for the selected segment or approved segments (up to 16).
5. The probe checks the command's scope policy before running Nmap and uploads discovered hosts. The operator selects non-probe devices.
6. The API resolves those stable device IDs to immutable IP targets and queues one scan job.
7. One scheduler runs up to three Nmap child processes concurrently and uploads progress and evidence-based results. The API also checks policy when creating diagnostics and scan jobs and again before dispatching queued commands.

## Storage and limits

For local development without `FORGESEC_DATABASE_URL`, the API stores atomic JSON files beneath `services/api/runtime-data`. With a PostgreSQL URL, the same collections are persisted in a transactional JSONB document table and activity in an append-only event table. The database is the source of truth for users, sessions, sites, approvals, agents, discoveries, scans, and commands. The runtime directory then holds only local caches. The migration command imports existing JSON into an empty PostgreSQL database without deleting the source. Run one API worker until a later storage/schema pass removes all single-process assumptions. The probe scan concurrency is three.

Worker identities, credential hashes, jobs, leases, and evidence use the same central store in separate `scanner-worker*` collections. A worker can claim only a job for its bound site and a capability it has reported available. Scope and profile approval are checked when queued, claimed, and renewed/completed; engine jobs also require current asset/scan identity. A five-minute lease can be retried up to three times. Nuclei jobs have a one-hour deadline; Greenbone jobs have a five-hour deadline; SSH inventory jobs have a 15-minute deadline. Evidence is reduced to validated finding or inventory sets and displayed in the asset drawer, separate from probe scan reports.

The [durable asset inventory](asset-inventory.md) merges saved discovery and host-scan evidence by site-scoped MAC, then current IP when MAC is unavailable. It preserves observation history and operator annotations separately from raw discovery/scan reports. Central worker evidence is not ingested into assets yet.

The [LLDP topology](topology.md) projects site-scoped physical-neighbor observations from successful probe SNMP enrichment. It does not infer links from shared subnets or port scans, and unmatched or aged evidence is labeled explicitly.

The [central vulnerability intelligence](vulnerability-intelligence.md) service correlates observed open-port CPEs with NVD and stores evidence-bound scan assessments and provider cache entries in the same central store. Report reads are local; only explicit operator refreshes call the provider when a lookup is not fresh in cache. It does not run a vulnerability scanner.

Existing enrolled probes are assigned to a site at API startup, but their networks are not automatically approved. Removing an approval blocks new jobs and cancels queued commands on dispatch. A command already claimed by a probe is not remotely stopped by changing policy; use the job's Cancel action as well. Site ownership is still a label, not a per-site permission boundary. MFA, SSO, and organization isolation remain future work.

No exploit execution, credential attacks, brute force, or aggressive NSE scripts are part of this product. Device classification and exposure flags are observations based on scan evidence, not vulnerability claims.
