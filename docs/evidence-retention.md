# Scan exports and evidence lifecycle

## What an export contains

History and the report page request `GET /api/scans/{scan_id}` when JSON or PDF is clicked. They do not export an older dashboard polling snapshot. The authenticated API returns the current saved scan, including its site and probe identity, selected targets, scan state, profile plan, host results, port evidence, rollups, changes, and recommendations. JSON preserves that API response. The branded PDF is a readable rendering of it, not a complete machine-readable substitute: the change table shows at most 20 entries per category and the service mix shows at most 12. Use JSON for exact stored detail. A running scan is explicitly a partial-in-time export; download again after completion for final evidence. A download failure does not produce an empty file.

The report page and PDF mark queued, running, cancelling, partial, failed, and cancelled coverage as incomplete. A completed status with failed, cancelled, or missing target results also carries that warning. If the report page loses its API connection after loading, it labels the visible content as the last loaded snapshot and offers Retry; export still fetches fresh saved evidence or fails. Long probe and host identity fields wrap in the PDF instead of being silently shortened.

JSON retains the API's original timestamp strings. The PDF renders timestamps in UTC, and the report page shows the operator's local time with its timezone label. Compare instants, not the displayed clock hour alone.

The report does not include raw Nmap XML, raw Greenbone reports, or every central-worker record. ForgeSec keeps reduced worker results separately. Greenbone controls retention of its own raw reports.

## Access and storage

Scan reads require a signed-in operator when `FORGESEC_AUTH_REQUIRED` is enabled; viewer, operator, and admin roles can read and export. API responses use `Cache-Control: private, no-store`. Browser downloads are copies on the operator's computer and must be handled as sensitive customer data. The application cannot revoke or delete a previously downloaded copy. Do not put exported reports, credentials, or backups in source control or a public download folder.

Production evidence belongs in the PostgreSQL control-plane database. Development JSON storage is under the configured API `runtime_data_dir`, including `scans`, `discoveries`, `assets`, asset observations/reviews, worker jobs, and activity. Back up the whole store, not just `scans`, to preserve relationships and history. The production backup command and isolated restore rehearsal are in [deployment.md](deployment.md). An on-demand backup is not a scheduled or off-host backup.

## Retention and deletion policy

ForgeSec currently has **no automatic evidence expiration, pruning job, or operator Delete button**. Historical server evidence remains until an explicitly approved storage migration or customer-data disposition is implemented. This is a behavior statement, not a recommendation to keep customer data forever. Before production use, the customer data owner must record a retention period, legal-hold procedure, backup retention, deletion authority, and destruction evidence in their operating policy. Do not set a time-to-live on the database or erase directories to simulate a retention policy: scans, assets, observations, comparisons, reviews, and worker jobs reference one another.

Probe uninstall removes the local service, tray, identity, logs, and state under `%ProgramData%\ForgeSec\NetworkAgent`. It does **not** call a server delete endpoint or erase scans. Administrators should revoke the probe credential after uninstall; queued work can then become cancelled, while old scan records remain accessible. To retire a customer's server data, first stop new collection, verify customer ownership and legal holds, take a protected backup, determine all dependent records and backups, obtain approval, and use a separately reviewed deletion/migration procedure. There is no self-service server-evidence deletion in v1.

## Verification gate

1. On an authorized test scan, download JSON and compare scan ID, status, targets, port states, timestamps, and origin with a fresh `GET /api/scans/{scan_id}`. Download PDF and compare the readable totals and host evidence with the same response. Repeat after the scan finishes; do not compare two different progress snapshots.
2. Confirm a signed-out request is rejected and that an authorized viewer can read but not mutate evidence. Use the [security boundary gate](security-boundary-validation.md) for cross-customer access.
3. In a disposable pilot, uninstall and revoke the probe. Confirm local cleanup, the server's revoked/offline probe state, and continued access to historical scan, asset, and activity records. Queued scans may transition to cancelled.
4. Restore an off-host production backup in an isolated environment and compare record counts and sample report IDs. Do not claim retention or recovery is production-accepted until the policy and this restore evidence are recorded.

## Step 18 local verification (2026-09-29)

- Web typecheck and report/export tests passed. Test scans cover fresh JSON export, PDF identity and port-state counts, incomplete coverage wording, wrapped metadata, and a service row continued across pages.
- Rendered the 128-target fixture PDF and the partial/long-text fixtures. The report title, ForgeSec logo, origin, status, table headings, continuation labels, and page footers remained readable. A table heading no longer lands alone at the end of a page.
- Mocked browser checks at 320px, 390px, and 1440px showed no report-page horizontal overflow. A partial scan displayed incomplete coverage instead of a "Clean" verdict; a simulated API outage labeled the visible report stale, and Retry recovered.
- PDF fixture timestamps with an explicit source offset now render as UTC; a rendered 128-target first page showed readable date, probe, and summary fields. A mocked report-page check showed its local timezone label and no horizontal overflow at 320px, 390px, and 1440px. Web typecheck and 23 local tests passed.
- These checks used fixtures, not a customer scan. The authorized JSON/PDF-to-API comparison, viewer access, uninstall/revocation history check, and production backup restore in the verification gate remain open.
- The customer data owner has not supplied a retention duration, hold procedure, backup retention period, deletion authority, or destruction evidence. Automatic deletion and a Delete button remain intentionally absent.
