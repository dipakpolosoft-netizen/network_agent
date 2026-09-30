# Durable asset inventory

The **Assets** view keeps one site-scoped record per observed device identity across
discoveries and host scans. It is historical inventory, not a live reachability
monitor. `Last observed` means the latest positive probe evidence, not "online now".

## How records are built

1. The API accepts a validated discovery result from an enrolled probe. Each
   non-probe device becomes one observation linked to its discovery and site.
2. An uploaded host scan adds an observation linked to its scan report. The
   latest successful scan contributes OS and a bounded sample of open services.
   Failed scans remain in the timeline but do not make a new asset or refresh
   `Last observed`.
3. Repeated uploads of the same source/device do not create another observation.
   At startup, existing discoveries and scan results are imported once after
   legacy probes receive site assignments. A restarted backfill is idempotent.
4. Operators can set a display name, owner, criticality, and tags. New evidence
   updates observed fields without replacing those manual annotations.

Identity resolution first uses a normalized MAC **within the same site**. Without
a known MAC match, it uses the latest IP in that site. A different MAC at a reused
IP creates a separate asset, while a known MAC can move to another IP and retain
its asset ID and bounded IP history. MAC-less hosts and MAC randomization remain
ambiguous; review those records before treating them as unique physical devices.
All-zero, broadcast, and multicast MACs are treated as unknown rather than stable
identity keys, so they cannot merge unrelated IPs into one asset.
Neither vendor nor hostname alone is used as a stable identity.

## Storage and access

Records live in the API's `assets`, `asset-observations`, `asset-mac-index`,
`asset-ip-index`, and `asset-migrations` collections. These use PostgreSQL JSONB
when `FORGESEC_DATABASE_URL` is set, or files beneath
`services/api/runtime-data` for local JSON mode. There is no automatic inventory
retention or deletion policy yet. Back up the database or runtime data with the
scan records. Observed fields can be rebuilt from saved evidence, but manual
ownership, criticality, display names, and tags cannot.

`GET /api/assets` supports `site_id`, `query`, `limit`, and `offset`.
`GET /api/assets/{asset_id}` returns one asset, and
`GET /api/assets/{asset_id}/observations` pages its evidence timeline.
The timeline compares confirmed-open ports only between complete results for
the same asset IP, probe, profile, and saved port plan. A partial or failed
result stays visible but does not replace that comparison baseline. A MAC can
keep one asset identity across an IP move; the move itself does not imply that
ports opened or closed. Older scans without a saved port plan remain visible,
but cannot establish a trustworthy port-change baseline. "No longer confirmed"
means a port was absent from the later observation, not that it was proven
closed by a `--open` scan.
`PATCH /api/assets/{asset_id}` changes only manual annotations. With operator
authentication enabled, viewers cannot patch; operators and admins can. Current
user roles are global, not restricted to individual sites.

The current central scanner worker interface stores its own raw evidence. That
evidence is **not** normalized into Assets until a scanner adapter and ingestion
contract are implemented. The Windows probe remains the source of discovery and
host-scan inventory in this step.

## Step 10 field check

After written scope approval, discover one authorized segment and scan one known
target. Set an asset display name and owner, then repeat the same approved scan
with the same probe, IP, profile, and saved port plan. In **Assets**, confirm the
same asset ID, unchanged manual annotations, separate timeline entries, and a
port delta that agrees with both scan reports. A missing port is only **no
longer confirmed**, not proven closed. A partial or failed host result must
remain in history without replacing the latest complete port snapshot. If the
target's IP genuinely changes, confirm its known MAC retains the asset ID but
does not compare ports across the two IPs. Do not create network changes just
to exercise this check.
