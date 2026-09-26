# Step 22: Unified asset evidence

The Assets drawer reads `GET /api/assets/{asset_id}/evidence`. This endpoint
joins saved host-scan observations, scan-bound NVD snapshots, and completed
Nuclei/Greenbone jobs by **asset ID, site ID, source scan, and target**. It does
not initiate a scan or contact NVD. Failed, cancelled, queued, and running jobs
appear as run states, never as findings. The latest successful SSH inventory
appears as host facts, not vulnerability findings.

Each signal retains its source, timestamp, source ID, scan-report link,
classification, severity, and `current` flag. `current` means linked to the
asset's latest recorded scan and IP. It does **not** mean the device is online,
the result has been recently revalidated, or that a vulnerability was exploited.
Saved NVD matches also become historical if the scan's CPE/service fingerprint
has changed. The operator can filter by source and reveal historical results.

Four classifications stay separate:

* Host-scan exposure signals are local heuristic/rule results.
* NVD CVEs are potential product/version correlations, not confirmed findings.
* Nuclei results are observations from the approved fixed web-header template.
* Greenbone results are scanner findings that still require operator validation.

The response is capped at 20 scan observations, 20 worker jobs, and 200 signal
items. `truncated` also signals partial NVD lookup/top-match output or bounded
Greenbone evidence. Full scan evidence remains in its scan report; full raw
Greenbone reports remain in Greenbone. The asset drawer's **Assessment tools**
expansion retains the existing authorized worker launch, stop, and history
controls. This step does not add exploit verification, package-to-CVE matching,
automatic remediation, or a deduplicated vulnerability ticket lifecycle.
