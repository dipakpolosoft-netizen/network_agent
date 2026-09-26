# Central scanner workers

This is a site-bound control-plane contract for scanner processes running on ForgeSec-managed infrastructure. It does **not** install scanner engines on a customer's endpoint or move the Windows probe's Nmap into the API container. There are three separate central adapters: the controlled [Nuclei web-check worker](nuclei-worker.md), the optional [Greenbone advanced worker](greenbone-worker.md), and the optional [Linux SSH inventory worker](ssh-inventory-worker.md). The existing probe workflow continues to run as before.

Use the [Step 20 central-worker validation](central-worker-validation.md) for host preflight and controlled live pilot gates.

## Identity and scope

An administrator can provision an implemented single-capability worker under **Settings > Workers**, or use `POST /api/workers` with one existing site and a capability. The protocol also accepts reserved `network_inventory` and `service_fingerprint` capabilities, but there is no bundled runtime for them. Implemented processes use `vulnerability_assessment`, `greenbone_assessment`, or `credentialed_inventory`. The response contains a random bearer credential **once**. Store it in the worker host's secret manager, not in source control or browser storage. The server retains only its hash. `GET /api/workers` lists status without credentials; `POST /api/workers/{worker_id}/revoke` invalidates a credential and releases active leases. A new identity must be provisioned to replace a revoked worker.

Workers connect **outbound** through the probe-facing HTTPS ingress. Do not expose the FastAPI HTTP port publicly. The credential is separate from probe credentials and operator sessions. An operator cannot provision or revoke a worker without the admin role and a valid CSRF token.

## Protocol

| Endpoint | Purpose |
| --- | --- |
| `POST /worker/heartbeat` | Report worker ID, version, and the subset of provisioned capabilities currently available. |
| `GET /worker/jobs/next` | Claim one eligible site-bound job, or receive HTTP 204. |
| `POST /worker/jobs/{job_id}/heartbeat` | Renew the five-minute lease using its `lease_id`. |
| `POST /worker/jobs/{job_id}/result` | Submit `completed` or `failed`, a short summary, and JSON evidence up to 256 KiB. |
| `GET /api/worker-jobs` | List central job state without raw evidence; filter by `site_id` or `asset_id`. |
| `POST /api/worker-jobs/nuclei` | Operator queues a check for a recently scanned asset and observed HTTP port. |
| `POST /api/worker-jobs/greenbone` | Administrator queues a single-host advanced assessment. |
| `POST /api/worker-jobs/inventory` | Administrator queues read-only SSH inventory for an observed Linux SSH host. |
| `POST /api/worker-jobs/{job_id}/cancel` | Administrator stops a queued or leased Greenbone or SSH inventory job. |
| `GET /api/worker-jobs/{job_id}` | View bounded, validated worker evidence. |

Each job has schema version `1.0`, site, capability, immutable target IP, approved profile, attempt count, deadline, and lease ID. The server checks CIDR exclusions and profile approval before queueing, claim, renewal, and result acceptance. A worker cannot claim another site's job or an unreported capability. Expired leases can be retried up to three times. A repeated identical result for a completed lease returns the stored outcome; a stale or foreign lease is rejected.

The Nuclei worker is deliberately limited to one bundled, read-only HTTP header template. Greenbone runs as a distinct, explicitly configured advanced worker and is not bundled with ForgeSec. The SSH inventory worker uses a separate site-specific key and pinned host keys, with no credential material in jobs or reports. Merely provisioning a worker does not scan the network. The scanner host needs direct network reachability to the target; an outbound-only customer probe does not grant that reachability by itself.

For local development without `FORGESEC_DATABASE_URL`, worker records and raw job evidence are JSON files beneath `services/api/runtime-data/scanner-worker*`. In production they use PostgreSQL's `forgesec_documents` table; activity is recorded in `forgesec_activity`.
