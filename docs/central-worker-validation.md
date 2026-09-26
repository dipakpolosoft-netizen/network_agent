# Step 20: Validate central workers

Run this on the **central worker hosts** after the production control plane and the selected worker engines are deployed. The Windows probe is not a worker host and its outbound connection is not a tunnel to customer targets. Greenbone and SSH inventory are optional; record them as **not deployed/not tested** unless a real pilot is completed. Keep all target IPs within a written site approval. Do not run this procedure against an arbitrary production device just to turn a UI status green.

## 1. Automated baseline

From `services/api`, run the API lint and the focused contract/adapter tests:

```powershell
.\.venv\Scripts\python.exe -m ruff check --no-cache src tests
.\.venv\Scripts\python.exe -m pytest -q tests\test_worker_flow.py tests\test_nuclei_worker.py tests\test_greenbone_worker.py tests\test_ssh_inventory_worker.py tests\test_worker_preflight.py
```

These tests exercise worker identity, site/capability restrictions, queue and lease behavior, cancellation/revocation, bounded evidence, the fixed Nuclei template, Greenbone task/report handling with a fake GMP client, and SSH read-only commands with a fake SSH client. They do **not** establish that Nuclei, Greenbone feeds, a Linux SSH account, or routes to a customer's subnet work in the field.

## 2. Worker-host preflight

Install the ForgeSec API wheel on each worker host with the needed optional extra, then inject the site-bound worker ID and credential from a secret manager. Never put the credential in the repository, a screenshot, or this validation record. Use the same `FORGESEC_API_URL` that the worker will use; remote hosts require trusted HTTPS.

On each worker host, run exactly the applicable command with its worker virtual environment:

```text
python -m forgesec_api.workers.check_runtime --worker nuclei
python -m forgesec_api.workers.check_runtime --worker greenbone
python -m forgesec_api.workers.check_runtime --worker ssh
```

`--offline` skips the read-only `GET /health` check while preparing a host. The preflight validates the API origin and worker ID without sending the credential, confirms the Nuclei binary/template or the Greenbone socket/client or the SSH key/known-hosts/client, and checks API TLS reachability. It does **not** authenticate the worker, test a target route, start an engine, or claim a job. A pass is readiness to attempt a controlled pilot, not evidence of a completed assessment.

For Step 30 production deployment, run the online preflight from each actual worker host against the customer-specific HTTPS origin. A remote API reporting `development` is rejected. Install and audit the selected worker dependencies on that host; the optional Greenbone and SSH extras are not yet represented by a hashed production lockfile. Record the worker-host OS, Python/engine versions, API origin, site and capability, certificate trust, and direct route to the approved target **without** putting credentials or target secrets in a release log. Do not mark a worker deployed solely because an identity was created or this preflight passed.

## 3. Nuclei web-check pilot

Use one recently scanned, approved asset with one observed HTTP port and a known test web service. Provision one site-bound `vulnerability_assessment` identity. Confirm a direct route from the **Nuclei worker host** to that exact IP and port, plus outbound HTTPS to ForgeSec. Start `forgesec_api.workers.nuclei_runtime` under the service account and confirm the worker becomes online with only that capability. In **Assets > Web checks**, confirm authorization and queue the one fixed header check. Record the job ID, exact target origin, template ID, final status, and expected presence/absence of `X-Content-Type-Options`. Check that the result is a bounded configuration observation and does not claim a CVE. A failed network route is not a negative finding.

## 4. Greenbone advanced pilot

Only on a central Linux host with a healthy Greenbone installation: verify feed sync, a protected `gvmd` Unix socket, a dedicated GMP account, audited scan-config/scanner/port-list UUIDs, and a scanner-to-target route. Provision a `greenbone_assessment` identity for one approved site and use one recently scanned asset whose site permits `full_tcp`. Obtain a maintenance window and explicit authorization before queueing **one IP** in **Assets > Advanced assessment**. Confirm exactly one matching `ForgeSec advanced <job-id>` task in Greenbone, progress and lease renewal in ForgeSec, bounded results for only that IP, and the full raw report retained in Greenbone. On a separate disposable test, cancel a job and verify Greenbone stops the task; inspect and stop any orphan manually. Record feed timestamp, Greenbone task/report IDs, job ID, result count, truncation, and stop outcome. Do not add target credentials to this integration.

## 5. SSH inventory pilot

Only on a central Linux host: use one dedicated read-only site account, a private key with mode `0600`, and an independently verified host key pinned under the target IP in `known_hosts`. Confirm the central host can reach the approved Linux asset on port 22 and that a recent ForgeSec host scan observed SSH open. Provision one `credentialed_inventory` identity for that site, start `forgesec_api.workers.ssh_inventory_runtime`, and queue **Collect inventory** for that asset. Record the job ID, target IP, OS/kernel/hostname, package-manager type, package count (maximum 200), truncation state, and audit entry. Check that no SSH key, raw command output, or arbitrary operator command appears in the job evidence. Test unknown/changed host-key rejection only against a disposable authorized target; do not alter a production host key for this check.

## 6. Cross-worker and exit gates

For every deployed worker, confirm its site and capability in **Settings > Workers**, a current heartbeat, one correctly scoped completed job, and evidence stored in PostgreSQL. Confirm a wrong-site or unapproved-profile request is rejected, an expired/changed source asset cannot be completed, and revocation invalidates the worker identity after the pilot. The automated tests cover those negative paths; repeat the relevant ones live only in a controlled test site. Stop/revoke pilot identities when no longer needed.

Record **pass**, **fail**, or **not tested** separately for Nuclei, Greenbone, and SSH inventory, with worker version, engine version, site, authorized target, route, job ID, result, and any cancellation/orphan outcome. Step 20 is not complete for a selected worker until its real host and approved target have been exercised. Do not equate a green preflight, simulated test, or online heartbeat with a successful customer-network scan.
