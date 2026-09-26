# Optional Linux SSH inventory worker (Step 11)

This worker is optional and runs on a **central Linux host**, not on each customer endpoint or in the Windows network probe. It uses a site-specific, read-only SSH account to collect one approved Linux host's OS release, kernel, architecture, hostname, and up to 200 installed package names and versions. It does not run arbitrary operator commands, use sudo, enumerate files or users, collect patches separately, or claim that a package is vulnerable. Windows/WinRM and SNMPv3 are not part of this mode.

The API accepts a job only when the asset has a completed host scan from the last 30 days with `22/tcp` observed open, the site's approved scope permits `full_tcp`, an SSH inventory worker for that site is online, and an administrator confirms authorization. At most one SSH inventory job can be queued or leased per site. Scope and source asset identity are checked again at claim, lease renewal, and result upload. The worker host must have a network route to the asset; the probe's outbound connection is not a tunnel.

## Set up the central worker

1. Create a dedicated non-root account on the authorized Linux targets. Grant only the read access needed for `/etc/os-release`, `uname`, `hostname`, and `dpkg-query` or `rpm`. Do not grant sudo or reuse a personal/admin key. Limit the SSH key to the site and rotate it under your normal secret-management process.
2. On the central Linux worker host, keep the private key outside the repository and readable only by the service account (`chmod 600`). Add the targets' **verified** SSH host keys under their IP addresses to a dedicated `known_hosts` file. Verify fingerprints through a trusted channel; do not blindly trust `ssh-keyscan` output. Unknown or changed host keys cause the worker to fail closed.
3. Provision a ForgeSec worker identity for the exact site using `POST /api/workers` with `capabilities: ["credentialed_inventory"]`. The [Nuclei runbook](nuclei-worker.md) has a PowerShell login/provisioning example; change its capability and label for SSH inventory. Store the one-time worker bearer credential in the service manager or secret manager. Do not place SSH keys, passwords, or host keys in the ForgeSec API or browser.
4. Install the optional client from `services/api` on the central Linux host:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install '.[ssh-inventory]'
```

5. Supply the site-specific settings and start the worker:

```bash
export FORGESEC_API_URL='https://your-forgesec-api.example'
export FORGESEC_WORKER_ID='<site-worker-uuid>'
export FORGESEC_WORKER_CREDENTIAL='<one-time-worker-credential>'
export FORGESEC_SSH_INVENTORY_USERNAME='forgesec-inventory'
export FORGESEC_SSH_INVENTORY_KEY_FILE='/run/secrets/forgesec-inventory-key'
export FORGESEC_SSH_INVENTORY_KNOWN_HOSTS='/etc/forgesec/known_hosts'
.venv/bin/python -m forgesec_api.workers.ssh_inventory_runtime
```

Run one identity and key per site. The worker connects only to the server-approved IP on port 22 and disables SSH-agent and default-key fallback. Its SSH library rejects unknown host keys. Do not expose the private key through a mounted web directory or application logs.

## Using the result

Open an asset with observed SSH under **Network Scanner > Assets**, confirm authorization, then choose **Collect inventory**. The drawer shows the job state and the bounded OS/package facts. **Stop** invalidates the job lease; the worker closes its SSH connection at its next check. An in-flight read-only command may finish first (up to its 15-second timeout). Raw SSH output and private key material are never uploaded. Only the normalized evidence is stored in `scanner-worker-jobs` (JSON in local mode, PostgreSQL in production).

Package data is a **sample of at most 200** entries and can be incomplete; the UI marks truncation. A successful SSH connection proves the configured account authenticated to the pinned host key, but it does not prove that every installed package or update was inventoried. Inventory is not itself a vulnerability finding. Do not turn package names into CVE claims without separate matching and verification.

The worker uses Paramiko's documented [SSH client host-key policy and key-file authentication](https://docs.paramiko.org/en/stable/api/client.html) and [bounded channel reads](https://docs.paramiko.org/en/stable/api/channel.html).
