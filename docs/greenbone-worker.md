# Separate Greenbone advanced worker (Step 10)

Greenbone is an **optional, separate central scanner installation**. ForgeSec does not install Greenbone/OpenVAS on customer endpoints, package it in the Windows probe, or embed it in the API container. The Windows probe supplies recent host-scan evidence; an administrator can then request an advanced assessment of **one asset IP** from the asset drawer. Greenbone's own scanner must have an authorized network route to that IP. The customer's outbound-only probe connection is not a tunnel.

The API requires a completed host scan within 30 days, an approved site scope allowing `full_tcp`, an online `greenbone_assessment` worker for that site, and explicit authorization plus maintenance-window confirmation. Only one Greenbone assessment can be queued/running per site. Nuclei workers cannot claim these jobs. Scope and asset identity are rechecked at claim, lease renewal, and result upload. This is an active vulnerability scan and may load the target; use an audited Greenbone scan configuration and an approved maintenance window.

## Central worker setup

1. Deploy and maintain Greenbone on a **central Linux host**. The [Greenbone Community Containers guide](https://greenbone.github.io/docs/latest/22.4/container/) is suitable for a lab pilot but explicitly says it is not intended as a production setup; choose and operate a production-suitable installation before the v1 full-suite release. Verify feed sync, scanner health, backup/update ownership, and a working `gvmd` Unix socket. The worker must be able to access that socket, commonly `/run/gvmd/gvmd.sock`; use controlled socket permissions or a protected volume mount, not a world-writable socket or a publicly exposed GMP port.
2. In Greenbone, choose and record the UUIDs for an audited **scan config**, scanner, and port list. ForgeSec does not let an operator choose arbitrary Greenbone configurations from the browser. Set up a dedicated least-privilege GMP user. Do not add SSH/SMB/SNMP target credentials to this worker; it creates uncredentialed single-IP targets.
3. Provision a ForgeSec worker for the exact site with **only** `greenbone_assessment`. Use the admin API flow in [scanner workers](scanner-workers.md) or the PowerShell provisioning example in [the Nuclei runbook](nuclei-worker.md), changing the capability to `greenbone_assessment`. Store the returned one-time credential in the worker host's secret manager.
4. Install the optional Python client on the Greenbone worker host, from `services/api` or from a built ForgeSec API wheel:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install '.[greenbone]'
```

5. Supply these variables from your service manager or secret store, then start the worker:

```bash
export FORGESEC_API_URL='https://your-forgesec-api.example'
export FORGESEC_WORKER_ID='<provisioned-worker-uuid>'
export FORGESEC_WORKER_CREDENTIAL='<one-time-worker-credential>'
export FORGESEC_GREENBONE_SOCKET='/run/gvmd/gvmd.sock'
export FORGESEC_GREENBONE_USERNAME='<dedicated-gmp-user>'
export FORGESEC_GREENBONE_PASSWORD='<gmp-password>'
export FORGESEC_GREENBONE_CONFIG_ID='<audited-scan-config-uuid>'
export FORGESEC_GREENBONE_SCANNER_ID='<scanner-uuid>'
export FORGESEC_GREENBONE_PORT_LIST_ID='<port-list-uuid>'
.venv/bin/python -m forgesec_api.workers.greenbone_runtime
```

For a non-loopback API, the worker requires HTTPS with normal certificate verification. The host running `gvmd`/OpenVAS needs reachability to the customer IP; test that route before requesting a scan. Do not place the Greenbone scanner on the customer's machine merely to make the UI button available.

## Operation and evidence

In **Assets > asset > Advanced assessment**, administrators confirm the host and maintenance window, then select **Run advanced scan**. The worker uses the official `python-gvm` GMP client to create or reconnect to a task named after the ForgeSec job, with a single-IP target, the fixed configured port list/config/scanner, and no target credentials. It polls progress and renews its ForgeSec lease. The job has a five-hour deadline and the worker stops waiting after four hours. **Stop** cancels the ForgeSec job; on the next lease check (up to about 30 seconds, plus an in-flight GMP call), the worker requests Greenbone `stop_task`. The site has a two-minute cooldown before another advanced job can be queued. A worker crash or unreachable `gvmd` can leave a task running; administrators should inspect Greenbone for tasks named `ForgeSec advanced <job-id>` and stop any orphaned task there.

The worker fetches the exact Greenbone report ID and uploads at most 50 reduced findings (name, severity, port, NVT OID, CVE IDs, result ID, and target host). The API rejects out-of-scope hosts, malformed data, duplicate result IDs, and oversized evidence. ForgeSec does **not** upload the raw Greenbone XML report, credentials, or scanner configuration. The result is displayed separately from Nuclei checks and the probe report. If more than 50 findings exist, the UI says so; inspect the full report in Greenbone. Greenbone owns raw-report retention and feed management; ForgeSec stores the reduced job result in PostgreSQL, or `services/api/runtime-data/scanner-worker-jobs` in local JSON mode.

The integration uses Greenbone's documented [GMP task and report methods](https://greenbone.github.io/python-gvm/api/gmpv227.html) and [Unix socket connection](https://greenbone.github.io/python-gvm/api/connections.html). Greenbone's [container workflow](https://greenbone.github.io/docs/latest/22.4/container/workflows.html) explains how to expose the `gvmd` socket to a trusted local client.
