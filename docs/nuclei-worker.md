# Controlled central Nuclei worker

The Windows probe still discovers hosts and scans ports. For an asset with a successful host scan in the last 30 days, an operator can open **Asset inventory > asset > Web checks** and request one check of an observed open HTTP port. The API verifies the site, approved network and scan profile, source asset/IP, live worker, and authorization confirmation before queueing. It rechecks scope and source identity when the worker claims and completes the job. The worker runs **one bundled, read-only GET template** that reports a missing `X-Content-Type-Options` header. It does not run arbitrary Nuclei templates, exploit checks, CVE scans, or Greenbone.

The worker runs on a ForgeSec-managed Windows or Linux host, not on the customer endpoint. It needs outbound HTTPS to the API **and direct network reachability to the target IP and port**. The customer probe's outbound connection is not a tunnel. If the central worker cannot route to a private customer subnet, the job will fail; use an explicitly authorized network path before trying it.

## Setup

1. Install a trusted [Nuclei release](https://github.com/projectdiscovery/nuclei/releases) on the **central worker host** and record the absolute path to the binary. Nuclei is not bundled with the Windows agent or API package. Keep this host and its Nuclei version patched.
2. Start the ForgeSec API and web app. Sign in as an administrator. The target site must exist with an approved scope/profile, and the asset must have a recent scan showing an open HTTP port.
3. Provision a site-bound worker identity with only `vulnerability_assessment`. The credential is returned once; store it in the worker host's secret manager. For a local development setup, this PowerShell session can provision it:

```powershell
$apiUrl = 'http://127.0.0.1:8000'
$webOrigin = 'http://127.0.0.1:3000'
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$email = Read-Host 'Admin email'
$password = Read-Host 'Admin password'
$login = Invoke-RestMethod -Uri "$apiUrl/api/auth/login" -Method Post -WebSession $session -ContentType 'application/json' -Headers @{ Origin = $webOrigin } -Body (@{ email = $email; password = $password } | ConvertTo-Json)
$sites = Invoke-RestMethod -Uri "$apiUrl/api/sites" -WebSession $session
$sites | Select-Object site_id, name
$siteId = Read-Host 'Site ID for this worker'
$worker = Invoke-RestMethod -Uri "$apiUrl/api/workers" -Method Post -WebSession $session -ContentType 'application/json' -Headers @{ 'X-CSRF-Token' = $login.csrf_token } -Body (@{ site_id = $siteId; label = 'Central web checks'; capabilities = @('vulnerability_assessment') } | ConvertTo-Json)
$env:FORGESEC_WORKER_ID = $worker.worker_id
$env:FORGESEC_WORKER_CREDENTIAL = $worker.credential
$password = $null
$worker = $null
```

4. On the worker host, set `FORGESEC_API_URL`, `FORGESEC_WORKER_ID`, `FORGESEC_WORKER_CREDENTIAL`, and `FORGESEC_NUCLEI_BINARY` from your secret/configuration system. Use HTTPS for any non-loopback API URL, with normal certificate verification. For a same-machine development test, in the provisioning terminal:

```powershell
$env:FORGESEC_API_URL = 'http://127.0.0.1:8000'
$env:FORGESEC_NUCLEI_BINARY = 'C:\Tools\nuclei\nuclei.exe'
cd C:\Users\USER\Desktop\forge-sec-network-agent\network_agent\services\api
.\.venv\Scripts\python.exe -m forgesec_api.workers.nuclei_runtime
```

5. Wait for `GET /api/workers` to show the worker online, then open an asset with an observed HTTP port, select the port/protocol, confirm authorization, and press **Run web check**. The drawer polls the job and shows its bounded result. Stop the worker with Ctrl+C; revoke its identity with `POST /api/workers/{worker_id}/revoke` if the credential is lost.

The worker invokes Nuclei with only the bundled template, JSONL output, redirects and Interactsh disabled, rate limit 2 requests/second, concurrency 1, five-second request timeout, zero retries, and a 120-second process limit. It does not pass the API credential to the Nuclei child. The API accepts only findings from the fixed template on the exact approved origin. At most eight web jobs can be pending per site. Raw HTTP responses and arbitrary Nuclei output are not uploaded.

Before starting the Nuclei child for a claimed job, the worker renews its lease against the API. If that renewal detects a cancelled, revoked, or unreachable lease, the child does not start. The normal lease checks continue while the child runs, and the worker forces another renewal after Nuclei exits, before parsing evidence or making a follow-up HTTP request. Cancellation can still race with a request already in flight. This does not turn the worker connection into a network tunnel or remove the need for the worker host to reach the target directly.

If Nuclei returns no finding, the worker makes one direct, five-second GET to the same IP, port, and scheme: a 2xx response with `X-Content-Type-Options` is required before saving a zero-finding result. Unreachable, redirected, non-2xx, TLS-invalid, or header-missing responses fail the check rather than implying a clean target. A Stop request invalidates the lease; the worker requests lease revalidation every 10 seconds while Nuclei runs and terminates the child when the lease is lost. API timeouts can delay acknowledgement.

Worker identities, jobs, and reduced evidence live in PostgreSQL for container deployments, or `services/api/runtime-data/scanner-worker*` in local JSON mode. The result is separate from probe scan reports and the [NVD/CPE intelligence](vulnerability-intelligence.md); a missing security header is a configuration observation, not proof of a CVE or compromise.

Nuclei flag behavior is documented by [ProjectDiscovery](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md). The bundled check follows the structure of [ProjectDiscovery's HTTP header templates](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/http-missing-security-headers.yaml).

## Step 13 field gate

The code and mocked tests do not constitute a live Nuclei pilot. On a central host with Nuclei installed, record the exact binary version and run `python -m forgesec_api.workers.check_runtime --worker nuclei` under the service account. Obtain written approval for one recently scanned web asset and its exact IP, TCP port, and protocol; confirm that the worker host has a direct route to it. Run one check against a known service with and one without `X-Content-Type-Options`, comparing the saved observation with the owner's HTTP response. Then test a deliberately unavailable approved target or controlled route failure: the job must say failed, not completed with zero findings. Stop a queued and a running test job and confirm neither accepts a late result. Record the site, worker ID, job IDs, target, route, timestamps, screenshots, and pass/fail outcome. Do not broaden scope or claim Step 13 field-validated until these checks pass.
