# ForgeSec deployment

## Local development

Create the first administrator once, using an interactive password prompt rather than a command-line argument. Skip the bootstrap command if an administrator already exists:

```powershell
cd services\api
.\.venv\Scripts\python.exe -m forgesec_api.auth.bootstrap
```

Start the API:

```powershell
cd services\api
.\.venv\Scripts\python.exe -m uvicorn forgesec_api.main:app --host 127.0.0.1 --port 8000
```

Start the web app in another terminal:

```powershell
cd apps\web
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000/login`. With no `FORGESEC_DATABASE_URL`, local state remains in `services/api/runtime-data`, including users and sessions. Authentication is enabled by default; set `FORGESEC_AUTH_REQUIRED=false` only for isolated test development.

If the existing local development administrator password is lost, stop the API first, then run `cd services/api` and `./.venv/Scripts/python.exe -m forgesec_api.auth.recover_admin --email admin@forgesec.local` from the repository root. The command refuses production or PostgreSQL storage, displays the resolved JSON store, and asks for an explicit confirmation before prompting for a new 12+ character password without echoing it. Restart the API afterward. It invalidates the administrator's old sessions but leaves sites, probes, and scan evidence intact. This is host-local recovery, not a dashboard password-reset feature.

Before discovery, open **Network Scanner** and create or select a site under **Sites and approved networks**. Approve the exact connected CIDR (typically a `/24` segment), optionally add excluded hosts and allowed scan profiles, then create a probe enrollment token for that site. Existing probes are migrated to a site on API startup but receive no automatic network approval. An excluded host cannot be scanned; if an exclusion overlaps a whole discovery segment, that segment is not discoverable. Use the probe's reported network and your organization's written authorization when choosing CIDRs.

The current published installer must be rebuilt and republished after changing probe source. The API enforces site policy even for older enrolled probes, but the new probe-side preflight check exists only in a newly built installer.

Device CVE correlation uses the official NVD API when an operator clicks
`Check CVEs` for an observed service CPE or starts a scan-report assessment.
Report assessments are saved centrally and can be read without an NVD request.
Results are cached in the central store for 24 hours. The
public NVD allowance works for occasional local lookups; for repeated use, set an
NVD API key before starting the API:

```powershell
$env:FORGESEC_NVD_API_KEY = '<your-nvd-api-key>'
```

`FORGESEC_NVD_CACHE_TTL_SECONDS` and `FORGESEC_NVD_TIMEOUT_SECONDS` optionally
control cache age and request timeout. CVE matches are version-based candidates,
not proof that a vulnerability is exploitable on the scanned device.
See [central vulnerability intelligence](vulnerability-intelligence.md) for
assessment freshness, limits, and storage.

## Local network access

The recommended LAN layout exposes only the Next.js dashboard. Browser API requests
use the dashboard's same-origin `/api` proxy, while FastAPI remains bound to
`127.0.0.1:8000` on the server.

Start both development services on the detected LAN address:

```powershell
cd C:\path\to\forgesec
.\scripts\start-lan.ps1
```

Open an Administrator PowerShell once and allow dashboard port 3000 only from the
connected network:

```powershell
.\scripts\enable-lan-firewall.ps1
```

The script works on Public or Private Windows network profiles but restricts the
rule to the detected interface address and subnet. It disables broad inbound
Node.js application rules before adding the port-specific ForgeSec rule. To
restrict access to one management computer, pass its IP with `-RemoteAddress`.

```powershell
.\scripts\enable-lan-firewall.ps1 -RemoteAddress 172.168.1.25
```

Stop the development services with:

```powershell
.\scripts\stop-lan.ps1
```

Do not enter operator credentials over a plain-HTTP LAN connection. Use an HTTPS reverse proxy or VPN endpoint and set `FORGESEC_WEB_ORIGIN` to that exact HTTPS origin. The API refuses password access on a non-loopback HTTP origin. The LAN scripts remain useful for isolated probe and network testing, not for remote password sign-in.

## Production control plane

Use a dedicated Docker host with a real DNS hostname, PostgreSQL storage, and HTTPS. The optional `docker-compose.production.yml` overlay adds Caddy on ports 80/443. It routes `/agent/*`, `/worker/*`, `/health`, and `/ready` to the API; dashboard and same-origin `/api/*` requests go to Next.js. API and web host ports remain loopback-only; PostgreSQL has no published port. Caddy's public certificate flow needs DNS and port 80/443 reachability from the certificate authority, including renewal; do not block that path with an allowlist that includes only operators and probes. If access must stay private, use a trusted enterprise certificate/ingress instead of this automatic-certificate overlay and adapt the Compose preflight to that ingress. Windows probes must trust the certificate and hostname. Do not expose the control plane broadly merely to obtain a certificate.

1. On the deployment host, copy `.env.example` to `.env` **only if `.env` does not already exist**. Keep it out of source control and restrict access. Set a unique `FORGESEC_CUSTOMER_ID` and `FORGESEC_COMPOSE_PROJECT` for this customer, plus `FORGESEC_PUBLIC_HOST=scan.your-real-domain.com`, `FORGESEC_WEB_ORIGIN=https://scan.your-real-domain.com`, and `NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL=https://scan.your-real-domain.com`. Keep `FORGESEC_BIND_ADDRESS=127.0.0.1`, `FORGESEC_API_PROXY_URL=http://api:8000`, and `NEXT_PUBLIC_FORGESEC_API_URL=` empty. Set a unique 16+ character `FORGESEC_POSTGRES_PASSWORD` and `FORGESEC_DATABASE_URL=postgresql://forgesec:<URL-encoded-password>@postgres:5432/forgesec`. If desired, set `FORGESEC_NVD_API_KEY` for central CVE lookups. No password or API key belongs in Git. See [customer isolation and scale](multi-customer-scale.md) before onboarding a second customer.
2. From the repository root, check the resolved configuration. This prints no secrets and starts no containers. The normal gate requires a non-default Compose project, a non-placeholder database password, and legacy-data adoption disabled. For a reviewed one-time legacy adoption, start only the API with that flag after a verified backup; turn it off and rerun this gate before starting the full stack:

```powershell
python .\scripts\check_production_config.py
```

3. For a **new empty deployment**, start PostgreSQL, build the API and web images, create the first administrator interactively, then start the HTTPS stack:

```powershell
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d postgres
docker compose -f docker-compose.yml -f docker-compose.production.yml build api web
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm -it api python -m forgesec_api.auth.bootstrap
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
docker compose -f docker-compose.yml -f docker-compose.production.yml ps
```

Do not rerun bootstrap when users already exist. Do not use `docker compose down -v`; that removes database and certificate volumes. A production update is `docker compose -f docker-compose.yml -f docker-compose.production.yml up --build -d` after a verified backup. The web image embeds the public probe URL at build time, so rebuild it when the hostname changes.

For a pre-Step-24 store without a customer binding, startup now refuses to claim the data automatically. After verifying a backup and ownership of the entire store, set `FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA=true` for one startup and then return it to `false`. Never use that flag to label a database containing multiple customers.

4. From an operator machine, check DNS and HTTPS, then sign in at `https://scan.your-real-domain.com/login`:

```powershell
Resolve-DnsName scan.your-real-domain.com
Test-NetConnection scan.your-real-domain.com -Port 443
Invoke-RestMethod https://scan.your-real-domain.com/health
Invoke-RestMethod https://scan.your-real-domain.com/ready
python .\scripts\smoke_production.py --base-url https://scan.your-real-domain.com
python .\scripts\smoke_production.py --base-url https://scan.your-real-domain.com --operator-email admin@your-real-domain.com --expected-role admin
python .\scripts\smoke_production.py --base-url https://scan.your-real-domain.com --operator-email operator@your-real-domain.com --expected-role operator
python .\scripts\smoke_production.py --base-url https://scan.your-real-domain.com --operator-email viewer@your-real-domain.com --expected-role viewer
```

The first smoke command uses normal TLS verification and confirms API health, database-backed readiness, login-page delivery, and that unauthenticated operator/agent requests are rejected. Each role command prompts for that account's password without putting it in shell history; it checks sign-in, the secure session cookie, authenticated account access, the returned role, user-management access (admin only), and sign-out. Create separate operator and viewer accounts with the administrator first. Run the smoke checks from a separate trusted operator machine and a second Windows pilot machine. Neither command enrolls a probe. `/ready` returns only `ready` or `unavailable` and the API container healthcheck uses it; `/health` alone does not verify PostgreSQL. Alert on repeated `/ready` failures, unhealthy containers, certificate renewal failures, backup failures, and stale probe heartbeats. Restrict log and monitoring access because operational metadata is sensitive. Check that the HTTPS certificate is trusted on the Windows pilot machine. Sign in with the bootstrapped administrator, generate a site-bound enrollment token in the UI, and confirm it shows the same HTTPS URL. Test one probe enrollment and heartbeat before any approved discovery. Keep `FORGESEC_ALLOW_PUBLIC_SCOPES=false`. The dashboard proxies `/api` to `http://api:8000` internally, while probe and central-worker machine paths go directly through HTTPS to the API. Do not publish port 8000 or enter credentials over plain HTTP LAN access.

The smoke checker rejects redirects instead of following them and requires the operator session cookie to be Secure, HttpOnly, SameSite=Strict, and host-scoped by name. A failed Compose preflight reports required setting **names**, never their values. Do not paste `.env`, database URLs, passwords, or backup archives into a ticket or chat.

Do not mark this gate complete based on Compose preflight or localhost checks alone. Record the deployment hostname, customer ID, exact image/commit, certificate issuer and expiry, PostgreSQL volume and backup schedule, and dated smoke results from both client machines. Check that only 80/443 are reachable from approved clients; API/web loopback ports and PostgreSQL must not be remotely exposed. Verify an admin can manage users, an operator cannot, and a viewer cannot launch jobs. Record the actual test accounts used without storing their passwords.

**Step 20 status (2026-09-29):** local production-tooling tests passed (32 tests), and customer-binding/PostgreSQL pool checks passed (6 passed, 1 skipped). Backup and restore-check now require an expected customer slug, and restore-check reports success only after the checksum, restored binding, row-count query, and isolated-container cleanup pass. These were mocked tooling tests, not a real backup or restore. The current `.env` does not pass Compose preflight; at least `FORGESEC_POSTGRES_PASSWORD`, `FORGESEC_DATABASE_URL`, and `FORGESEC_CUSTOMER_ID` need deployment-specific values. No production stack, external HTTPS smoke, scheduled alert, encrypted off-host backup, or live restore rehearsal was performed. Step 20 remains open until those checks are recorded on the designated host and approved by the deployment owner.

### Backup and restore rehearsal

After the database contains data, make a custom-format `pg_dump` archive in a restricted, encrypted, off-host-backed location. The script streams bytes without PowerShell text redirection and prints a SHA-256 hash:

```powershell
python .\scripts\production_backup.py backup --output-dir 'D:\ForgeSecBackups' --expected-customer-id '<customer slug from FORGESEC_CUSTOMER_ID>'
python .\scripts\production_backup.py restore-check 'D:\ForgeSecBackups\forgesec-YYYYMMDDTHHMMSSZ-xxxxxxxx.dump' --expected-sha256 '<SHA-256 printed by backup>' --expected-customer-id '<same customer slug>'
```

Use the actual archive path, digest, and the deployment's customer slug. Backup checks the live database's customer binding before `pg_dump`; restore-check verifies the same binding in the restored archive. Neither accepts an unbound or different-customer store. The script does **not** encrypt the dump: encrypt it with your approved backup tooling before off-host transfer, then decrypt it only on a separate, access-controlled restore host. Run `restore-check` there against the copied plaintext archive and the original SHA-256. The command rejects a missing or mismatched digest before starting Docker. It starts a temporary PostgreSQL 17 container with no published ports or network, restores the archive, checks ForgeSec schema and row counts, then removes that temporary container. A cleanup failure is a failed rehearsal requiring manual inspection; the command does **not** overwrite production. Schedule backups, off-host transfer, retention, and failure alerts externally; this command is on-demand, not an automated backup service. Record a successful off-host restore rehearsal, digest, row counts, and recovery time before go-live. Treat every archive as sensitive: it contains users, probe credential hashes, inventory, and scan evidence. Keep one API worker until remaining single-process assumptions are removed.

### Import existing JSON data

For an existing JSON deployment, stop the old API and back up its entire runtime directory or Docker volume first. Start only PostgreSQL. If the JSON files are on the Windows host, mount their **actual** directory read-only into the one-off import container, then run the import once against an empty database:

```powershell
$oldData = (Resolve-Path 'C:\path\to\network_agent\services\api\runtime-data').Path
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d postgres
docker compose -f docker-compose.yml -f docker-compose.production.yml build api web
docker compose -f docker-compose.yml -f docker-compose.production.yml run --rm --volume "${oldData}:/import:ro" api python -m forgesec_api.migrate_json --source /import
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

If the old JSON files are already in the Compose `forgesec-runtime` volume, use `--source /var/lib/forgesec` instead of the read-only mount. The import preserves probe credential hashes, site approvals, scans, and reports. It refuses a nonempty destination and leaves JSON files untouched. Existing imported users mean **do not** run administrator bootstrap again. Check records and roles after import, then back up PostgreSQL and rehearse restore. PostgreSQL is now the source of truth for scans, assets, CVE assessments, and NVD cache entries; the runtime volume may still contain legacy cache files.

### Operator access

Admins can add, disable, and re-enable users at `/network-agent/users`. Operators may run approved discovery, diagnostics, and scans; viewers can inspect data but not launch jobs. Every signed-in user can change their password under **Settings > Account**, which invalidates earlier sessions. Sessions expire after `FORGESEC_SESSION_TTL_SECONDS` (default 12 hours). Roles are global; per-site membership, MFA, SSO, and self-service admin password reset are not implemented in this milestone. The local development recovery command above is not available for production PostgreSQL deployments.

## Windows agent release

Development packaging, which excludes OEM dependencies and code signing:

```powershell
cd agent_builder
.\scripts\release.ps1 -Development
```

Production packaging requires the licensed `installer\dependencies\nmap-oem.exe` package, which includes Npcap OEM, a Windows SDK `signtool.exe`, and a code-signing certificate in the Windows certificate store. Pin the licensed binary's supplier-verified SHA-256 before building:

```powershell
$env:FORGESEC_NMAP_OEM_SHA256 = '<supplier-verified-sha256>'
$env:FORGESEC_SIGN_CERT_SHA1 = '<certificate-thumbprint>'
.\scripts\release.ps1 -ExpectedCommit '<reviewed-40-character-git-sha>'
```

The release command lints and tests the agent, builds and signs `ForgeSecAgent.exe`, compiles and signs the Inno installer, runs package diagnostics, writes a SHA-256 release manifest under `agent_builder\dist\installer`, then publishes `ForgeSec-Network-Agent-Setup.exe` and `release.json` into the web public directory.

Follow the [one-install pilot](one-install-pilot.md) before distributing the setup. The development build is unsigned and does not bundle Nmap/Npcap, so it is not a customer one-install package.

The installer supports interactive enrollment and silent deployment:

```powershell
.\ForgeSec-Network-Agent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SERVERURL=https://forgesec.example /ENROLLMENTTOKEN=<one-time-token>
```

Existing DPAPI enrollment is retained during upgrades. To force a fresh local enrollment during development or redeployment, pass `/RESETAGENTDATA=1` with a new one-time token:

```powershell
.\ForgeSec-Network-Agent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESETAGENTDATA=1 /SERVERURL=http://127.0.0.1:8000 /ENROLLMENTTOKEN=<one-time-token>
```

### Probe connection security

The probe connects outbound to the API. Non-loopback server URLs require HTTPS with normal certificate and hostname verification; HTTP redirects are not followed. Enrollment tokens are single-use and site-bound. After enrollment, the probe stores its bearer credential under Windows DPAPI, and the API stores only its SHA-256 hash. New probes rotate that credential every 30 days. A replacement is staged locally before the rotation request, so the probe can recover if the server accepts the request but its response is lost. Previously enrolled credentials remain valid on the server until upgraded probes rotate; the new ForgeSec token prefix does not invalidate them.

An administrator can select a probe under **Network Scanner > Agent fleet** and choose **Revoke**. Revocation immediately invalidates its credential, stops future authenticated commands and uploads, and cancels queued jobs. It does not uninstall the probe or interrupt a scan already executing locally at that instant. To reconnect a revoked installation, create a new enrollment token and reinstall with `/RESETAGENTDATA=1` (or uninstall and reinstall). Revocation is recorded in the activity log with the administrator and reason.

This milestone uses HTTPS plus rotating bearer credentials, **not mTLS**. Mutual TLS requires a managed probe CA, certificate issuance/renewal/revocation, and an ingress that verifies client certificates. Do not treat the current bearer token as a client certificate. Keep the API private behind a trusted HTTPS ingress and never disable server certificate validation on the probe.

The separate [central Nuclei worker](nuclei-worker.md) can run the approved web-header check. The optional [Greenbone advanced worker](greenbone-worker.md) controls an existing central Greenbone installation. The optional [SSH inventory worker](ssh-inventory-worker.md) collects read-only Linux OS and package facts with a site-specific key kept on the central worker. All require a direct route from the worker to the selected target; none changes the downloadable Windows probe.

Uninstall removes the service, program files, Start Menu entry, Run key, and `%ProgramData%\ForgeSec\NetworkAgent`.
