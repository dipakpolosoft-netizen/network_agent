# Telesec deployment

## Local development

Start the API:

```powershell
cd services\api
.\.venv\Scripts\python.exe -m uvicorn telesec_api.main:app --host 127.0.0.1 --port 8000
```

Start the web app in another terminal:

```powershell
cd apps\web
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

Open `http://127.0.0.1:3000/network-agent`.

Device CVE correlation uses the official NVD API only when an operator clicks
`Check CVEs` for an observed service CPE. Results are cached for 24 hours. The
public NVD allowance works for occasional local lookups; for repeated use, set an
NVD API key before starting the API:

```powershell
$env:TELESEC_NVD_API_KEY = '<your-nvd-api-key>'
```

`TELESEC_NVD_CACHE_TTL_SECONDS` and `TELESEC_NVD_TIMEOUT_SECONDS` optionally
control cache age and request timeout. CVE matches are version-based candidates,
not proof that a vulnerability is exploitable on the scanned device.

## Local network access

The recommended LAN layout exposes only the Next.js dashboard. Browser API requests
use the dashboard's same-origin `/api` proxy, while FastAPI remains bound to
`127.0.0.1:8000` on the server.

Start both development services on the detected LAN address:

```powershell
cd C:\path\to\telesec
.\scripts\start-lan.ps1
```

Open an Administrator PowerShell once and allow dashboard port 3000 only from the
connected network:

```powershell
.\scripts\enable-lan-firewall.ps1
```

The script works on Public or Private Windows network profiles but restricts the
rule to the detected interface address and subnet. It disables broad inbound
Node.js application rules before adding the port-specific Telesec rule. To
restrict access to one management computer, pass its IP with `-RemoteAddress`.

```powershell
.\scripts\enable-lan-firewall.ps1 -RemoteAddress 172.168.1.25
```

Stop the development services with:

```powershell
.\scripts\stop-lan.ps1
```

Local v1 has no human login. Every computer allowed by this firewall rule can use
the dashboard, so do not expose port 3000 to the internet or an untrusted network.

## Container deployment

Docker runs only the web and API services:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
docker compose ps
```

Both published ports bind to `127.0.0.1` by default. A Windows agent on the same computer can use `http://127.0.0.1:8000`. To connect agents from another machine, expose the API only through an approved HTTPS reverse proxy, VPN, or private ingress, set `NEXT_PUBLIC_TELESEC_API_URL` and `TELESEC_WEB_ORIGIN` to the externally valid addresses, rebuild the web image, and keep `TELESEC_ALLOW_PUBLIC_SCOPES=false`.

For dashboard-only LAN access through Docker, set `TELESEC_BIND_ADDRESS=0.0.0.0`.
The web container proxies `/api` to `http://api:8000`; the API host port remains
loopback-only.

Do not scale the API beyond one process while JSON storage is in use. To back up, stop the API and archive the `telesec-runtime` volume. Restore the complete volume before restarting; do not merge individual collection files from different backups.

## Windows agent release

Development packaging, which excludes OEM dependencies and code signing:

```powershell
cd agent_builder
.\scripts\release.ps1 -Development
```

Production packaging requires the licensed `installer\dependencies\nmap-oem.exe` package, which includes Npcap OEM, a Windows SDK `signtool.exe`, and a code-signing certificate in the Windows certificate store:

```powershell
$env:TELESEC_SIGN_CERT_SHA1 = '<certificate-thumbprint>'
.\scripts\release.ps1
```

The release command lints and tests the agent, builds and signs `TelesecAgent.exe`, compiles and signs the Inno installer, runs package diagnostics, publishes only `Telesec-Network-Agent-Setup.exe` into the web public directory, and writes a SHA-256 release manifest under `agent_builder\dist\installer`.

The installer supports interactive enrollment and silent deployment:

```powershell
.\Telesec-Network-Agent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SERVERURL=https://telesec.example /ENROLLMENTTOKEN=<one-time-token>
```

Existing DPAPI enrollment is retained during upgrades. To force a fresh local enrollment during development or redeployment, pass `/RESETAGENTDATA=1` with a new one-time token:

```powershell
.\Telesec-Network-Agent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /RESETAGENTDATA=1 /SERVERURL=http://127.0.0.1:8000 /ENROLLMENTTOKEN=<one-time-token>
```

Uninstall removes the service, program files, Start Menu entry, Run key, and `%ProgramData%\Telesec\NetworkAgent`.
