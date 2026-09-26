# ForgeSec

ForgeSec is a local-first network inventory and authorized reconnaissance system. It combines an operational Next.js dashboard, a FastAPI JSON control plane, and a native Windows agent that orchestrates Nmap at the monitored site.

## Product boundaries

The [v1 architecture and scope decision](docs/v1-architecture-scope.md) fixes tool placement, the full-suite release boundary, and explicit non-claims. The Windows probe includes Nmap/Npcap for local scanning; central workers require their own target routes.

- Operator sign-in uses server-side sessions and admin/operator/viewer roles. Local JSON storage remains available for development; Docker uses PostgreSQL.
- Agents use single-use enrollment tokens and hashed machine credentials.
- Every probe belongs to a site; discovery, diagnostics, and scans require a saved approved CIDR for that site.
- Discovery runs on approved connected IPv4 segments of up to `/24` each. Multi-segment jobs are limited to 16 segments and require explicit confirmation.
- Detailed scanning accepts only operator-selected discovered devices inside approved scopes. Large selections run in batches.
- One agent runs at most three Nmap host processes concurrently.
- Docker runs web and API only. The scanner is one native Windows service per site.
- No exploitation, brute force, credential attacks, or aggressive scripts.

## Repository

- `apps/web`: Network Agent dashboard and the one public setup download.
- `services/api`: operator access, PostgreSQL/JSON storage, site policy, enrollment, probe, command, discovery, scan, and activity APIs.
- `agent_builder`: Windows agent source, tests, PyInstaller build, Inno setup, and release automation.
- `shared/schemas`: versioned JSON contracts and dependency-free validation.
- `docs`: architecture and deployment runbooks.

## Quick verification

Run the local verification bundle:

```powershell
.\scripts\verify-local.ps1
```

For the optional integrated API/agent smoke test, use `-IncludeSmoke` after installing
the agent runtime dependencies into the API virtual environment.

```powershell
cd shared\schemas
python validate_schemas.py

cd ..\..\services\api
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\pytest.exe -q

cd ..\..\agent_builder
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\pytest.exe -q
```

See the [pilot baseline](docs/pilot-baseline.md) before a real install or scan, the [agent lifecycle pilot](docs/agent-lifecycle-pilot.md) for the real Windows install/upgrade/uninstall test, and the [discovery/scan pilot](docs/discovery-scan-pilot.md) for accuracy checks. The [operating workflow](docs/operating-workflow.md) covers the site-to-report path, [deployment](docs/deployment.md) covers first-admin bootstrap and storage, and the [one-install pilot](docs/one-install-pilot.md) covers release gates. The [asset inventory](docs/asset-inventory.md) explains identity matching, the [LLDP topology](docs/topology.md) covers observed links and field checks, [vulnerability intelligence](docs/vulnerability-intelligence.md) explains saved CVE assessments, the [central Nuclei worker](docs/nuclei-worker.md) covers controlled web checks, the [Greenbone worker](docs/greenbone-worker.md) covers optional advanced assessments, and the [SSH inventory worker](docs/ssh-inventory-worker.md) covers optional read-only Linux inventory.

For production promotion, use the [final acceptance and release gate](docs/final-acceptance-release.md). The current development installer must not be treated as a signed one-install customer release.

Before packaging, use the [release source baseline](docs/release-baseline.md) to freeze the v1 revision and dependencies.
