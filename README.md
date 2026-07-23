# Telesec

Telesec is a local-first network inventory and authorized reconnaissance system. It combines an operational Next.js dashboard, a FastAPI JSON control plane, and a native Windows agent that orchestrates Nmap at the monitored site.

## Product boundaries

- No human login or database in local v1; dashboard and API bind to localhost by default.
- Agents use single-use enrollment tokens and hashed machine credentials.
- Discovery accepts authorized private networks only and is capped at one `/24` per command.
- Detailed scanning accepts exactly the operator-selected devices, at most 10 per job.
- One agent runs at most three Nmap host processes concurrently.
- Docker runs web and API only. The scanner is one native Windows service per site.
- No exploitation, brute force, credential attacks, or aggressive scripts.

## Repository

- `apps/web`: Network Agent dashboard and the one public setup download.
- `services/api`: enrollment, agent, command, discovery, scan, and activity APIs.
- `agent_builder`: Windows agent source, tests, PyInstaller build, Inno setup, and release automation.
- `shared/schemas`: versioned JSON contracts and dependency-free validation.
- `docs`: architecture and deployment runbooks.

## Quick verification

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

Use `docker compose up --build -d` for the local web/API deployment. See [architecture](docs/architecture.md) and [deployment](docs/deployment.md) for enrollment, release, HTTPS ingress, backup, and recovery details.
