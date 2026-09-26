# Step 27: Release source and dependency baseline

The checker is a **read-only audit and freeze gate** for the v1 full-suite scope in [FS-ADR-001](v1-architecture-scope.md). Running it does not commit changes, install a probe, start servers, or scan a network. A clean test suite is evidence of behavior, not a frozen release revision.

## Pre-freeze audit (2026-09-26)

This snapshot was taken before candidate selection. It records why the earlier working tree was not frozen; use the source gate and exact commit SHA to establish the current candidate status.

| Check | Result |
| --- | --- |
| HEAD before release freeze | `127a2f7a67c6fdc56d99dbd4c40d8c197beafdf2` |
| Git worktree | **Not frozen at audit time:** 213 changed/untracked status entries after the lock and image-pinning work. Generated `.step*-tests` runtime data is excluded from release source without deleting it. |
| Versions | API, agent package/source, web package/lock all report `0.1.0`. |
| Web lock | Present, direct dependency metadata matches `package.json`. `npm audit` found no known advisories in production or full installed web dependencies at this check. |
| Python dependency audit | `pip-audit 2.10.1` found no known advisories in either resolved hash lock on this date. Optional Greenbone and SSH worker-host installations still need their own Step 30 lock/audit. |
| Python production locks | API Linux/Python 3.13 and agent Windows/Python 3.12 locks now pin transitive packages and SHA-256 hashes. The API Docker build and agent release/build scripts install from them; clean agent install, lint, and 71 tests passed. |
| Container base images | Python, Node, PostgreSQL, and Caddy now use registry digest references. The pinned API and web images built locally; API `pip check` and import passed. The final wheel-only API test image digest is `sha256:6e1f5e7fd150873e83b6d0a569b9c1982328719a633b5c76bf2b62e19819a09c`. Local test image digests are not promoted release-image digests. |
| Tracked sensitive paths | The gate found no tracked `.env`, private-key/OEM package, or runtime-data path. A filename check cannot prove absence of secrets inside ordinary source files. |
| Whitespace | `git diff --check` found no whitespace errors; line-ending warnings are not release failures. |
| Production package | The current installer manifest is `0.1.0 development`, unsigned, with no licensed scanner bundle. Package acceptance belongs to later steps. |
| Local verification | The full bundle after the lock/build edits passed 10 schemas, 18 pilot-plan tests, 5 acceptance-gate tests, 4 baseline-gate tests, 96 API tests (1 expected database skip), 71 agent tests, web typecheck/build, and installer hash check. The opt-in PostgreSQL integration passed separately against a disposable digest-pinned PostgreSQL 17 container, which was stopped. Rerun the full bundle against the final reviewed revision. |

The advisory findings are time- and environment-specific. Re-run them immediately before release, inspect every finding, and audit the **resolved** Python locks and worker-host dependencies. A zero-advisory result is not proof that dependencies are free of unknown issues. Do not commit `.env`, OEM media, credentials, customer inventory, or raw backup archives to make the worktree clean.

## Regenerate the Python locks

Use `uv 0.12.19` from the repository root. The `pyproject.toml` files supply application dependencies; each `requirements.in` adds the Hatchling build backend. Review version and hash changes before accepting regenerated locks:

```powershell
uv pip compile services/api/pyproject.toml services/api/requirements.in --python-version 3.13 --python-platform x86_64-manylinux_2_17 --generate-hashes --output-file services/api/requirements.lock --no-header
uv pip compile agent_builder/pyproject.toml agent_builder/requirements.in --extra build --extra dev --python-version 3.12 --python-platform x86_64-pc-windows-msvc --generate-hashes --output-file agent_builder/requirements.lock --no-header
```

The API image installs the Linux lock with pip's `--require-hashes --only-binary=:all:`; the agent release scripts do the same with the Windows lock before installing the local source wheel without dependency resolution. Do not substitute a Windows lock for the API's Linux Docker runtime. Build and test the exact container digests and locks again when intentionally upgrading any dependency.

## Complete the freeze

1. Review `git status --short` and the actual diff. Determine which existing changes belong to v1; preserve user work. Commit or explicitly exclude every intended source change through the normal review process. Do not use `git reset --hard` or delete untracked material to manufacture a clean tree.
2. Confirm the reviewed candidate still matches the API **Python 3.13** and agent/build **Windows Python 3.12** locks, then repeat clean installs. Step 30 must additionally lock/audit optional Greenbone and SSH worker extras on their actual host platform.
3. Rebuild and test the reviewed candidate from its pinned API/web base and PostgreSQL/Caddy image references. Record the candidate's resulting image digests; do not substitute a locally tagged image with unknown provenance.
4. Run the offline source gate from the repository root. Pass the chosen candidate commit SHA when the release owner has selected one:

```powershell
.\services\api\.venv\Scripts\python.exe .\scripts\check_release_baseline.py --expected-commit '<reviewed-commit-sha>'
.\scripts\verify-local.ps1
npm audit --prefix apps/web --omit=dev
```

5. Run the Python vulnerability audit on the resolved locks and the separately installed worker-host environments, preserve date/version/results in restricted release evidence, and run the PostgreSQL integration test against a disposable database. The normal local suite skips that integration when `FORGESEC_TEST_DATABASE_URL` is absent. Preserve the selected commit, lock hashes, test output, and build-image digests together.

**Step 27 done when:** the source gate exits zero on the reviewed commit; clean installs, dependency advisories, PostgreSQL integration, and full local verification have evidence tied to that same revision. The pre-freeze audit above did **not** meet this exit gate. A passing source gate does not authorize a production package or customer deployment; those have later acceptance gates.
