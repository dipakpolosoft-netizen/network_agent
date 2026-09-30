# Step 25: Final acceptance and release

For this product's v1 **full-suite** release, follow [FS-ADR-001](v1-architecture-scope.md). The release gate requires real pilot evidence for Nuclei, Greenbone, and SSH inventory; a reduced-scope release would need an explicitly revised decision and gate, not a `not_deployed` shortcut.

**Current state:** a local development installer is available, but it is unsigned and does not bundle licensed Nmap/Npcap. It is not a customer release. This procedure is a release decision for one exact installer SHA-256 and one customer deployment, not permission for broad network scanning.

**Feature Step 21 local status (2026-09-29):** `verify-local.ps1 -SkipWebBuild -IncludeSmoke` passed 10 schemas, 37 pilot-plan tests, 7 acceptance-gate tests, 4 source-gate tests, API lint and 216 API tests (1 opt-in PostgreSQL skip), agent lint and 153 agent tests, web typecheck, the development-installer hash check, and a synthetic loopback enrollment/discovery/scan smoke test. Separately, 23 web tests passed. The web production build was deliberately skipped while the development server is in use; this is not an exact-candidate release run. The source gate still reports 140 changed/untracked entries, production Compose preflight lacks deployment-specific values, and package preflight lacks signtool, a signing certificate, licensed Nmap OEM media, and its supplier-verified hash. No real-network scan, signing, customer deployment, clean-machine pilot, production backup restore, or final download promotion occurred. Step 21 is **not release-accepted**.

## 1. Freeze and verify the candidate

Complete the [Step 27 release baseline](release-baseline.md), freeze a source revision and version, and record the commit and deployment's `FORGESEC_CUSTOMER_ID`. Do not modify the candidate between testing and release. On the build host, run:

```powershell
cd C:\Users\USER\Desktop\forge-sec-network-agent\network_agent
.\scripts\verify-local.ps1
.\agent_builder\scripts\check-production-package.ps1
python .\scripts\check_production_config.py
```

`verify-local.ps1` covers schemas, API/agent lint and tests, web typecheck/build, and published-installer integrity. Production config validation needs the real deployment `.env`; it does not start containers. The package preflight needs the licensed Nmap OEM file, its supplier-verified hash, a valid code-signing certificate and signtool. Also verify the organization's Inno Setup and Nmap/Npcap redistribution terms. A passing local test suite alone is not acceptance.

Once those prerequisites pass, build the production candidate with `agent_builder\scripts\release.ps1 -ExpectedCommit '<reviewed-40-character-git-sha>'` (without `-Development`), then rerun `scripts\verify-local.ps1` against that exact packaged candidate. The release command writes the build manifest and publishes identical bytes to the web **source** download folder. Keep that folder isolated from a live customer-facing development web server until approval. Do not rebuild/redeploy the production web image yet: its `/public` files are baked into the image. Retain the build manifest, source revision, OEM supplier record, and signing certificate identity. Never store a token, password, key, raw database dump, or unredacted customer inventory in the acceptance record.

## 2. Collect real acceptance evidence

Use the [Step 14 pilot boundary](pilot-baseline.md), [clean-machine production pilot](clean-machine-release-pilot.md), [central-worker validation](central-worker-validation.md), [topology field check](topology.md), [customer isolation](multi-customer-scale.md), and [production backup/restore rehearsal](deployment.md). Enter a concise ticket or protected evidence-bundle reference for each **pass** in a local copy of the worksheet. The checker cannot prove that a reference is truthful; the named approver must review the actual result.

Required gate meanings:

| Gate | Evidence to review |
| --- | --- |
| `automated_checks` | Exact revision, test/build logs, and matching package hash. |
| `production_control_plane` | Trusted HTTPS from a separate probe, production config, health, and correct probe-facing URL. |
| `customer_isolation` | Unique customer ID, database/volumes/hostname/operator directory, and no mixed-customer data. |
| `backup_restore` | Encrypted off-host backup, verified restore rehearsal, recovery time. |
| `operator_access` | Admin/operator/viewer boundaries, sign-in, and session invalidation. |
| `scope_approval` | Written site/CIDR/exclusions/profile approval, expiry, and known-device baseline. |
| `package_licenses` | OEM and Inno commercial rights, supplier hash, publisher/signature record. |
| `clean_machine_install` | Clean Windows VM, interactive branding/tray, bundled Nmap/Npcap, HTTPS enrollment. |
| `agent_lifecycle` | Heartbeat, restart, **newer signed version** upgrade, uninstall cleanup, server revocation. |
| `discovery_scan` | One approved discovery and target scan compared with known devices; misses and uncertainty recorded. |
| `report_evidence` | Progress, asset/evidence linkage, report view, JSON/PDF downloads, audit. |
| `topology_field` | Live LLDP devices and links compared with device management evidence; unsupported topology documented. |
| `security_negative_paths` | Wrong-site/out-of-scope/revoked paths rejected, no secret leakage. |
| `operations_rollback` | Health/worker monitoring, backup and rollback owner, tested stop/recovery procedure and scale limits. |

For each central worker (`nuclei`, `greenbone`, `ssh_inventory`), record `pass` with a real approved worker-host and target pilot. A preflight or mocked test is not a worker pilot. A worker may be optional for an individual customer site, but the **v1 full-suite release** cannot pass while an integration is untested or `not_deployed`. Use an approved lab target if the customer has no suitable Linux/web/Greenbone target; never scan an unapproved customer device to complete the gate. Topology is also core to this release. If the pilot network has no suitable LLDP devices, leave this gate open or obtain a separately approved lab pilot.

## 3. Review and run the fail-closed gate

```powershell
Copy-Item .\docs\final-acceptance.example.json .\docs\final-acceptance.local.json
notepad .\docs\final-acceptance.local.json
python .\scripts\check_final_acceptance.py --evidence .\docs\final-acceptance.local.json
```

The local record is ignored by Git. Keep `release_scope` as `v1_full_suite`, fill `release_sha256` with the **exact** build manifest hash and `release_commit` with its reviewed source commit, record `pass` evidence for every required gate and central worker, and obtain a named release owner's approval with a UTC timestamp. The checker rehashes the build and web-source installer, compares manifests, requires production/licensed-package metadata, and independently validates the published installer's Windows Authenticode signature. It does not install software, contact a target, create a token, or publish an image. An empty/example worksheet must fail. Preserve the completed worksheet and referenced evidence under the organization's restricted release records.
The Authenticode check also compares the certificate thumbprint read from the installer with the manifest's signer thumbprint; a valid signature from a different signer is not accepted.

## 4. Promote and confirm

Only after gate approval, build/deploy the production web image using the accepted source revision and published installer. Before opening the download broadly, fetch `release.json` and the installer over production HTTPS from a **separate** machine and compare their SHA-256/size/version/channel with the approved manifest. If bytes differ, stop and rerun acceptance for the new hash. Verify `/health`, sign-in, the enrollment URL, the download, and one authorized probe heartbeat after deploy. Record the deployed image digest, promotion time, operator, and rollback image/backup reference. Monitor errors, worker queues, and probe heartbeat; suspend enrollment/download or roll back the web image if those checks fail. Do not roll back the database blindly after a schema/data migration.

**Release is incomplete** while any required evidence, signature/OEM license, clean-machine pilot, newer-version upgrade, live topology check, backup restore, or final HTTPS download comparison is missing. The checker verifies local candidate readiness; the post-deploy HTTPS comparison and monitoring remain a separate human release action.
