"""Fail-closed, read-only gate for a ForgeSec production release candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_GATES = (
    "automated_checks",
    "production_control_plane",
    "customer_isolation",
    "backup_restore",
    "operator_access",
    "scope_approval",
    "package_licenses",
    "clean_machine_install",
    "agent_lifecycle",
    "discovery_scan",
    "report_evidence",
    "topology_field",
    "security_negative_paths",
    "operations_rollback",
)
REQUIRED_V1_WORKERS = ("nuclei", "greenbone", "ssh_inventory")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _signature_identity(path: Path) -> tuple[str, str | None]:
    # Read the actual signer independently of the manifest's claims.
    literal = str(path).replace("'", "''")
    command = (
        f"$signature = Get-AuthenticodeSignature -LiteralPath '{literal}'; "
        "$thumbprint = if ($signature.SignerCertificate) "
        "{ $signature.SignerCertificate.Thumbprint } else { $null }; "
        "[pscustomobject]@{ status = $signature.Status.ToString(); "
        "thumbprint = $thumbprint } | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        return f"check failed: {result.stderr.strip()}", None
    try:
        identity = json.loads(result.stdout)
        status = identity["status"]
        thumbprint = identity.get("thumbprint")
        if not isinstance(status, str) or (
            thumbprint is not None and not isinstance(thumbprint, str)
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        return "check failed: invalid Authenticode response", None
    return status, thumbprint


def validate_artifacts(
    source: dict,
    published: dict,
    source_file: Path,
    published_file: Path,
    *,
    signature_status: str | None = None,
    signer_thumbprint: str | None = None,
) -> list[str]:
    errors: list[str] = []
    for label, manifest, artifact in (
        ("Build", source, source_file),
        ("Published", published, published_file),
    ):
        if manifest.get("schema_version") != 1:
            errors.append(f"{label} manifest schema_version must be 1")
        if not artifact.is_file():
            errors.append(f"{label} installer is missing: {artifact}")
            continue
        actual_hash = _sha256(artifact)
        if str(manifest.get("sha256", "")).upper() != actual_hash:
            errors.append(f"{label} installer SHA-256 does not match its manifest")
        if manifest.get("size_bytes") != artifact.stat().st_size:
            errors.append(f"{label} installer size does not match its manifest")
    if source != published:
        errors.append("Published release.json differs from the build manifest")
    if source.get("channel") != "production":
        errors.append("Release channel is not production")
    if source.get("signed") is not True:
        errors.append("Manifest does not attest to a signed installer")
    if source.get("includes_licensed_scanner") is not True:
        errors.append("Manifest does not attest to bundled licensed Nmap/Npcap")
    if not SHA256.fullmatch(str(source.get("nmap_oem_sha256", ""))):
        errors.append("Manifest lacks the supplier-verified Nmap OEM SHA-256")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", str(source.get("source_commit", ""))):
        errors.append("Manifest lacks the frozen source commit")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", str(source.get("signer_thumbprint", ""))):
        errors.append("Manifest lacks the approved signer thumbprint")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(source.get("version", ""))):
        errors.append("Manifest has no valid semantic release version")
    if source.get("file") != source_file.name:
        errors.append("Build manifest filename does not match the installer")
    if source.get("product") != "ForgeSec Network Agent":
        errors.append("Build manifest product is not ForgeSec Network Agent")
    if source_file.name != f"ForgeSec-Network-Agent-Setup-{source.get('version')}.exe":
        errors.append("Build installer filename does not match the release version")
    if signature_status is not None:
        if signature_status != "Valid":
            errors.append(
                f"Published installer Authenticode is not valid: {signature_status}"
            )
        if not signer_thumbprint or signer_thumbprint.upper() != str(
            source.get("signer_thumbprint", "")
        ).upper():
            errors.append("Published installer signer differs from the release manifest")
    return errors


def validate_evidence(evidence: dict, manifest: dict) -> list[str]:
    errors: list[str] = []
    if evidence.get("schema_version") != 1:
        errors.append("Acceptance record schema_version must be 1")
    if evidence.get("release_scope") != "v1_full_suite":
        errors.append(
            "Acceptance record release_scope must be v1_full_suite (FS-ADR-001)"
        )
    if not str(evidence.get("customer_id", "")).strip():
        errors.append("Acceptance record needs the customer deployment ID")
    if (
        str(evidence.get("release_sha256", "")).upper()
        != str(manifest.get("sha256", "")).upper()
    ):
        errors.append("Acceptance record is not bound to this release SHA-256")
    if (
        str(evidence.get("release_commit", "")).lower()
        != str(manifest.get("source_commit", "")).lower()
    ):
        errors.append("Acceptance record is not bound to this source commit")
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        gates = {}
    for name in REQUIRED_GATES:
        item = gates.get(name)
        if not isinstance(item, dict) or item.get("status") != "pass":
            errors.append(f"{name}: required gate is not pass")
        elif not str(item.get("evidence", "")).strip():
            errors.append(f"{name}: pass needs an evidence reference")
    workers = evidence.get("workers")
    if not isinstance(workers, dict):
        workers = {}
    for name in REQUIRED_V1_WORKERS:
        item = workers.get(name)
        if not isinstance(item, dict) or item.get("status") != "pass":
            errors.append(f"{name}: full-suite worker pilot must be pass")
        elif not str(item.get("evidence", "")).strip():
            errors.append(f"{name}: pass needs a live-pilot evidence reference")
    signoff = evidence.get("signoff")
    if not isinstance(signoff, dict):
        signoff = {}
    if (
        signoff.get("decision") != "approved"
        or not str(signoff.get("approver", "")).strip()
    ):
        errors.append("Release needs an explicit named approval")
    try:
        signed_at = datetime.fromisoformat(
            str(signoff.get("approved_at_utc", "")).replace("Z", "+00:00")
        )
        if signed_at.tzinfo is None or signed_at > datetime.now(UTC):
            raise ValueError
    except ValueError:
        errors.append("Approval needs a valid, nonfuture approved_at_utc timestamp")
    return errors


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument(
        "--build-manifest",
        type=Path,
        default=ROOT / "agent_builder/dist/installer/release-manifest.json",
    )
    parser.add_argument(
        "--published-manifest",
        type=Path,
        default=ROOT / "apps/web/public/downloads/agent/release.json",
    )
    parser.add_argument(
        "--published-installer",
        type=Path,
        default=ROOT
        / "apps/web/public/downloads/agent/ForgeSec-Network-Agent-Setup.exe",
    )
    args = parser.parse_args()
    try:
        source = _read_json(args.build_manifest)
        published = _read_json(args.published_manifest)
        evidence = _read_json(args.evidence)
    except (OSError, ValueError) as exc:
        print(f"NOT READY: Cannot read acceptance input: {exc}")
        return 2
    version = str(source.get("version", ""))
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print("NOT READY: Build manifest has no valid release version")
        return 1
    source_file = (
        args.build_manifest.parent / f"ForgeSec-Network-Agent-Setup-{version}.exe"
    )
    try:
        signature, thumbprint = (
            _signature_identity(args.published_installer)
            if args.published_installer.is_file()
            else (None, None)
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        signature, thumbprint = f"check failed: {exc}", None
    errors = validate_artifacts(
        source,
        published,
        source_file,
        args.published_installer,
        signature_status=signature,
        signer_thumbprint=thumbprint,
    ) + validate_evidence(evidence, source)
    if errors:
        for error in errors:
            print(f"NOT READY: {error}")
        return 1
    print(f"ACCEPTED: {source['version']} SHA-256 {source['sha256']}")
    print(
        "Local artifacts and approvals passed. Review evidence before promotion."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
