"""Offline tests for the final release gate."""

from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from check_final_acceptance import REQUIRED_GATES, REQUIRED_V1_WORKERS, validate_artifacts, validate_evidence


def _manifest(payload: bytes) -> dict:
    return {
        "schema_version": 1,
        "product": "ForgeSec Network Agent",
        "version": "1.2.3",
        "channel": "production",
        "file": "ForgeSec-Network-Agent-Setup-1.2.3.exe",
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest().upper(),
        "signed": True,
        "includes_licensed_scanner": True,
        "nmap_oem_sha256": "A" * 64,
    }


def _evidence(manifest: dict) -> dict:
    return {
        "schema_version": 1,
        "release_scope": "v1_full_suite",
        "customer_id": "pilot-customer",
        "release_sha256": manifest["sha256"],
        "gates": {name: {"status": "pass", "evidence": f"TICKET-{name}"} for name in REQUIRED_GATES},
        "workers": {name: {"status": "pass", "evidence": f"PILOT-{name}"} for name in REQUIRED_V1_WORKERS},
        "signoff": {
            "decision": "approved", "approver": "Release owner",
            "approved_at_utc": datetime.now(timezone.utc).isoformat(),
        },
    }


class FinalAcceptanceTests(unittest.TestCase):
    def test_matching_production_artifacts_and_signed_status(self) -> None:
        payload = b"test signed package"
        manifest = _manifest(payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            built = root / manifest["file"]
            published = root / "published.exe"
            built.write_bytes(payload)
            published.write_bytes(payload)
            self.assertEqual(validate_artifacts(manifest, copy.deepcopy(manifest), built, published, signature_status="Valid"), [])
            self.assertIn("Authenticode", " ".join(validate_artifacts(manifest, manifest, built, published, signature_status="NotSigned")))
            published.write_bytes(b"different")
            self.assertIn("SHA-256", " ".join(validate_artifacts(manifest, manifest, built, published, signature_status="Valid")))

    def test_development_and_manifest_mismatch_are_rejected(self) -> None:
        payload = b"test package"
        manifest = _manifest(payload)
        published_manifest = copy.deepcopy(manifest)
        published_manifest["channel"] = "development"
        manifest["channel"] = "development"
        with tempfile.TemporaryDirectory() as directory:
            built = Path(directory) / manifest["file"]
            built.write_bytes(payload)
            errors = validate_artifacts(manifest, published_manifest, built, built, signature_status="Valid")
            self.assertIn("not production", " ".join(errors))
            published_manifest["version"] = "1.2.4"
            self.assertIn("differs", " ".join(validate_artifacts(manifest, published_manifest, built, built)))

    def test_all_required_evidence_passes(self) -> None:
        manifest = _manifest(b"package")
        self.assertEqual(validate_evidence(_evidence(manifest), manifest), [])

    def test_unfinished_or_unbound_evidence_is_rejected(self) -> None:
        manifest = _manifest(b"package")
        evidence = _evidence(manifest)
        evidence["release_sha256"] = "0" * 64
        evidence["gates"]["agent_lifecycle"] = {"status": "not_tested", "evidence": ""}
        evidence["workers"]["nuclei"] = {"status": "pass", "evidence": ""}
        evidence["signoff"]["decision"] = "pending"
        errors = " ".join(validate_evidence(evidence, manifest))
        for expected in ("SHA-256", "agent_lifecycle", "nuclei", "approval"):
            self.assertIn(expected, errors)

    def test_full_suite_cannot_skip_a_worker_or_scope(self) -> None:
        manifest = _manifest(b"package")
        evidence = _evidence(manifest)
        evidence["release_scope"] = "core"
        evidence["workers"]["greenbone"] = {"status": "not_deployed", "evidence": "Deferred"}
        errors = " ".join(validate_evidence(evidence, manifest))
        self.assertIn("v1_full_suite", errors)
        self.assertIn("greenbone", errors)


if __name__ == "__main__":
    unittest.main()
