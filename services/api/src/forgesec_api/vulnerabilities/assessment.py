"""Persist central CVE correlation against a scan's exact observed evidence."""

from __future__ import annotations

import hashlib
import json
from collections import Counter

from forgesec_api.activity import record_activity
from forgesec_api.scans.service import ScanService
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now
from forgesec_api.vulnerabilities.service import (
    InvalidCpe,
    VulnerabilityProviderUnavailable,
    VulnerabilityService,
)

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SEVERITY_RANK = {
    severity: len(SEVERITIES) - index
    for index, severity in enumerate(SEVERITIES)
}


class AssessmentNotFound(RuntimeError):
    pass


class AssessmentEvidenceChanged(RuntimeError):
    pass


def _fingerprint(contexts: dict[str, list[dict]]) -> str:
    encoded = json.dumps(contexts, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _summarize(cpe: str, affected_services: list[dict], lookup: dict) -> dict:
    vulnerabilities = lookup.get("vulnerabilities") or []
    counts: Counter[str] = Counter()
    for vulnerability in vulnerabilities:
        severity = vulnerability.get("severity")
        counts[severity if severity in SEVERITIES else "unknown"] += 1
    present = [severity for severity in SEVERITIES if counts[severity]]
    return {
        "cpe": cpe,
        "normalized_cpe": lookup.get("normalized_cpe"),
        "affected_services": affected_services[:128],
        "affected_service_count": len(affected_services),
        "total": lookup.get("total", 0),
        "returned": lookup.get("returned", len(vulnerabilities)),
        "severity_counts": {severity: counts[severity] for severity in SEVERITIES},
        "highest_severity": (
            max(present, key=SEVERITY_RANK.__getitem__) if present else None
        ),
        "known_exploited": sum(
            bool(item.get("known_exploited")) for item in vulnerabilities
        ),
        "top_vulnerabilities": vulnerabilities[:10],
        "error": None,
    }


class AssessmentService:
    def __init__(
        self,
        store: JsonStore,
        scans: ScanService,
        vulnerabilities: VulnerabilityService,
    ):
        self.store = store
        self.scans = scans
        self.vulnerabilities = vulnerabilities

    def get(self, scan_id: str) -> dict:
        contexts = self.scans.observed_cpe_contexts(scan_id)
        assessment = self.store.read("vulnerability-assessments", scan_id)
        if assessment is None:
            raise AssessmentNotFound
        return {
            **assessment,
            "evidence_current": (
                assessment["evidence_fingerprint"] == _fingerprint(contexts)
            ),
        }

    def refresh(
        self, scan_id: str, *, limit: int, actor_id: str | None = None
    ) -> dict:
        contexts = self.scans.observed_cpe_contexts(scan_id)
        fingerprint = _fingerprint(contexts)
        items = []
        aggregate_counts: Counter[str] = Counter()
        total_vulnerabilities = 0
        returned_vulnerabilities = 0
        known_exploited = 0
        cached_lookups = 0
        for cpe, affected_services in list(contexts.items())[:limit]:
            try:
                lookup = self.vulnerabilities.lookup(cpe)
                cached_lookups += bool(lookup.get("cached"))
                item = _summarize(cpe, affected_services, lookup)
            except (InvalidCpe, VulnerabilityProviderUnavailable) as exc:
                item = {
                    "cpe": cpe,
                    "normalized_cpe": None,
                    "affected_services": affected_services[:128],
                    "affected_service_count": len(affected_services),
                    "total": 0,
                    "returned": 0,
                    "severity_counts": {severity: 0 for severity in SEVERITIES},
                    "highest_severity": None,
                    "known_exploited": 0,
                    "top_vulnerabilities": [],
                    "error": str(exc),
                }
            items.append(item)
            total_vulnerabilities += item["total"]
            returned_vulnerabilities += item["returned"]
            known_exploited += item["known_exploited"]
            aggregate_counts.update(item["severity_counts"])

        items.sort(
            key=lambda item: (
                -item["known_exploited"],
                -SEVERITY_RANK[item["highest_severity"] or "unknown"],
                -item["returned"],
                item["cpe"],
            )
        )
        result = {
            "source": "NVD",
            "scan_id": scan_id,
            "total_cpes": len(contexts),
            "checked_cpes": sum(item["error"] is None for item in items),
            "failed_cpes": sum(item["error"] is not None for item in items),
            "skipped_cpes": max(0, len(contexts) - len(items)),
            "total_vulnerabilities": total_vulnerabilities,
            "returned_vulnerabilities": returned_vulnerabilities,
            "known_exploited": known_exploited,
            "severity_counts": {
                severity: aggregate_counts[severity] for severity in SEVERITIES
            },
            "items": items,
            "assessed_at": isoformat(utc_now()),
            "evidence_fingerprint": fingerprint,
            "evidence_current": True,
            "cached_lookups": cached_lookups,
        }
        with self.store.locked():
            if _fingerprint(self.scans.observed_cpe_contexts(scan_id)) != fingerprint:
                raise AssessmentEvidenceChanged
            self.store.write("vulnerability-assessments", scan_id, result)
            record_activity(
                self.store,
                event_type="vulnerability.assessed",
                message="Scan CVE correlation refreshed",
                actor_type="user" if actor_id else "server",
                actor_id=actor_id,
                resource_type="scan",
                resource_id=scan_id,
                details={
                    "checked_cpes": result["checked_cpes"],
                    "failed_cpes": result["failed_cpes"],
                    "skipped_cpes": result["skipped_cpes"],
                },
            )
        return result
