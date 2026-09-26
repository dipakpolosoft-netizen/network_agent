"""Read-only, provenance-preserving evidence for one durable asset."""

from __future__ import annotations

from forgesec_api.scans.service import ScanService
from forgesec_api.storage import JsonStore
from forgesec_api.vulnerabilities.assessment import _fingerprint

MAX_SCAN_SOURCES = 20
MAX_WORKER_RUNS = 20
MAX_ITEMS = 200


def _greenbone_severity(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def build_asset_evidence(store: JsonStore, scans: ScanService, asset: dict) -> dict:
    asset_id = asset["asset_id"]
    site_id = asset["site_id"]
    observations = sorted(
        (
            item
            for item in store.list_by_field("asset-observations", "asset_id", asset_id)
            if item["asset_id"] == asset_id
            and item["site_id"] == site_id
            and item["source_type"] == "scan"
        ),
        key=lambda item: item["observed_at"],
        reverse=True,
    )
    jobs = sorted(
        (
            job
            for job in store.list_by_field(
                "scanner-worker-jobs", "source_asset_id", asset_id
            )
            if job.get("source_asset_id") == asset_id and job["site_id"] == site_id
        ),
        key=lambda job: job["created_at"],
        reverse=True,
    )
    truncated = len(observations) > MAX_SCAN_SOURCES or len(jobs) > MAX_WORKER_RUNS
    items: list[dict] = []
    runs: list[dict] = []
    inventory = None

    for observation in observations[:MAX_SCAN_SOURCES]:
        scan_id = observation["source_id"]
        scan = store.read("scans", scan_id)
        if not scan:
            continue
        result = next(
            (
                item
                for item in scan.get("results", [])
                if item["device_id"] == observation["source_device_id"]
                and item["ip"] == observation["ip"]
            ),
            None,
        )
        if not result:
            continue
        current = (
            scan_id == asset.get("last_scan_id")
            and observation["ip"] == asset["last_ip"]
        )
        for flag in result.get("exposure_flags") or []:
            items.append(
                {
                    "source": "host_scan",
                    "classification": "exposure_signal",
                    "source_id": scan_id,
                    "scan_id": scan_id,
                    "observed_at": observation["observed_at"],
                    "current": current,
                    "severity": flag["severity"],
                    "title": flag["title"],
                    "detail": flag["evidence"],
                    "reference": flag["code"],
                    "target": observation["ip"],
                }
            )

        assessment = store.read("vulnerability-assessments", scan_id)
        if not assessment:
            continue
        if assessment.get("skipped_cpes") or assessment.get("failed_cpes"):
            truncated = True
        contexts = scans.observed_cpe_contexts(scan_id)
        current = current and assessment.get("evidence_fingerprint") == _fingerprint(
            contexts
        )
        observed_cpes = {
            cpe
            for cpe, services in contexts.items()
            if any(
                service["device_id"] == observation["source_device_id"]
                and service["ip"] == observation["ip"]
                for service in services
            )
        }
        for match in assessment.get("items", []):
            if match["cpe"] not in observed_cpes or match.get("error"):
                continue
            if match.get("total", 0) > len(match.get("top_vulnerabilities") or []):
                truncated = True
            for vulnerability in match.get("top_vulnerabilities") or []:
                items.append(
                    {
                        "source": "nvd",
                        "classification": "potential_cve",
                        "source_id": scan_id,
                        "scan_id": scan_id,
                        "observed_at": assessment["assessed_at"],
                        "current": current,
                        "severity": vulnerability["severity"],
                        "title": vulnerability["cve_id"],
                        "detail": vulnerability["description"],
                        "reference": match["cpe"],
                        "target": observation["ip"],
                    }
                )

    for job in jobs[:MAX_WORKER_RUNS]:
        source = (
            "nuclei"
            if job.get("template_profile") == "http_baseline"
            else "greenbone"
            if job.get("assessment_profile") == "greenbone_single_host"
            else "ssh_inventory"
            if job.get("inventory_profile") == "linux_ssh_readonly"
            else None
        )
        if source is None:
            continue
        current = job["target_ip"] == asset["last_ip"] and job.get(
            "source_scan_id"
        ) == asset.get("last_scan_id")
        runs.append(
            {
                "job_id": job["job_id"],
                "source": source,
                "status": job["status"],
                "created_at": job["created_at"],
                "completed_at": job.get("completed_at"),
                "summary": job.get("summary"),
                "current": current,
            }
        )
        if job["status"] != "completed" or not job.get("evidence"):
            continue
        evidence = job["evidence"]
        observed_at = job["completed_at"]
        if source == "ssh_inventory":
            if inventory is None:
                inventory = {
                    "job_id": job["job_id"],
                    "observed_at": observed_at,
                    "current": current,
                    "hostname": evidence["hostname"],
                    "os_name": evidence["os_name"],
                    "os_version": evidence.get("os_version"),
                    "kernel": evidence["kernel"],
                    "package_count": len(evidence.get("packages", [])),
                    "packages_truncated": evidence["packages_truncated"],
                }
            continue
        if evidence.get("truncated"):
            truncated = True
        for finding in evidence.get("findings") or []:
            if source == "nuclei":
                title = finding["title"]
                detail = finding["matched_at"]
                severity = finding["severity"]
                reference = finding["template_id"]
                target = evidence["target_url"]
            else:
                title = finding["name"]
                detail = (
                    ", ".join(finding.get("cves") or []) or "No CVE identifier reported"
                )
                severity = _greenbone_severity(finding["severity"])
                reference = finding.get("nvt_oid")
                target = f"{finding['host']}:{finding['port']}"
            items.append(
                {
                    "source": source,
                    "classification": "configuration_observation"
                    if source == "nuclei"
                    else "scanner_finding",
                    "source_id": job["job_id"],
                    "scan_id": job.get("source_scan_id"),
                    "observed_at": observed_at,
                    "current": current,
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "reference": reference,
                    "target": target,
                }
            )

    items.sort(key=lambda item: item["observed_at"], reverse=True)
    if len(items) > MAX_ITEMS:
        truncated = True
    return {
        "asset_id": asset_id,
        "items": items[:MAX_ITEMS],
        "runs": runs,
        "latest_inventory": inventory,
        "truncated": truncated,
    }
