"""Read-only, provenance-preserving evidence for one durable asset."""

from __future__ import annotations

import hashlib
import json

from forgesec_api.scans.service import ScanService
from forgesec_api.storage import JsonStore
from forgesec_api.time import parse_timestamp
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


def _add_item(items: list[dict], asset_id: str, item: dict, identity: str) -> None:
    key = [asset_id, item["source"], item["source_id"], identity]
    item["review_id"] = hashlib.sha256(
        json.dumps(key, separators=(",", ":")).encode()
    ).hexdigest()
    item["review_status"] = "unreviewed"
    items.append(item)


def _job_matches_scan(
    store: JsonStore,
    observed_devices: dict[tuple[str, str, str], set[str]],
    site_id: str,
    job: dict,
) -> bool:
    scan_id = job.get("source_scan_id")
    target_ip = job.get("target_ip")
    if not scan_id or not target_ip:
        return False
    scan = store.read("scans", scan_id)
    if not scan or scan.get("site_id") != site_id:
        return False
    device_ids = observed_devices.get((scan_id, target_ip, scan["agent_id"]), set())
    return any(
        result.get("status") == "completed"
        and result["device_id"] in device_ids
        and result["ip"] == target_ip
        for result in scan.get("results", [])
    )


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
    observed_devices: dict[tuple[str, str, str], set[str]] = {}
    for observation in observations:
        key = (
            observation["source_id"],
            observation["ip"],
            observation["agent_id"],
        )
        observed_devices.setdefault(key, set()).add(observation["source_device_id"])
    jobs = sorted(
        (
            job
            for job in store.list_by_field(
                "scanner-worker-jobs", "source_asset_id", asset_id
            )
            if job.get("source_asset_id") == asset_id
            and job["site_id"] == site_id
            and _job_matches_scan(store, observed_devices, site_id, job)
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
        if (
            not scan
            or scan.get("site_id") != site_id
            or scan.get("agent_id") != observation["agent_id"]
        ):
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
        current = result.get("status") == "completed" and (
            scan_id == asset.get("last_scan_id")
            and observation["ip"] == asset["last_ip"]
        )
        for flag in result.get("exposure_flags") or []:
            _add_item(
                items,
                asset_id,
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
                },
                f"{observation['source_device_id']}|{observation['ip']}|{flag['code']}",
            )

        assessment = store.read("vulnerability-assessments", scan_id)
        if not assessment or assessment.get("scan_id") != scan_id:
            continue
        if assessment.get("skipped_cpes") or assessment.get("failed_cpes"):
            truncated = True
        contexts = scans.observed_cpe_contexts(scan_id)
        current = current and assessment.get("evidence_fingerprint") == _fingerprint(
            contexts
        )
        observed_services = {
            cpe: [
                service
                for service in services
                if (
                    service["device_id"] == observation["source_device_id"]
                    and service["ip"] == observation["ip"]
                )
            ]
            for cpe, services in contexts.items()
        }
        for match in assessment.get("items", []):
            services = observed_services.get(match["cpe"], [])
            if not services or match.get("error"):
                continue
            if match.get("total", 0) > len(match.get("top_vulnerabilities") or []):
                truncated = True
            for vulnerability in match.get("top_vulnerabilities") or []:
                _add_item(
                    items,
                    asset_id,
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
                        "target": ", ".join(
                            sorted(
                                {
                                    f"{service['ip']}:{service['port']}/{service['protocol']}"
                                    for service in services
                                }
                            )[:8]
                        ),
                    },
                    f"{observation['source_device_id']}|{observation['ip']}|{match['cpe']}|{vulnerability['cve_id']}",
                )

    newest_completed: set[tuple[str, str, int | None, str | None]] = set()
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
        linked_to_latest = job["target_ip"] == asset["last_ip"] and job.get(
            "source_scan_id"
        ) == asset.get("last_scan_id")
        coverage = (
            source,
            job.get("target_ip", ""),
            job.get("target_port"),
            job.get("target_scheme"),
        )
        current = linked_to_latest and coverage not in newest_completed
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
        newest_completed.add(coverage)
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
            _add_item(
                items,
                asset_id,
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
                },
                finding["template_id"]
                if source == "nuclei"
                else finding.get("result_id")
                or "|".join(
                    str(finding.get(key, ""))
                    for key in ("host", "port", "nvt_oid", "name")
                ),
            )

    items.sort(key=lambda item: item["observed_at"], reverse=True)
    if len(items) > MAX_ITEMS:
        truncated = True
    selected = items[:MAX_ITEMS]
    for item in selected:
        review = store.read("asset-evidence-reviews", item["review_id"])
        if (
            review
            and review.get("review_id") == item["review_id"]
            and review.get("asset_id") == asset_id
            and review.get("site_id") == site_id
            and review.get("source") == item["source"]
            and review.get("source_id") == item["source_id"]
            and (
                item["source"] != "nvd"
                or parse_timestamp(review["updated_at"])
                >= parse_timestamp(item["observed_at"])
            )
        ):
            item.update(
                review_status=review["status"],
                review_note=review.get("note") or None,
                reviewed_at=review["updated_at"],
                reviewed_by=review.get("actor_id"),
            )
    return {
        "asset_id": asset_id,
        "items": selected,
        "runs": runs,
        "latest_inventory": inventory,
        "truncated": truncated,
    }
