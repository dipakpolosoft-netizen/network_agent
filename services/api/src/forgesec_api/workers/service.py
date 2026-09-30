"""Site-bound identity and leased jobs for central scanner workers."""

from __future__ import annotations

import hmac
import ipaddress
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import ValidationError

from forgesec_api.activity import record_activity
from forgesec_api.security import generate_worker_credential, hash_secret
from forgesec_api.sites.service import SiteService
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, parse_timestamp, utc_now
from forgesec_api.workers.models import (
    Capability,
    GreenboneEvidence,
    GreenboneJobCreate,
    InventoryJobCreate,
    LinuxInventoryEvidence,
    NucleiEvidence,
    NucleiJobCreate,
    WorkerCreate,
    WorkerHeartbeat,
    WorkerResult,
)

LEASE_SECONDS = 300
JOB_SECONDS = 3600
MAX_ATTEMPTS = 3
OFFLINE_SECONDS = 90
MAX_NUCLEI_EVIDENCE_AGE_DAYS = 30
MAX_NUCLEI_SITE_JOBS = 8
MAX_GREENBONE_JOB_SECONDS = 5 * 3600
MAX_INVENTORY_JOB_SECONDS = 15 * 60
GREENBONE_CANCEL_COOLDOWN_SECONDS = 120
HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 9443}


class WorkerError(RuntimeError):
    pass


class WorkerNotFound(WorkerError):
    pass


class WorkerUnauthorized(WorkerError):
    pass


class WorkerConflict(WorkerError):
    pass


class WorkerScopeError(WorkerError):
    pass


class WorkerService:
    def __init__(self, store: JsonStore, sites: SiteService):
        self.store = store
        self.sites = sites

    def provision(
        self, payload: WorkerCreate, *, actor_id: str | None = None
    ) -> tuple[dict, str]:
        self.sites.get(str(payload.site_id))
        credential = generate_worker_credential()
        credential_hash = hash_secret(credential)
        now = isoformat(utc_now())
        record = {
            "worker_id": str(uuid4()),
            "site_id": str(payload.site_id),
            "label": payload.label.strip(),
            "capabilities": payload.capabilities,
            "available_capabilities": [],
            "version": None,
            "credential_hash": credential_hash,
            "created_at": now,
            "last_heartbeat_at": None,
            "revoked_at": None,
        }
        with self.store.locked():
            self.store.write("scanner-workers", record["worker_id"], record)
            self.store.write(
                "scanner-worker-credentials",
                credential_hash,
                {"worker_id": record["worker_id"], "credential_hash": credential_hash},
            )
            record_activity(
                self.store,
                event_type="scanner_worker.provisioned",
                message="Scanner worker provisioned",
                actor_type="user",
                actor_id=actor_id,
                resource_type="scanner_worker",
                resource_id=record["worker_id"],
                details={"site_id": record["site_id"]},
            )
        return record, credential

    def authenticate(self, credential: str) -> dict:
        supplied_hash = hash_secret(credential)
        with self.store.locked():
            index = self.store.read("scanner-worker-credentials", supplied_hash)
            if index is None or not hmac.compare_digest(
                supplied_hash, index.get("credential_hash", "")
            ):
                raise WorkerUnauthorized
            worker = self.store.read("scanner-workers", index["worker_id"])
            if (
                worker is None
                or worker.get("revoked_at")
                or not hmac.compare_digest(
                    supplied_hash, worker.get("credential_hash", "")
                )
            ):
                raise WorkerUnauthorized
            return worker

    def _current(self, authenticated: dict) -> dict:
        worker = self.store.read("scanner-workers", authenticated["worker_id"])
        if (
            worker is None
            or worker.get("revoked_at")
            or not hmac.compare_digest(
                worker["credential_hash"], authenticated["credential_hash"]
            )
        ):
            raise WorkerUnauthorized
        return worker

    def heartbeat(self, authenticated: dict, payload: WorkerHeartbeat) -> dict:
        with self.store.locked():
            worker = self._current(authenticated)
            if worker["worker_id"] != str(payload.worker_id):
                raise WorkerUnauthorized
            if not set(payload.available_capabilities).issubset(worker["capabilities"]):
                raise WorkerConflict("Capability was not provisioned for this worker")
            worker["available_capabilities"] = payload.available_capabilities
            worker["version"] = payload.version
            worker["last_heartbeat_at"] = isoformat(utc_now())
            self.store.write("scanner-workers", worker["worker_id"], worker)
            return worker

    def public(self, worker: dict) -> dict:
        last_seen = worker.get("last_heartbeat_at")
        status = "offline"
        if worker.get("revoked_at"):
            status = "revoked"
        elif last_seen and utc_now() - parse_timestamp(last_seen) < timedelta(
            seconds=OFFLINE_SECONDS
        ):
            status = "online"
        return {
            key: value for key, value in worker.items() if key != "credential_hash"
        } | {"status": status}

    def list_public(self) -> list[dict]:
        return [self.public(item) for item in self.store.list("scanner-workers")]

    def revoke(self, worker_id: str, *, actor_id: str | None = None) -> dict:
        with self.store.locked():
            worker = self.store.read("scanner-workers", worker_id)
            if worker is None:
                raise WorkerNotFound
            if worker.get("revoked_at"):
                raise WorkerConflict("Worker already revoked")
            worker["revoked_at"] = isoformat(utc_now())
            self.store.write("scanner-workers", worker_id, worker)
            self.store.delete("scanner-worker-credentials", worker["credential_hash"])
            for job in self.store.list("scanner-worker-jobs"):
                if job["worker_id"] == worker_id and job["status"] == "leased":
                    self._release(job, reason="Worker access revoked")
            record_activity(
                self.store,
                event_type="scanner_worker.revoked",
                message="Scanner worker access revoked",
                actor_type="user",
                actor_id=actor_id,
                resource_type="scanner_worker",
                resource_id=worker_id,
            )
            return worker

    def enqueue(
        self,
        *,
        site_id: str,
        capability: Capability,
        target_ip: str,
        profile: str,
        target_port: int | None = None,
        target_scheme: str | None = None,
        template_profile: str | None = None,
        assessment_profile: str | None = None,
        inventory_profile: str | None = None,
        source_asset_id: str | None = None,
        source_scan_id: str | None = None,
        ttl_seconds: int = JOB_SECONDS,
    ) -> dict:
        try:
            address = ipaddress.IPv4Address(target_ip)
        except ipaddress.AddressValueError as exc:
            raise WorkerScopeError("Target must be an IPv4 address") from exc
        with self.store.locked():
            if not self.sites.approved(site_id, str(address), profile):
                raise WorkerScopeError("Target or profile is outside approved scope")
            now = utc_now()
            job = {
                "schema_version": "1.0",
                "job_id": str(uuid4()),
                "site_id": site_id,
                "capability": capability,
                "target_ip": str(address),
                "profile": profile,
                "status": "queued",
                "attempt": 0,
                "worker_id": None,
                "lease_id": None,
                "lease_expires_at": None,
                "expires_at": isoformat(now + timedelta(seconds=ttl_seconds)),
                "created_at": isoformat(now),
                "updated_at": isoformat(now),
                "completed_at": None,
                "summary": None,
                "evidence": None,
                "target_port": target_port,
                "target_scheme": target_scheme,
                "template_profile": template_profile,
                "assessment_profile": assessment_profile,
                "inventory_profile": inventory_profile,
                "source_asset_id": source_asset_id,
                "source_scan_id": source_scan_id,
                "progress": None,
                "phase": None,
            }
            self.store.write("scanner-worker-jobs", job["job_id"], job)
            record_activity(
                self.store,
                event_type="scanner_job.queued",
                message="Central scanner job queued",
                resource_type="scanner_job",
                resource_id=job["job_id"],
                details={"site_id": site_id, "capability": capability},
            )
            return job

    def _scanned_asset(self, asset_id: str) -> tuple[dict, dict, dict]:
        asset = self.store.read("assets", asset_id)
        if (
            asset is None
            or not asset.get("last_scan_id")
            or not asset.get("last_scan_at")
            or asset.get("last_scan_status") != "completed"
        ):
            raise WorkerScopeError("Asset has no host-scan evidence")
        if utc_now() - parse_timestamp(asset["last_scan_at"]) > timedelta(
            days=MAX_NUCLEI_EVIDENCE_AGE_DAYS
        ):
            raise WorkerScopeError("Host-scan evidence is older than 30 days")
        scan = self.store.read("scans", asset["last_scan_id"])
        if scan is None:
            raise WorkerScopeError("Source scan is unavailable")
        if scan.get("site_id") != asset["site_id"]:
            raise WorkerScopeError("Source scan site does not match this asset")
        agent = self.store.read("agents", scan["agent_id"])
        if agent is None or agent.get("site_id") != asset["site_id"]:
            raise WorkerScopeError("Source scan does not belong to this site")
        observed_device_ids = {
            item["source_device_id"]
            for item in self.store.list("asset-observations")
            if item["asset_id"] == asset["asset_id"]
            and item["source_type"] == "scan"
            and item["source_id"] == scan["scan_id"]
        }
        matching = [
            result
            for result in scan.get("results", [])
            if result["device_id"] in observed_device_ids
            and result["ip"] == asset["last_ip"]
            and result["status"] == "completed"
        ]
        if not matching:
            raise WorkerScopeError("Asset IP has no matching successful scan")
        return asset, scan, matching[0]

    def enqueue_nuclei(
        self, payload: NucleiJobCreate, *, actor_id: str | None = None
    ) -> dict:
        with self.store.locked():
            asset, scan, result = self._scanned_asset(str(payload.asset_id))
            ports = result.get("ports", [])
            if not any(
                port["port"] == payload.port
                and port["protocol"] == "tcp"
                and port["state"] == "open"
                and (
                    "http" in str(port.get("service") or "").lower()
                    or payload.port in HTTP_PORTS
                )
                for port in ports
            ):
                raise WorkerScopeError("Port is not an observed open HTTP service")
            ready = any(
                worker["site_id"] == asset["site_id"]
                and self.public(worker)["status"] == "online"
                and "vulnerability_assessment" in worker["available_capabilities"]
                for worker in self.store.list("scanner-workers")
            )
            if not ready:
                raise WorkerConflict("No Nuclei-capable worker is online for this site")
            active = [
                job
                for job in self.store.list("scanner-worker-jobs")
                if job["site_id"] == asset["site_id"]
                and job["capability"] == "vulnerability_assessment"
                and job["status"] in {"queued", "leased"}
            ]
            if len(active) >= MAX_NUCLEI_SITE_JOBS:
                raise WorkerConflict("Site already has too many pending web checks")
            if any(
                job.get("source_asset_id") == asset["asset_id"]
                and job.get("target_port") == payload.port
                and job.get("target_scheme") == payload.scheme
                for job in active
            ):
                raise WorkerConflict("A web check is already pending for this target")
            job = self.enqueue(
                site_id=asset["site_id"],
                capability="vulnerability_assessment",
                target_ip=asset["last_ip"],
                profile=scan["profile"],
                target_port=payload.port,
                target_scheme=payload.scheme,
                template_profile="http_baseline",
                source_asset_id=asset["asset_id"],
                source_scan_id=scan["scan_id"],
            )
            record_activity(
                self.store,
                event_type="nuclei_job.requested",
                message="Approved web configuration check requested",
                actor_type="user" if actor_id else "server",
                actor_id=actor_id,
                resource_type="scanner_job",
                resource_id=job["job_id"],
                details={"asset_id": asset["asset_id"], "port": payload.port},
            )
            return job

    def enqueue_greenbone(
        self, payload: GreenboneJobCreate, *, actor_id: str | None = None
    ) -> dict:
        with self.store.locked():
            asset, scan, result = self._scanned_asset(str(payload.asset_id))
            if result["status"] != "completed":
                raise WorkerScopeError(
                    "Advanced assessment requires a completed host scan"
                )
            if not self.sites.approved(asset["site_id"], asset["last_ip"], "full_tcp"):
                raise WorkerScopeError("Advanced assessment requires full_tcp approval")
            ready = any(
                worker["site_id"] == asset["site_id"]
                and self.public(worker)["status"] == "online"
                and "greenbone_assessment" in worker["available_capabilities"]
                for worker in self.store.list("scanner-workers")
            )
            if not ready:
                raise WorkerConflict("No Greenbone worker is online for this site")
            if any(
                job["site_id"] == asset["site_id"]
                and job.get("assessment_profile") == "greenbone_single_host"
                and (
                    job["status"] in {"queued", "leased"}
                    or (
                        job["status"] == "cancelled"
                        and utc_now() - parse_timestamp(job["updated_at"])
                        < timedelta(seconds=GREENBONE_CANCEL_COOLDOWN_SECONDS)
                    )
                )
                for job in self.store.list("scanner-worker-jobs")
            ):
                raise WorkerConflict(
                    "An advanced assessment is pending or cooling down at this site"
                )
            job = self.enqueue(
                site_id=asset["site_id"],
                capability="greenbone_assessment",
                target_ip=asset["last_ip"],
                profile="full_tcp",
                assessment_profile="greenbone_single_host",
                source_asset_id=asset["asset_id"],
                source_scan_id=scan["scan_id"],
                ttl_seconds=MAX_GREENBONE_JOB_SECONDS,
            )
            record_activity(
                self.store,
                event_type="greenbone_job.requested",
                message="Advanced single-host assessment requested",
                actor_type="user" if actor_id else "server",
                actor_id=actor_id,
                resource_type="scanner_job",
                resource_id=job["job_id"],
                details={"asset_id": asset["asset_id"], "site_id": asset["site_id"]},
            )
            return job

    def enqueue_inventory(
        self, payload: InventoryJobCreate, *, actor_id: str | None = None
    ) -> dict:
        with self.store.locked():
            asset, scan, result = self._scanned_asset(str(payload.asset_id))
            if result["status"] != "completed":
                raise WorkerScopeError("Inventory requires a completed host scan")
            if not any(
                port["port"] == 22
                and port["protocol"] == "tcp"
                and port["state"] == "open"
                for port in result.get("ports", [])
            ):
                raise WorkerScopeError("SSH is not an observed open service")
            if not self.sites.approved(asset["site_id"], asset["last_ip"], "full_tcp"):
                raise WorkerScopeError("SSH inventory requires full_tcp approval")
            if not any(
                worker["site_id"] == asset["site_id"]
                and self.public(worker)["status"] == "online"
                and "credentialed_inventory" in worker["available_capabilities"]
                for worker in self.store.list("scanner-workers")
            ):
                raise WorkerConflict("No SSH inventory worker is online for this site")
            if any(
                job["site_id"] == asset["site_id"]
                and job.get("inventory_profile") == "linux_ssh_readonly"
                and job["status"] in {"queued", "leased"}
                for job in self.store.list("scanner-worker-jobs")
            ):
                raise WorkerConflict(
                    "An SSH inventory job is already pending at this site"
                )
            job = self.enqueue(
                site_id=asset["site_id"],
                capability="credentialed_inventory",
                target_ip=asset["last_ip"],
                profile="full_tcp",
                inventory_profile="linux_ssh_readonly",
                source_asset_id=asset["asset_id"],
                source_scan_id=scan["scan_id"],
                ttl_seconds=MAX_INVENTORY_JOB_SECONDS,
            )
            record_activity(
                self.store,
                event_type="inventory_job.requested",
                message="Read-only SSH inventory requested",
                actor_type="user" if actor_id else "server",
                actor_id=actor_id,
                resource_type="scanner_job",
                resource_id=job["job_id"],
                details={"asset_id": asset["asset_id"], "site_id": asset["site_id"]},
            )
            return job

    def cancel_job(self, job_id: str, *, actor_id: str | None = None) -> dict:
        with self.store.locked():
            job = self.store.read("scanner-worker-jobs", job_id)
            if job is None:
                raise WorkerNotFound
            advanced = job.get("assessment_profile") == "greenbone_single_host"
            inventory = job.get("inventory_profile") == "linux_ssh_readonly"
            web_check = job.get("template_profile") == "http_baseline"
            if not (advanced or inventory or web_check):
                raise WorkerConflict("This job cannot be stopped here")
            if job["status"] not in {"queued", "leased"}:
                raise WorkerConflict("Job is already finished")
            now = isoformat(utc_now())
            message = (
                "Advanced assessment stopped by administrator"
                if advanced
                else (
                    "SSH inventory stopped by administrator"
                    if inventory
                    else "Web check stopped by operator"
                )
            )
            job.update(
                status="cancelled",
                summary=message,
                completed_at=now,
                updated_at=now,
            )
            self.store.write("scanner-worker-jobs", job_id, job)
            record_activity(
                self.store,
                event_type=(
                    "greenbone_job.cancelled"
                    if advanced
                    else (
                        "inventory_job.cancelled"
                        if inventory
                        else "nuclei_job.cancelled"
                    )
                ),
                message=message,
                actor_type="user" if actor_id else "server",
                actor_id=actor_id,
                resource_type="scanner_job",
                resource_id=job_id,
                details={"site_id": job["site_id"]},
            )
            return job

    def _nuclei_source_current(self, job: dict) -> bool:
        if not job.get("source_asset_id"):
            return True
        asset = self.store.read("assets", job["source_asset_id"])
        return bool(
            asset
            and asset["site_id"] == job["site_id"]
            and asset["last_ip"] == job["target_ip"]
            and asset["last_scan_id"] == job["source_scan_id"]
        )

    @staticmethod
    def _validate_nuclei_evidence(job: dict, result: WorkerResult) -> None:
        if job.get("template_profile") != "http_baseline":
            return
        if result.status == "failed":
            if result.evidence:
                raise WorkerConflict("Failed web checks cannot upload evidence")
            return
        try:
            evidence = NucleiEvidence.model_validate(result.evidence)
        except ValidationError as exc:
            raise WorkerConflict("Invalid Nuclei evidence") from exc
        expected = f"{job['target_scheme']}://{job['target_ip']}:{job['target_port']}"
        if (
            evidence.target_url != expected
            or evidence.template_profile != job["template_profile"]
        ):
            raise WorkerConflict("Nuclei evidence target does not match the job")
        seen: set[str] = set()
        for finding in evidence.findings:
            try:
                parsed = urlsplit(finding.matched_at)
                matched_port = parsed.port
            except ValueError as exc:
                raise WorkerConflict("Nuclei finding URL is invalid") from exc
            if (
                parsed.scheme != job["target_scheme"]
                or parsed.hostname != job["target_ip"]
                or matched_port != job["target_port"]
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or finding.template_id in seen
            ):
                raise WorkerConflict("Nuclei finding is outside the approved target")
            seen.add(finding.template_id)

    @staticmethod
    def _validate_greenbone_evidence(job: dict, result: WorkerResult) -> None:
        if job.get("assessment_profile") != "greenbone_single_host":
            return
        if result.status == "failed":
            if result.evidence:
                raise WorkerConflict("Failed Greenbone jobs cannot upload evidence")
            return
        try:
            evidence = GreenboneEvidence.model_validate(result.evidence)
        except ValidationError as exc:
            raise WorkerConflict("Invalid Greenbone evidence") from exc
        if evidence.target_ip != job["target_ip"]:
            raise WorkerConflict("Greenbone evidence target does not match the job")
        if len({finding.result_id for finding in evidence.findings}) != len(
            evidence.findings
        ):
            raise WorkerConflict("Greenbone evidence has duplicate results")
        if any(finding.host != job["target_ip"] for finding in evidence.findings):
            raise WorkerConflict("Greenbone finding is outside the approved target")

    @staticmethod
    def _validate_inventory_evidence(job: dict, result: WorkerResult) -> None:
        if job.get("inventory_profile") != "linux_ssh_readonly":
            return
        if result.status == "failed":
            if result.evidence:
                raise WorkerConflict("Failed inventory jobs cannot upload evidence")
            return
        try:
            evidence = LinuxInventoryEvidence.model_validate(result.evidence)
        except ValidationError as exc:
            raise WorkerConflict("Invalid SSH inventory evidence") from exc
        if evidence.target_ip != job["target_ip"]:
            raise WorkerConflict("Inventory evidence target does not match the job")
        identities = {(item.name, item.version) for item in evidence.packages}
        if len(identities) != len(evidence.packages):
            raise WorkerConflict("Inventory has duplicate packages")

    def _release(self, job: dict, *, reason: str = "Worker lease expired") -> None:
        job.update(
            status="queued" if job["attempt"] < MAX_ATTEMPTS else "failed",
            worker_id=None,
            lease_id=None,
            lease_expires_at=None,
            updated_at=isoformat(utc_now()),
        )
        if job["status"] == "failed":
            job["completed_at"] = job["updated_at"]
            job["summary"] = f"{reason} after maximum attempts"
        self.store.write("scanner-worker-jobs", job["job_id"], job)

    def claim_next(self, authenticated: dict) -> dict | None:
        with self.store.locked():
            worker = self._current(authenticated)
            if self.public(worker)["status"] != "online":
                return None
            jobs = sorted(
                self.store.list_by_field(
                    "scanner-worker-jobs", "site_id", worker["site_id"]
                ),
                key=lambda item: item["created_at"],
            )
            now = utc_now()
            for job in jobs:
                if (
                    job["status"] == "leased"
                    and parse_timestamp(job["lease_expires_at"]) <= now
                ):
                    self._release(job)
            if any(
                job["status"] == "leased" and job["worker_id"] == worker["worker_id"]
                for job in jobs
            ):
                return None
            for job in jobs:
                if job["status"] != "queued" or job["site_id"] != worker["site_id"]:
                    continue
                if parse_timestamp(job["expires_at"]) <= now:
                    job.update(
                        status="failed",
                        summary="Job expired before claim",
                        completed_at=isoformat(now),
                        updated_at=isoformat(now),
                    )
                elif not self.sites.approved(
                    job["site_id"], job["target_ip"], job["profile"]
                ):
                    job.update(
                        status="cancelled",
                        summary="Site scope approval is inactive",
                        completed_at=isoformat(now),
                        updated_at=isoformat(now),
                    )
                elif not self._nuclei_source_current(job):
                    job.update(
                        status="cancelled",
                        summary="Source asset changed after job creation",
                        completed_at=isoformat(now),
                        updated_at=isoformat(now),
                    )
                elif job["capability"] in worker["available_capabilities"]:
                    job.update(
                        status="leased",
                        attempt=job["attempt"] + 1,
                        worker_id=worker["worker_id"],
                        lease_id=str(uuid4()),
                        lease_expires_at=isoformat(
                            now + timedelta(seconds=LEASE_SECONDS)
                        ),
                        updated_at=isoformat(now),
                    )
                else:
                    continue
                self.store.write("scanner-worker-jobs", job["job_id"], job)
                if job["status"] == "leased":
                    return job
            return None

    def _active_lease(self, authenticated: dict, job_id: str, lease_id: str) -> dict:
        worker = self._current(authenticated)
        job = self.store.read("scanner-worker-jobs", job_id)
        if job is None:
            raise WorkerNotFound
        if job["status"] != "leased" or job["worker_id"] != worker["worker_id"]:
            raise WorkerConflict("Job is not leased to this worker")
        if not hmac.compare_digest(job["lease_id"], lease_id):
            raise WorkerConflict("Invalid job lease")
        if parse_timestamp(job["lease_expires_at"]) <= utc_now():
            raise WorkerConflict("Job lease expired")
        if parse_timestamp(job["expires_at"]) <= utc_now():
            job.update(
                status="failed",
                summary="Job deadline expired",
                completed_at=isoformat(utc_now()),
                updated_at=isoformat(utc_now()),
            )
            self.store.write("scanner-worker-jobs", job_id, job)
            return job
        if not self.sites.approved(job["site_id"], job["target_ip"], job["profile"]):
            job.update(
                status="cancelled",
                summary="Site scope approval is inactive",
                completed_at=isoformat(utc_now()),
                updated_at=isoformat(utc_now()),
            )
            self.store.write("scanner-worker-jobs", job_id, job)
        elif not self._nuclei_source_current(job):
            job.update(
                status="cancelled",
                summary="Source asset changed after job creation",
                completed_at=isoformat(utc_now()),
                updated_at=isoformat(utc_now()),
            )
            self.store.write("scanner-worker-jobs", job_id, job)
        return job

    def renew(
        self,
        authenticated: dict,
        job_id: str,
        lease_id: str,
        *,
        progress: int | None = None,
        phase: str | None = None,
    ) -> dict:
        with self.store.locked():
            job = self._active_lease(authenticated, job_id, lease_id)
            if job["status"] == "leased":
                now = utc_now()
                job["lease_expires_at"] = isoformat(
                    now + timedelta(seconds=LEASE_SECONDS)
                )
                job["updated_at"] = isoformat(now)
                if progress is not None:
                    job["progress"] = progress
                if phase is not None:
                    job["phase"] = phase
                self.store.write("scanner-worker-jobs", job_id, job)
        if job["status"] == "cancelled":
            raise WorkerScopeError(job["summary"])
        if job["status"] == "failed":
            raise WorkerConflict("Job deadline expired")
        return job

    def complete(self, authenticated: dict, job_id: str, result: WorkerResult) -> dict:
        with self.store.locked():
            worker = self._current(authenticated)
            existing = self.store.read("scanner-worker-jobs", job_id)
            if existing is None:
                raise WorkerNotFound
            if existing["status"] in {"completed", "failed"}:
                if (
                    existing["worker_id"] == worker["worker_id"]
                    and existing["lease_id"] == str(result.lease_id)
                    and existing["status"] == result.status
                    and existing["summary"] == result.summary
                    and existing["evidence"] == result.evidence
                ):
                    return existing
                raise WorkerConflict("Job is already complete")
            job = self._active_lease(authenticated, job_id, str(result.lease_id))
            rejected_status = job["status"] if job["status"] != "leased" else None
            if job["status"] == "leased":
                self._validate_nuclei_evidence(job, result)
                self._validate_greenbone_evidence(job, result)
                self._validate_inventory_evidence(job, result)
                now = isoformat(utc_now())
                job.update(
                    status=result.status,
                    summary=result.summary,
                    evidence=result.evidence,
                    completed_at=now,
                    updated_at=now,
                    lease_expires_at=None,
                    progress=100
                    if result.status == "completed"
                    else job.get("progress"),
                    phase="Done" if result.status == "completed" else job.get("phase"),
                )
                self.store.write("scanner-worker-jobs", job_id, job)
                record_activity(
                    self.store,
                    event_type=f"scanner_job.{result.status}",
                    message=result.summary,
                    actor_type="scanner_worker",
                    actor_id=authenticated["worker_id"],
                    resource_type="scanner_job",
                    resource_id=job_id,
                    details={"site_id": job["site_id"]},
                )
        if rejected_status == "cancelled":
            raise WorkerScopeError(job["summary"])
        if rejected_status == "failed":
            raise WorkerConflict("Job deadline expired")
        return job

    def list_jobs(
        self, *, asset_id: str | None = None, site_id: str | None = None
    ) -> list[dict]:
        if asset_id:
            jobs = self.store.list_by_field(
                "scanner-worker-jobs", "source_asset_id", asset_id
            )
        elif site_id:
            jobs = self.store.list_by_field("scanner-worker-jobs", "site_id", site_id)
        else:
            jobs = self.store.list("scanner-worker-jobs")
        return [job for job in jobs if not site_id or job["site_id"] == site_id]

    def get_job(self, job_id: str) -> dict:
        job = self.store.read("scanner-worker-jobs", job_id)
        if job is None:
            raise WorkerNotFound
        return job
