"""Site-bound, read-only Linux inventory from a central SSH worker."""

from __future__ import annotations

import ipaddress
import os
import shlex
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from forgesec_api.workers.models import LinuxInventoryEvidence
from forgesec_api.workers.runtime_client import (
    WorkerClient,
    WorkerLeaseLost,
    WorkerRuntimeError,
)

VERSION = "0.1.0-ssh-inventory"
MAX_COMMAND_BYTES = 80 * 1024
COMMAND_TIMEOUT = 15
POLL_SECONDS = 10
PACKAGE_LIMIT = 200

PACKAGE_COMMAND = (
    "if command -v dpkg-query >/dev/null 2>&1; then "
    "data=$(LC_ALL=C dpkg-query -W -f='${binary:Package}\\t${Version}\\n' "
    "2>/dev/null) || exit 1; "
    "printf 'dpkg\\n'; printf '%s\\n' \"$data\" | head -n 201; "
    "elif command -v rpm >/dev/null 2>&1; then "
    "data=$(LC_ALL=C rpm -qa --qf '%{NAME}.%{ARCH}\\t%{VERSION}-%{RELEASE}\\n' "
    "2>/dev/null) || exit 1; "
    "printf 'rpm\\n'; printf '%s\\n' \"$data\" | head -n 201; "
    "else printf 'none\\n'; fi"
)


@dataclass(frozen=True)
class SshInventorySettings:
    username: str
    key_path: Path
    known_hosts_path: Path

    @classmethod
    def from_env(cls) -> SshInventorySettings:
        names = (
            "FORGESEC_SSH_INVENTORY_USERNAME",
            "FORGESEC_SSH_INVENTORY_KEY_FILE",
            "FORGESEC_SSH_INVENTORY_KNOWN_HOSTS",
        )
        if any(not os.environ.get(name) for name in names):
            raise WorkerRuntimeError("Missing SSH inventory worker configuration")
        key_path = Path(os.environ[names[1]]).resolve()
        known_hosts_path = Path(os.environ[names[2]]).resolve()
        if not key_path.is_file() or not known_hosts_path.is_file():
            raise WorkerRuntimeError("SSH key or known_hosts file is unavailable")
        if key_path.stat().st_mode & 0o077:
            raise WorkerRuntimeError("SSH private key must not be group/world readable")
        if known_hosts_path.stat().st_mode & 0o022:
            raise WorkerRuntimeError("SSH known_hosts must not be group/world writable")
        username = os.environ[names[0]]
        if (
            not username
            or username != username.strip()
            or username.casefold() == "root"
            or len(username) > 128
        ):
            raise WorkerRuntimeError("Invalid SSH inventory username")
        return cls(username, key_path, known_hosts_path)


def _target(job: dict) -> str:
    if (
        job.get("schema_version") != "1.0"
        or job.get("capability") != "credentialed_inventory"
        or job.get("inventory_profile") != "linux_ssh_readonly"
        or job.get("profile") != "full_tcp"
        or job.get("target_port") is not None
        or job.get("target_scheme") is not None
        or job.get("assessment_profile") is not None
        or job.get("template_profile") is not None
    ):
        raise WorkerRuntimeError("Unsupported SSH inventory job")
    try:
        UUID(job["job_id"])
        UUID(job["lease_id"])
        UUID(job["source_asset_id"])
        UUID(job["source_scan_id"])
        return str(ipaddress.IPv4Address(job["target_ip"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkerRuntimeError("Invalid SSH inventory target") from exc


def open_ssh(settings: SshInventorySettings, target_ip: str):
    try:
        import paramiko
    except ImportError as exc:
        raise WorkerRuntimeError("Install the ssh-inventory API extra") from exc
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(str(settings.known_hosts_path))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=target_ip,
            port=22,
            username=settings.username,
            key_filename=str(settings.key_path),
            timeout=COMMAND_TIMEOUT,
            banner_timeout=COMMAND_TIMEOUT,
            auth_timeout=COMMAND_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        return client
    except BaseException:
        client.close()
        raise


def _command(client, command: str) -> str:
    deadline = time.monotonic() + COMMAND_TIMEOUT
    _stdin, stdout, _stderr = client.exec_command(
        command, timeout=COMMAND_TIMEOUT, get_pty=False
    )
    channel = stdout.channel
    output = bytearray()
    error_bytes = 0
    try:
        while True:
            if time.monotonic() >= deadline:
                raise WorkerRuntimeError("Read-only SSH inventory command timed out")
            received = False
            while channel.recv_ready():
                chunk = channel.recv(min(4096, MAX_COMMAND_BYTES + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_COMMAND_BYTES:
                    raise WorkerRuntimeError("SSH inventory output exceeded the limit")
                received = True
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(min(4096, 4097 - error_bytes))
                if not chunk:
                    break
                error_bytes += len(chunk)
                if error_bytes > 4096:
                    raise WorkerRuntimeError(
                        "SSH inventory error output exceeded limit"
                    )
                received = True
            if channel.exit_status_ready():
                if channel.recv_exit_status() != 0:
                    raise WorkerRuntimeError("Read-only SSH inventory command failed")
                try:
                    return output.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise WorkerRuntimeError(
                        "SSH inventory output is not valid UTF-8"
                    ) from exc
            if not received:
                time.sleep(0.05)
    finally:
        channel.close()


def _os_release(value: str) -> tuple[str, str | None]:
    fields: dict[str, str] = {}
    for line in value.splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        name, raw = line.split("=", 1)
        if name not in {"PRETTY_NAME", "NAME", "VERSION_ID"}:
            continue
        try:
            parsed = shlex.split(raw, posix=True)
        except ValueError:
            continue
        if len(parsed) == 1:
            fields[name] = parsed[0].strip()
    os_name = fields.get("PRETTY_NAME") or fields.get("NAME")
    if not os_name:
        raise WorkerRuntimeError("Target did not report an OS release")
    return os_name[:160], (fields.get("VERSION_ID") or None)


def _packages(value: str) -> tuple[str, list[dict], bool]:
    lines = value.splitlines()
    if not lines or lines[0] not in {"dpkg", "rpm", "none"}:
        raise WorkerRuntimeError("Unsupported Linux package manager response")
    manager = lines[0]
    if manager == "none":
        if len(lines) != 1:
            raise WorkerRuntimeError("Unsupported Linux package manager response")
        return manager, [], False
    if len(lines) == 1:
        raise WorkerRuntimeError("Package query returned no installed packages")
    packages: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in lines[1:]:
        if "\t" not in line:
            raise WorkerRuntimeError("Package query returned malformed data")
        name, version = line.split("\t", 1)
        name, version = name.strip(), version.strip()
        if not name or not version or len(name) > 160 or len(version) > 160:
            raise WorkerRuntimeError("Package query returned malformed data")
        identity = (name, version)
        if identity not in seen:
            seen.add(identity)
            packages.append({"name": name, "version": version})
    truncated = len(lines) - 1 > PACKAGE_LIMIT
    return manager, packages[:PACKAGE_LIMIT], truncated


def run_inventory(
    job: dict,
    settings: SshInventorySettings,
    *,
    on_tick: Callable[[int, str], None],
    ssh_factory: Callable = open_ssh,
) -> dict:
    target_ip = _target(job)
    on_tick(5, "Connecting")
    client = ssh_factory(settings, target_ip)
    try:
        on_tick(20, "Reading OS")
        os_name, os_version = _os_release(_command(client, "cat /etc/os-release"))
        on_tick(45, "Reading host")
        uname = _command(client, "uname -srm").strip().split()
        if len(uname) < 3 or uname[0] != "Linux":
            raise WorkerRuntimeError("Target did not report a Linux kernel")
        on_tick(55, "Reading host")
        hostnames = _command(client, "hostname").strip().splitlines()
        if not hostnames:
            raise WorkerRuntimeError("Target did not report a hostname")
        hostname = hostnames[0]
        on_tick(70, "Reading packages")
        manager, packages, truncated = _packages(_command(client, PACKAGE_COMMAND))
        on_tick(95, "Validating")
        evidence = {
            "schema_version": "1.0",
            "engine": "ssh_inventory",
            "inventory_profile": "linux_ssh_readonly",
            "target_ip": target_ip,
            "hostname": hostname[:255],
            "os_name": os_name,
            "os_version": os_version[:160] if os_version else None,
            "kernel": uname[1][:160],
            "architecture": uname[2][:80],
            "package_manager": manager,
            "packages": packages,
            "packages_truncated": truncated,
        }
        return LinuxInventoryEvidence.model_validate(evidence).model_dump(mode="json")
    finally:
        client.close()


def run_forever(client: WorkerClient, settings: SshInventorySettings) -> None:
    while True:
        try:
            client.heartbeat()
            job = client.claim()
            if job is None:
                time.sleep(POLL_SECONDS)
                continue

            def keep_lease(progress: int, phase: str, claimed_job: dict = job) -> None:
                try:
                    client.renew(claimed_job, progress=progress, phase=phase)
                except WorkerRuntimeError as exc:
                    raise WorkerLeaseLost("SSH inventory lease was lost") from exc

            try:
                evidence = run_inventory(job, settings, on_tick=keep_lease)
                client.finish(
                    job,
                    "completed",
                    f"{len(evidence['packages'])} Linux packages observed",
                    evidence,
                )
            except WorkerLeaseLost:
                print("SSH inventory lease lost", file=sys.stderr)
            except WorkerRuntimeError as exc:
                client.finish(job, "failed", str(exc)[:2000], {})
            except Exception:
                client.finish(job, "failed", "SSH inventory collection failed", {})
        except WorkerRuntimeError as exc:
            if "HTTP 401" in str(exc):
                raise
            print(str(exc), file=sys.stderr)
            time.sleep(POLL_SECONDS)


def main() -> None:
    if os.name != "posix":
        raise WorkerRuntimeError("SSH inventory worker requires a Linux host")
    settings = SshInventorySettings.from_env()
    client = WorkerClient(
        os.environ["FORGESEC_API_URL"],
        os.environ["FORGESEC_WORKER_ID"],
        os.environ["FORGESEC_WORKER_CREDENTIAL"],
        capability="credentialed_inventory",
        version=VERSION,
    )
    try:
        run_forever(client, settings)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
