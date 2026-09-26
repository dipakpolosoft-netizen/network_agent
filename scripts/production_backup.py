"""Stream a PostgreSQL backup safely and rehearse restore in an isolated container."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml"]
POSTGRES_RESTORE_IMAGE = (
    "postgres:17@sha256:d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f"
)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=ROOT, check=False, **kwargs)


def archive_hash(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    with path.open("rb") as archive:
        if archive.read(5) != b"PGDMP":
            raise ValueError("Not a PostgreSQL custom-format archive")
        archive.seek(0)
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            digest.update(chunk)
    return path.stat().st_size, digest.hexdigest()


def backup(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = destination / f"forgesec-{stamp}-{secrets.token_hex(4)}.dump"
    partial = archive.with_suffix(".partial")
    try:
        with partial.open("xb") as output:
            result = run(
                COMPOSE + [
                    "exec", "-T", "postgres", "pg_dump", "--no-password",
                    "-U", "forgesec", "-d", "forgesec", "-Fc",
                ],
                stdout=output,
                stderr=subprocess.PIPE,
            )
        if result.returncode:
            raise RuntimeError("pg_dump failed; confirm PostgreSQL is healthy")
        size, digest = archive_hash(partial)
        if size < 100:
            raise RuntimeError("Backup is unexpectedly small")
        os.replace(partial, archive)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    print(f"Backup: {archive}")
    print(f"Bytes: {size}")
    print(f"SHA-256: {digest}")
    print("Next: run restore-check against this archive on the deployment host.")


def restore_check(archive: Path) -> None:
    if not archive.is_file():
        raise ValueError("Backup archive does not exist")
    size, digest = archive_hash(archive)
    if size < 100:
        raise ValueError("Backup is unexpectedly small")
    name = f"forgesec-restore-check-{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(24)
    created = False
    try:
        result = run(
            [
                "docker", "run", "--detach", "--rm", "--name", name,
                "--network", "none", "-e", "POSTGRES_USER=forgesec",
                "-e", f"POSTGRES_PASSWORD={password}",
                "-e", "POSTGRES_DB=forgesec", POSTGRES_RESTORE_IMAGE,
            ],
            capture_output=True,
        )
        if result.returncode:
            raise RuntimeError("Could not start isolated PostgreSQL restore container")
        created = True
        for _ in range(60):
            ready = run(
                ["docker", "exec", name, "pg_isready", "-U", "forgesec", "-d", "forgesec"],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Restore container did not become ready")
        copied = run(
            ["docker", "cp", str(archive.resolve()), f"{name}:/tmp/forgesec.dump"],
            capture_output=True,
        )
        if copied.returncode:
            raise RuntimeError("Could not copy backup into restore container")
        restored = run(
            [
                "docker", "exec", name, "pg_restore", "--exit-on-error",
                "--no-owner", "--no-acl", "-U", "forgesec", "-d", "forgesec",
                "/tmp/forgesec.dump",
            ],
            capture_output=True,
        )
        if restored.returncode:
            raise RuntimeError("pg_restore failed in isolated PostgreSQL")
        counts = run(
            [
                "docker", "exec", name, "psql", "-U", "forgesec", "-d", "forgesec",
                "-At", "-c", "SELECT (SELECT count(*) FROM forgesec_schema_version), "
                "(SELECT count(*) FROM forgesec_documents), "
                "(SELECT count(*) FROM forgesec_activity)",
            ],
            capture_output=True,
            text=True,
        )
        if counts.returncode or not counts.stdout.strip().startswith("1|"):
            raise RuntimeError("Restored ForgeSec schema is missing or invalid")
        print(f"Restore check passed for {archive}")
        print(f"Bytes: {size}; SHA-256: {digest}")
        print(f"Schema version, documents, activity rows: {counts.stdout.strip()}")
        print("The isolated restore container is being removed; production is unchanged.")
    finally:
        if created:
            stopped = run(["docker", "stop", "--time", "1", name], capture_output=True)
            if stopped.returncode:
                print(f"Warning: could not stop isolated container {name}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="action", required=True)
    backup_command = subcommands.add_parser("backup")
    backup_command.add_argument("--output-dir", type=Path, required=True)
    restore_command = subcommands.add_parser("restore-check")
    restore_command.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "backup":
            backup(args.output_dir)
        else:
            restore_check(args.archive)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Backup operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
