"""Regression checks for safe restore rehearsals."""

from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from production_backup import (
    CUSTOMER_BINDING_QUERY,
    archive_hash,
    backup,
    restore_check,
)


class ProductionBackupTests(unittest.TestCase):
    def test_archive_digest_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            content = b"PGDMP" + b"x" * 100
            archive.write_bytes(content)
            self.assertEqual(
                archive_hash(archive),
                (len(content), hashlib.sha256(content).hexdigest()),
            )

    def test_restore_rejects_tampered_archive_before_starting_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            archive.write_bytes(b"PGDMP" + b"x" * 100)
            with patch("production_backup.run") as run:
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    restore_check(archive, "0" * 64, "test-customer")
                run.assert_not_called()

    def test_restore_requires_a_valid_expected_digest_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            archive.write_bytes(b"PGDMP" + b"x" * 100)
            with patch("production_backup.run") as run:
                with self.assertRaisesRegex(ValueError, "Expected SHA-256"):
                    restore_check(archive, "", "test-customer")
                run.assert_not_called()

    def test_failed_dump_removes_partial_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            def fake_run(command, **_kwargs):
                if "psql" in command:
                    return SimpleNamespace(returncode=0, stdout="test-customer\n")
                return SimpleNamespace(returncode=1)

            with patch(
                "production_backup.run",
                side_effect=fake_run,
            ):
                with self.assertRaisesRegex(RuntimeError, "pg_dump failed"):
                    backup(destination, "test-customer")
            self.assertEqual(list(destination.iterdir()), [])

    def test_backup_rejects_another_customer_before_dump(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "new-backups"
            with patch(
                "production_backup.run",
                return_value=SimpleNamespace(
                    returncode=0, stdout="another-customer\n"
                ),
            ) as run:
                with self.assertRaisesRegex(RuntimeError, "customer binding"):
                    backup(destination, "test-customer")
            self.assertEqual(run.call_count, 1)
            self.assertFalse(destination.exists())

    def test_backup_streams_after_matching_customer_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)

            def fake_run(command, **kwargs):
                if "psql" in command:
                    return SimpleNamespace(returncode=0, stdout="test-customer\n")
                kwargs["stdout"].write(b"PGDMP" + b"x" * 100)
                return SimpleNamespace(returncode=0)

            output = io.StringIO()
            with (
                patch("production_backup.run", side_effect=fake_run),
                redirect_stdout(output),
            ):
                backup(destination, "test-customer")
            archives = list(destination.glob("*.dump"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].stat().st_size, 105)
            self.assertEqual(list(destination.glob("*.partial")), [])
            self.assertIn("SHA-256:", output.getvalue())

    def test_failed_restore_stops_isolated_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            archive.write_bytes(b"PGDMP" + b"x" * 100)
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                failed_restore = command[:3] == ["docker", "exec", container_name]
                failed_restore &= "pg_restore" in command
                return SimpleNamespace(returncode=1 if failed_restore else 0)

            container_name = "forgesec-restore-check-test"
            with (
                patch("production_backup.secrets.token_hex", return_value="test"),
                patch("production_backup.run", side_effect=fake_run),
            ):
                with self.assertRaisesRegex(RuntimeError, "pg_restore failed"):
                    restore_check(
                        archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                        "test-customer",
                    )
            self.assertIn(
                ["docker", "stop", "--time", "1", container_name], commands
            )

    def test_restore_checks_customer_binding_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            archive.write_bytes(b"PGDMP" + b"x" * 100)
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                if command[-1] == CUSTOMER_BINDING_QUERY:
                    return SimpleNamespace(returncode=0, stdout="another-customer\n")
                if "psql" in command:
                    return SimpleNamespace(returncode=0, stdout="1|3|4\n")
                return SimpleNamespace(returncode=0)

            with (
                patch("production_backup.secrets.token_hex", return_value="test"),
                patch("production_backup.run", side_effect=fake_run),
            ):
                with self.assertRaisesRegex(RuntimeError, "customer binding"):
                    restore_check(
                        archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                        "test-customer",
                    )
            self.assertIn(
                ["docker", "stop", "--time", "1", "forgesec-restore-check-test"],
                commands,
            )

    def test_failed_restore_cleanup_is_not_reported_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            archive.write_bytes(b"PGDMP" + b"x" * 100)

            def fake_run(command, **_kwargs):
                if command[:2] == ["docker", "stop"]:
                    return SimpleNamespace(returncode=1)
                if command[-1] == CUSTOMER_BINDING_QUERY:
                    return SimpleNamespace(returncode=0, stdout="test-customer\n")
                if "psql" in command:
                    return SimpleNamespace(returncode=0, stdout="1|3|4\n")
                return SimpleNamespace(returncode=0)

            with (
                patch("production_backup.secrets.token_hex", return_value="test"),
                patch("production_backup.run", side_effect=fake_run),
            ):
                with self.assertRaisesRegex(RuntimeError, "Could not stop isolated"):
                    restore_check(
                        archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                        "test-customer",
                    )

    def test_restore_reports_success_after_matching_binding_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "backup.dump"
            archive.write_bytes(b"PGDMP" + b"x" * 100)
            commands = []

            def fake_run(command, **_kwargs):
                commands.append(command)
                if command[-1] == CUSTOMER_BINDING_QUERY:
                    return SimpleNamespace(returncode=0, stdout="test-customer\n")
                if "psql" in command:
                    return SimpleNamespace(returncode=0, stdout="1|3|4\n")
                return SimpleNamespace(returncode=0)

            output = io.StringIO()
            with (
                patch("production_backup.secrets.token_hex", return_value="test"),
                patch("production_backup.run", side_effect=fake_run),
                redirect_stdout(output),
            ):
                restore_check(
                    archive, hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "test-customer",
                )
            self.assertIn("Restore check passed", output.getvalue())
            self.assertIn("container was removed", output.getvalue())
            self.assertIn(
                ["docker", "stop", "--time", "1", "forgesec-restore-check-test"],
                commands,
            )


if __name__ == "__main__":
    unittest.main()
