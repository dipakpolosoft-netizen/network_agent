"""Offline tests for release source/version hygiene."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from check_release_baseline import lock_issues, sensitive_tracked_paths, unpinned_container_images, version_issues


class ReleaseBaselineTests(unittest.TestCase):
    def test_versions_and_lock_agree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                "services/api/pyproject.toml": '[project]\nversion = "1.2.3"\n',
                "agent_builder/pyproject.toml": '[project]\nversion = "1.2.3"\n',
                "agent_builder/src/forgesec_agent/__init__.py": '__version__ = "1.2.3"\n',
                "apps/web/package.json": json.dumps({"version": "1.2.3", "dependencies": {"next": "1"}}),
                "apps/web/package-lock.json": json.dumps({
                    "version": "1.2.3", "packages": {"": {"version": "1.2.3", "dependencies": {"next": "1"}}},
                }),
            }
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            self.assertEqual(version_issues(root), ("1.2.3", []))
            path = root / "apps/web/package-lock.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["packages"][""]["dependencies"]["next"] = "2"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertIn("dependencies differs", " ".join(version_issues(root)[1]))

    def test_sensitive_files_are_not_tracked(self) -> None:
        paths = [
            ".env.example", "services/api/runtime-data/.gitkeep", "app/main.py",
            ".env", "secrets/site.key", "agent_builder/installer/dependencies/nmap-oem.exe",
        ]
        self.assertEqual(sensitive_tracked_paths(paths), paths[-3:])

    def test_moving_container_tags_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                "services/api/Dockerfile", "apps/web/Dockerfile",
                "docker-compose.yml", "docker-compose.production.yml",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("FROM python:3.13-slim\nimage: postgres:17\n", encoding="utf-8")
            self.assertEqual(len(unpinned_container_images(root)), 8)

    def test_lock_requires_pins_hashes_and_expected_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "services/api/requirements.lock"
            path = root / name
            path.parent.mkdir(parents=True)
            self.assertIn("missing", " ".join(lock_issues(root, name)))
            path.write_text("", encoding="utf-8")
            self.assertIn("empty", " ".join(lock_issues(root, name)))
            path.write_text("fastapi==0.1 \\\n    --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
            self.assertIn("lacks required packages", " ".join(lock_issues(root, name)))
            path.write_text("fastapi==0.1 \\\n    # no hash\n", encoding="utf-8")
            self.assertIn("lacks a SHA-256", " ".join(lock_issues(root, name)))


if __name__ == "__main__":
    unittest.main()
