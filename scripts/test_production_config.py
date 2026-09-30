"""Production preflight regression tests."""

from __future__ import annotations

import copy
import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from check_production_config import main, validate


class ProductionConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = {
            "name": "customer-one",
            "services": {
                "api": {
                    "environment": {
                        "FORGESEC_ENV": "production",
                        "FORGESEC_CUSTOMER_ID": "customer-one",
                        "FORGESEC_AUTH_REQUIRED": "true",
                        "FORGESEC_ALLOW_PUBLIC_SCOPES": "false",
                        "FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA": "false",
                        "FORGESEC_WEB_ORIGIN": "https://scan.company.com",
                        "FORGESEC_DATABASE_URL": (
                            "postgresql://forgesec:pilot-9T2mK4nQ7rL8@postgres:5432/forgesec"
                        ),
                    },
                    "ports": [{"host_ip": "127.0.0.1", "published": "8000"}],
                },
                "web": {
                    "build": {"args": {
                        "FORGESEC_API_PROXY_URL": "http://api:8000",
                        "NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL": "https://scan.company.com",
                    }},
                    "ports": [{"host_ip": "127.0.0.1", "published": "3000"}],
                },
                "postgres": {"environment": {
                    "POSTGRES_PASSWORD": "pilot-9T2mK4nQ7rL8"
                }},
                "caddy": {
                    "environment": {"FORGESEC_PUBLIC_HOST": "scan.company.com"},
                    "ports": [{"published": "80"}, {"published": "443"}],
                },
            }
        }

    def test_valid_production_config(self) -> None:
        self.assertEqual(validate(self.config), [])

    def test_rejects_local_agent_url(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["web"]["build"]["args"][
            "NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL"
        ] = "http://127.0.0.1:8000"
        self.assertTrue(any("AGENT_SERVER_URL" in issue for issue in validate(config)))

    def test_rejects_missing_customer_identity(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["api"]["environment"].pop("FORGESEC_CUSTOMER_ID")
        self.assertTrue(any("CUSTOMER_ID" in issue for issue in validate(config)))

    def test_rejects_default_compose_project(self) -> None:
        config = copy.deepcopy(self.config)
        config["name"] = "forgesec"
        self.assertTrue(any("COMPOSE_PROJECT" in issue for issue in validate(config)))

    def test_rejects_legacy_adoption_in_normal_startup(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["api"]["environment"][
            "FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA"
        ] = "true"
        self.assertTrue(any("adoption" in issue for issue in validate(config)))

    def test_rejects_placeholder_password(self) -> None:
        config = copy.deepcopy(self.config)
        password = "ChangeMePlease12345"
        config["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] = password
        config["services"]["api"]["environment"]["FORGESEC_DATABASE_URL"] = (
            f"postgresql://forgesec:{password}@postgres:5432/forgesec"
        )
        self.assertTrue(any("DATABASE_URL" in issue for issue in validate(config)))

    def test_rejects_exposed_api(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["api"]["ports"][0]["host_ip"] = "0.0.0.0"
        self.assertTrue(any("api must not" in issue for issue in validate(config)))

    def test_rejects_database_password_mismatch(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"] = "different-password"
        self.assertTrue(any("DATABASE_URL" in issue for issue in validate(config)))

    def test_rejects_placeholder_hostname(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["caddy"]["environment"]["FORGESEC_PUBLIC_HOST"] = "forgesec.example"
        self.assertTrue(any("real DNS hostname" in issue for issue in validate(config)))

        config["services"]["caddy"]["environment"]["FORGESEC_PUBLIC_HOST"] = "scan.your-real-domain.com"
        self.assertTrue(any("real DNS hostname" in issue for issue in validate(config)))

        config["services"]["caddy"]["environment"]["FORGESEC_PUBLIC_HOST"] = "192.0.2.1"
        self.assertTrue(any("real DNS hostname" in issue for issue in validate(config)))

    def test_rejects_malformed_urls_without_crashing(self) -> None:
        config = copy.deepcopy(self.config)
        config["services"]["api"]["environment"]["FORGESEC_DATABASE_URL"] = "postgresql://[invalid"
        config["services"]["web"]["build"]["args"][
            "NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL"
        ] = "https://scan.company.com:bad"
        issues = validate(config)
        self.assertTrue(any("DATABASE_URL" in issue for issue in issues))
        self.assertTrue(any("AGENT_SERVER_URL" in issue for issue in issues))

    def test_compose_failure_reports_setting_names_without_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("", encoding="utf-8")
            stderr = io.StringIO()
            with (
                patch("sys.argv", ["check_production_config.py", "--env-file", str(env_file)]),
                patch(
                    "check_production_config.subprocess.run",
                    return_value=SimpleNamespace(
                        returncode=1,
                        stderr="FORGESEC_DATABASE_URL is unset; secret-value-123",
                    ),
                ),
                redirect_stderr(stderr),
            ):
                self.assertEqual(main(), 2)
            self.assertIn("FORGESEC_DATABASE_URL", stderr.getvalue())
            self.assertNotIn("secret-value-123", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
