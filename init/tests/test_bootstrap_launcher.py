"""Test the read-only GCP bootstrap launcher boundary."""

from __future__ import annotations

import importlib.util
import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "init/scripts/run_gcp_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("run_gcp_bootstrap", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load bootstrap launcher")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class TestBootstrapLauncher(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        private = self.root / ".local/gcp-bootstrap"
        private.mkdir(parents=True, exist_ok=True)
        private.chmod(0o700)
        self._write_private(private / "project.json", {"project_id": "shell-platform"})
        self._write_private(
            private / "ledger.json",
            {
                "schema_version": "1.0",
                "trial_start": "2026-08-05",
                "trial_end": "2026-11-03",
                "credit_amount": "88.92",
                "credit_percent": "34",
                "warning_threshold": "5",
                "screenshot": ".local/gcp-bootstrap/credits.png",
            },
        )
        self._write_private(private / "credits.png", b"png")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_private(path: Path, value: str | bytes | dict[str, Any]) -> None:
        if isinstance(value, bytes):
            path.write_bytes(value)
        elif isinstance(value, dict):
            path.write_text(json.dumps(value), encoding="utf-8")
        else:
            path.write_text(value, encoding="utf-8")
        path.chmod(0o600)

    def run_gcloud(self, *_: object, **__: object) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    def test_ledger_validates_the_private_record(self) -> None:
        result = launcher.ledger(repository_root=self.root)
        self.assertEqual(result, 0)

    def test_ledger_rejects_a_missing_screenshot(self) -> None:
        (self.root / ".local/gcp-bootstrap/credits.png").unlink()
        with self.assertRaises(launcher.BootstrapLauncherError):
            launcher.ledger(repository_root=self.root)

    def test_discover_requires_private_inputs(self) -> None:
        (self.root / ".local/gcp-bootstrap/project.json").chmod(0o644)
        with self.assertRaises(launcher.BootstrapLauncherError):
            launcher.discover(
                repository_root=self.root,
                run_process=self.run_gcloud,
            )

    def test_discover_rejects_an_invalid_project_id(self) -> None:
        self._write_private(
            self.root / ".local/gcp-bootstrap/project.json",
            {"project_id": "UPPER"},
        )
        with self.assertRaises(launcher.BootstrapLauncherError):
            launcher.discover(
                repository_root=self.root,
                run_process=self.run_gcloud,
            )

    def test_verify_requires_billing_enabled(self) -> None:
        def run(command: list[str], **kwargs: object) -> SimpleNamespace:
            if "billing" in command:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps({"billingEnabled": False}), stderr=""
                )
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")

        with self.assertRaises(launcher.BootstrapLauncherError):
            launcher.verify(repository_root=self.root, run_process=run)

    def test_verify_requires_the_deployment_service_account(self) -> None:
        def run(command: list[str], **kwargs: object) -> SimpleNamespace:
            if "billing" in command:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps({"billingEnabled": True}), stderr=""
                )
            if "service-accounts" in command:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")

        with self.assertRaises(launcher.BootstrapLauncherError):
            launcher.verify(repository_root=self.root, run_process=run)

    def test_verify_requires_the_custom_role(self) -> None:
        def run(command: list[str], **kwargs: object) -> SimpleNamespace:
            if "billing" in command:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps({"billingEnabled": True}), stderr=""
                )
            if "service-accounts" in command:
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"email": "shell-local-deployer@shell-platform.iam.gserviceaccount.com"}]
                    ),
                    stderr="",
                )
            if "roles" in command:
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")

        with self.assertRaises(launcher.BootstrapLauncherError):
            launcher.verify(repository_root=self.root, run_process=run)

    def test_verify_passes_with_a_complete_boundary(self) -> None:
        def run(command: list[str], **kwargs: object) -> SimpleNamespace:
            if "billing" in command:
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps({"billingEnabled": True}), stderr=""
                )
            if "service-accounts" in command:
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"email": "shell-local-deployer@shell-platform.iam.gserviceaccount.com"}]
                    ),
                    stderr="",
                )
            if "roles" in command:
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"name": "projects/shell-platform/roles/shell_local_deployer"}]
                    ),
                    stderr="",
                )
            if "services" in command:
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(
                        [{"config": {"name": api}} for api in sorted(launcher.REQUIRED_APIS)]
                    ),
                    stderr="",
                )
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")

        result = launcher.verify(repository_root=self.root, run_process=run)
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
