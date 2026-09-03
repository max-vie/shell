"""Test the source-only security-tooling supply and Trivy gate."""

from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


supply = load("validate_security_tooling", ROOT / "tar/scripts/validate_security_tooling.py")
trivy = load("run_trivy_scan", ROOT / "tar/scripts/run_trivy_scan.py")


def report(image: str, severity: str | None = None) -> dict[str, object]:
    vulnerabilities = [] if severity is None else [{"VulnerabilityID": "CVE-test", "Severity": severity}]
    return {
        "SchemaVersion": 2,
        "ArtifactName": image,
        "ArtifactType": "container_image",
        "Metadata": {"RepoDigests": [image]},
        "Results": [{"Target": "image", "Vulnerabilities": vulnerabilities}],
    }


class SecurityToolingTests(unittest.TestCase):
    def test_public_tool_pins_validate(self) -> None:
        lock = supply.validate()
        self.assertEqual(lock["tools"]["trivy"]["version"], "0.73.0")
        self.assertEqual(lock["tools"]["kube-bench"]["version"], "0.16.0")
        self.assertEqual(lock["tools"]["k6"]["version"], "2.1.0")

    def test_trivy_report_gate(self) -> None:
        image = "registry.shell.internal/shell/release-feed@sha256:" + "a" * 64
        self.assertEqual(trivy.validate_report(report(image), image)["HIGH"], 0)
        with self.assertRaisesRegex(trivy.ScanError, "HIGH/CRITICAL"):
            trivy.validate_report(report(image, "HIGH"), image)

    def test_trivy_command_is_offline_and_does_not_take_credentials(self) -> None:
        command = trivy.build_command(
            "trivy",
            "docker.io/library/alpine@sha256:" + "b" * 64,
            Path("/cache"),
            Path("/report"),
        )
        self.assertIn("--skip-db-update", command)
        self.assertIn("--ignore-unfixed", command)
        self.assertNotIn("--password", command)
        self.assertNotIn("--username", command)

    def test_trivy_scan_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            (cache / "db").mkdir(parents=True, mode=0o700)
            cache.chmod(0o700)
            (cache / "db/trivy.db").write_bytes(b"db")
            (cache / "db/metadata.json").write_text("{}", encoding="utf-8")
            report_path = root / "evidence/report.json"
            image = "registry.shell.internal/shell/system/release-feed@sha256:" + "d" * 64

            def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps(report(image)), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(trivy.subprocess, "run", side_effect=fake_run):
                self.assertEqual(trivy.scan(image, report_path, cache)["HIGH"], 0)
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(trivy.ScanError, "overwrite"):
                trivy.scan(image, report_path, cache)


if __name__ == "__main__":
    unittest.main()
