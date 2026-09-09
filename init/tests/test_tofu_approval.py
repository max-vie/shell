from __future__ import annotations

import json
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path



SCRIPT = Path(__file__).resolve().parents[1] / "scripts/validate_tofu_approval.py"
SPEC = importlib.util.spec_from_file_location("validate_tofu_approval", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TofuApprovalTests(unittest.TestCase):
    def record(self, path: Path, **overrides: object) -> None:
        value: dict[str, object] = {
            "schema_version": "1.0",
            "status": "approved",
            "project_id": "shell-platform",
            "root": "network",
            "commit": "a" * 40,
            "approval": "environment-gcp/init/tofu/network",
            "plan_sha256": "b" * 64,
            "approved_at": "2026-09-09T00:00:00Z",
        }
        value.update(overrides)
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)

    def test_accepts_exact_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            self.record(path)
            record = validator.load_record(path)
            validator.validate_record(
                record,
                project_id="shell-platform",
                root="network",
                commit="a" * 40,
                approval="environment-gcp/init/tofu/network",
                digest="b" * 64,
            )

    def test_rejects_digest_or_root_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            self.record(path)
            record = validator.load_record(path)
            with self.assertRaisesRegex(validator.ApprovalError, "digest"):
                validator.validate_record(
                    record,
                    project_id="shell-platform",
                    root="network",
                    commit="a" * 40,
                    approval="environment-gcp/init/tofu/network",
                    digest="c" * 64,
                )
            with self.assertRaisesRegex(validator.ApprovalError, "root"):
                validator.validate_record(
                    record,
                    project_id="shell-platform",
                    root="shared-nodes",
                    commit="a" * 40,
                    approval="environment-gcp/init/tofu/network",
                    digest="b" * 64,
                )


if __name__ == "__main__":
    unittest.main()
