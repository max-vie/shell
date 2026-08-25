"""Test the public SUDO identity and access contracts."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "sudo/scripts/validate_access_contracts.py"
SPEC = importlib.util.spec_from_file_location("validate_access_contracts", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load SUDO access validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestAccessContracts(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.access_root = self.root / "sudo/access"
        self.access_root.mkdir(parents=True)
        source = SOURCE_ROOT / "sudo/access"
        self.documents: dict[str, dict[str, object]] = {}
        for name, filename in validator.CONTRACT_FILES.items():
            document = json.loads((source / filename).read_text(encoding="utf-8"))
            self.documents[name] = document
            self.write(name, document)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, document: dict[str, object]) -> None:
        filename = validator.CONTRACT_FILES[name]
        (self.access_root / filename).write_text(
            json.dumps(document),
            encoding="utf-8",
        )

    def altered(self, name: str) -> dict[str, object]:
        return copy.deepcopy(self.documents[name])

    def test_current_access_contracts_validate(self) -> None:
        documents = validator.validate_contracts(self.root)
        self.assertEqual(set(documents), set(validator.CONTRACT_FILES))

    def test_rejects_unknown_fields_and_invalid_json(self) -> None:
        identity = self.altered("identity")
        identity["credential"] = "do-not-allow-new-fields"
        self.write("identity", identity)
        with self.assertRaisesRegex(validator.AccessContractError, "shape changed"):
            validator.validate_contracts(self.root)

        (self.access_root / validator.CONTRACT_FILES["identity"]).write_bytes(b"\xff")
        with self.assertRaisesRegex(validator.AccessContractError, "invalid JSON"):
            validator.validate_contracts(self.root)

    def test_rejects_identity_group_drift(self) -> None:
        freeipa = self.altered("freeipa")
        freeipa["identity"]["groups"] = ["platform-admins"]  # type: ignore[index]
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(validator.AccessContractError, "FreeIPA groups"):
            validator.validate_contracts(self.root)

        self.write("freeipa", self.documents["freeipa"])
        kubernetes = self.altered("kubernetes")
        kubernetes["identity"]["required_groups"] = ["platform-admins"]  # type: ignore[index]
        self.write("kubernetes", kubernetes)
        with self.assertRaisesRegex(validator.AccessContractError, "Kubernetes groups"):
            validator.validate_contracts(self.root)

    def test_rejects_changed_node_and_cluster_scope(self) -> None:
        delivery = self.altered("delivery")
        delivery["host"]["ip_address"] = "10.77.0.212"  # type: ignore[index]
        self.write("delivery", delivery)
        with self.assertRaisesRegex(validator.AccessContractError, "host identity"):
            validator.validate_contracts(self.root)

        self.write("delivery", self.documents["delivery"])
        identity = self.altered("identity")
        identity["cluster_scope"] = ["gcp"]
        self.write("identity", identity)
        with self.assertRaisesRegex(validator.AccessContractError, "cluster scope"):
            validator.validate_contracts(self.root)

    def test_rejects_implemented_or_secret_store_claims(self) -> None:
        freeipa = self.altered("freeipa")
        freeipa["private_custody"]["secret_store"] = validator.UNDECIDED + "-changed"  # type: ignore[index]
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(validator.AccessContractError, "private custody"):
            validator.validate_contracts(self.root)

        self.write("freeipa", self.documents["freeipa"])
        kubernetes = self.altered("kubernetes")
        kubernetes["required_contracts"]["service_endpoints"]["status"] = "implemented"  # type: ignore[index]
        self.write("kubernetes", kubernetes)
        with self.assertRaisesRegex(validator.AccessContractError, "required contracts"):
            validator.validate_contracts(self.root)

    def test_rejects_missing_or_symlinked_contracts(self) -> None:
        identity_path = self.access_root / validator.CONTRACT_FILES["identity"]
        identity_path.unlink()
        with self.assertRaisesRegex(validator.AccessContractError, "missing regular"):
            validator.validate_contracts(self.root)

        outside = Path(self.temporary.name) / "identity.json"
        outside.write_text(json.dumps(self.documents["identity"]), encoding="utf-8")
        identity_path.symlink_to(outside)
        with self.assertRaisesRegex(validator.AccessContractError, "missing regular"):
            validator.validate_contracts(self.root)

    def test_main_reports_controlled_secret_free_errors(self) -> None:
        identity = self.altered("identity")
        identity["proof_status"] = "live-verified"
        self.write("identity", identity)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(validator, "REPOSITORY_ROOT", self.root):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = validator.main()
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("must remain source-only", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
