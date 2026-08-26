"""Test MAKE's source-only delivery-node consumer contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "make/scripts/validate_service_node_handoff.py"
SPEC = importlib.util.spec_from_file_location("validate_service_node_handoff", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load service handoff validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestServiceNodeHandoff(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository_root = Path(self.temporary.name) / "repository"
        for relative in (
            "make/contracts/service-node-handoff-requirements.json",
            "sudo/access/freeipa-host-profile.json",
            "sudo/access/delivery-host-profile.json",
            "sudo/secrets/delivery-input-contract.json",
            "tar/manifests/delivery-supply.json",
        ):
            target = self.repository_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, target)
        self.contract_path = (
            self.repository_root
            / "make/contracts/service-node-handoff-requirements.json"
        )
        self.contract = json.loads(
            (
                SOURCE_ROOT / "make/contracts/service-node-handoff-requirements.json"
            ).read_text(encoding="utf-8")
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, value: dict[str, Any]) -> None:
        self.contract_path.write_text(json.dumps(value), encoding="utf-8")

    def test_current_contract_matches_the_delivery_boundary(self) -> None:
        contract = validator.validate_contract(
            SOURCE_ROOT / "make/contracts/service-node-handoff-requirements.json",
            repository_root=SOURCE_ROOT,
        )
        self.assertEqual(contract["policy_owner"], "make")
        self.assertEqual(contract["producer_owner"], "init")
        self.assertEqual(contract["required_identity"]["service_node_id"], "delivery-01")

    def test_rejects_contract_requirement_drift(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []

        os_drift = copy.deepcopy(self.contract)
        os_drift["required_identity"]["os"]["major_version"] = 12
        cases.append(("OS", os_drift, "service identity requirements changed"))

        trust_drift = copy.deepcopy(self.contract)
        trust_drift["trust"]["forgejo_host"] = "other.shell.internal"
        cases.append(("trust", trust_drift, "service trust requirements changed"))

        artifact_drift = copy.deepcopy(self.contract)
        artifact_drift["source_contracts"]["artifact_supply"] = (  # type: ignore[index]
            "tar/manifests/other.json"
        )
        cases.append(("artifact", artifact_drift, "source contracts changed"))

        owner_drift = copy.deepcopy(self.contract)
        owner_drift["policy_owner"] = "init"
        cases.append(("owner", owner_drift, "MAKE must own"))

        version_drift = copy.deepcopy(self.contract)
        version_drift["contract_version"] = "2.0.0"
        cases.append(("version", version_drift, "version changed"))

        package_drift = copy.deepcopy(self.contract)
        package_drift["required_rootless_packages"] = ["podman"]
        cases.append(("packages", package_drift, "package requirements changed"))

        service_drift = copy.deepcopy(self.contract)
        service_drift["required_service"]["port"] = 80  # type: ignore[index]
        cases.append(("service", service_drift, "endpoint requirements changed"))

        excluded_drift = copy.deepcopy(self.contract)
        excluded_drift["excluded_fields"] = []
        cases.append(("excluded", excluded_drift, "producer boundary changed"))

        for label, value, message in cases:
            with self.subTest(case=label):
                self.write(value)
                with self.assertRaisesRegex(validator.ServiceHandoffError, message):
                    validator.validate_contract(
                        self.contract_path,
                        repository_root=self.repository_root,
                    )

    def test_rejects_cross_owner_contract_mismatch(self) -> None:
        delivery_path = self.repository_root / "sudo/access/delivery-host-profile.json"
        delivery = json.loads(delivery_path.read_text(encoding="utf-8"))
        delivery["service"]["fqdn"] = "other.shell.internal"
        delivery_path.write_text(json.dumps(delivery), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.ServiceHandoffError, "service FQDN mismatch"
        ):
            validator.validate_contract(
                self.contract_path,
                repository_root=self.repository_root,
            )

    def test_rejects_malformed_duplicate_and_symlinked_contracts(self) -> None:
        self.contract_path.write_bytes(b"{")
        with self.assertRaisesRegex(validator.ServiceHandoffError, "invalid JSON"):
            validator.validate_contract(
                self.contract_path,
                repository_root=self.repository_root,
            )

        self.contract_path.write_text(
            '{"schema_version":"1.0","schema_version":"1.0"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(validator.ServiceHandoffError, "duplicate JSON"):
            validator.validate_contract(
                self.contract_path,
                repository_root=self.repository_root,
            )

        target = Path(self.temporary.name) / "target.json"
        target.write_text(json.dumps(self.contract), encoding="utf-8")
        self.contract_path.unlink()
        self.contract_path.symlink_to(target)
        with self.assertRaisesRegex(validator.ServiceHandoffError, "symlinked"):
            validator.validate_contract(
                self.contract_path,
                repository_root=self.repository_root,
            )

    def test_rejects_missing_or_symlinked_source_contracts(self) -> None:
        for relative in validator.EXPECTED_SOURCE_CONTRACTS.values():
            with self.subTest(reference=relative):
                target = self.repository_root / relative
                source = SOURCE_ROOT / relative
                target.unlink()
                with self.assertRaisesRegex(
                    validator.ServiceHandoffError, "missing regular"
                ):
                    validator.validate_contract(
                        self.contract_path,
                        repository_root=self.repository_root,
                    )

                outside = Path(self.temporary.name) / f"outside-{target.name}"
                shutil.copyfile(source, outside)
                target.symlink_to(outside)
                with self.assertRaisesRegex(
                    validator.ServiceHandoffError, "symlinked"
                ):
                    validator.validate_contract(
                        self.contract_path,
                        repository_root=self.repository_root,
                    )
                target.unlink()
                shutil.copyfile(source, target)

    def test_rejects_source_contract_through_symlinked_ancestor(self) -> None:
        source_directory = self.repository_root / "tar/manifests"
        real_directory = self.repository_root / "tar/manifests-real"
        source_directory.rename(real_directory)
        outside = Path(self.temporary.name) / "outside-manifests"
        shutil.copytree(real_directory, outside)
        source_directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(validator.ServiceHandoffError, "symlinked"):
            validator.validate_contract(
                self.contract_path,
                repository_root=self.repository_root,
            )


if __name__ == "__main__":
    unittest.main()
