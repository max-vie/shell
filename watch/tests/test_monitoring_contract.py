"""Test WATCH's source-only metrics contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


WATCH_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = WATCH_ROOT / "scripts/validate_monitoring_contract.py"
SPEC = importlib.util.spec_from_file_location("validate_monitoring_contract", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load WATCH contract validator: {SCRIPT}")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class TestMonitoringContract(unittest.TestCase):
    def test_current_contract_validates(self) -> None:
        document = validator.validate_contract()
        self.assertEqual("cluster-monitoring-requirements", document["contract_id"])
        self.assertEqual("environment-gcp", document["environment"])
        self.assertEqual("gcp-k3s-01", document["cluster"]["first_server"])
        self.assertEqual(["k3s", "helm"], document["required_guest_tools"])
        self.assertEqual("make", document["deployment"]["owner"])
        self.assertEqual(["make", "watch"], document["consumer_owners"])

    def test_contract_rejects_cluster_drift(self) -> None:
        source = json.loads(
            (WATCH_ROOT / "contracts/cluster-monitoring-requirements.json").read_text(
                encoding="utf-8"
            )
        )
        altered = copy.deepcopy(source)
        altered["cluster"]["first_server_address"] = "10.77.0.202"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(
                validator.MonitoringContractError, "cluster boundary"
            ):
                validator.validate_contract(path)

    def test_contract_rejects_service_selector_drift(self) -> None:
        source = json.loads(
            (WATCH_ROOT / "contracts/cluster-monitoring-requirements.json").read_text(
                encoding="utf-8"
            )
        )
        altered = copy.deepcopy(source)
        altered["deployment"]["service_selectors"]["prometheus"] = "release=other"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(
                validator.MonitoringContractError, "deployment boundary"
            ):
                validator.validate_contract(path)

    def test_contract_requires_full_tar_supply_validation(self) -> None:
        with mock.patch.object(
            validator.watch_supply,
            "validate_public",
            side_effect=validator.watch_supply.WatchSupplyError("digest drift"),
        ):
            with self.assertRaisesRegex(
                validator.watch_supply.WatchSupplyError, "digest drift"
            ):
                validator.validate_contract()

    def test_contract_rejects_duplicate_nested_keys(self) -> None:
        source = (
            WATCH_ROOT / "contracts/cluster-monitoring-requirements.json"
        ).read_text(encoding="utf-8")
        altered = source.replace(
            '"release": "shell-watch",',
            '"release": "shell-watch", "release": "other",',
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "contract.json"
            path.write_text(altered, encoding="utf-8")
            with self.assertRaisesRegex(
                validator.MonitoringContractError, "duplicate JSON key: release"
            ):
                validator.validate_contract(path)

    def test_contract_contains_no_private_values_or_unrelated_scope(self) -> None:
        serialized = (
            WATCH_ROOT / "contracts/cluster-monitoring-requirements.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("token", serialized.lower())
        self.assertNotIn("openbao", serialized.lower())
        self.assertNotIn("repository", serialized.lower())


if __name__ == "__main__":
    unittest.main()
