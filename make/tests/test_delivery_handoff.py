"""Test the path-only MAKE delivery handoff."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "make/scripts/render_delivery_handoff.py"
SPEC = importlib.util.spec_from_file_location("render_delivery_handoff", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load delivery handoff generator: {SCRIPT}")
handoff = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(handoff)


class TestDeliveryHandoff(unittest.TestCase):
    def test_current_public_contracts_bind_without_private_reads(self) -> None:
        document = handoff.validate_public(SOURCE_ROOT)
        self.assertEqual("source-only", document["proof_status"])
        self.assertEqual("delivery-01", document["service_node_id"])
        self.assertEqual(
            str(SOURCE_ROOT / ".local/sudo/delivery/bootstrap.sops.json"),
            document["sudo_delivery_bootstrap_path"],
        )
        self.assertEqual(
            str(SOURCE_ROOT / ".local/ansible/connection-inventory.yml"),
            document["init_connection_inventory_path"],
        )

    def test_rendered_handoff_is_path_only_and_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "delivery-ansible-vars.json"
            rendered = handoff.write_handoff(output, SOURCE_ROOT)
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual(rendered, handoff.validate_handoff(output, SOURCE_ROOT))
            serialized = output.read_text(encoding="utf-8")

        self.assertEqual(handoff.HANDOFF_FIELDS, set(rendered))
        self.assertNotIn("admin_password", serialized)
        self.assertNotIn("private_key", serialized)
        self.assertNotIn("api_token", serialized)
        self.assertNotIn("-----BEGIN", serialized)
        self.assertEqual(
            64,
            len(rendered["service_ca_sha256"]),
        )
        self.assertEqual(
            64,
            len(rendered["service_contract_digest"]),
        )

    def test_validator_rejects_handoff_path_and_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "delivery-ansible-vars.json"
            handoff.write_handoff(output, SOURCE_ROOT)
            document = json.loads(output.read_text(encoding="utf-8"))

            document["sudo_forgejo_tls_path"] = str(
                SOURCE_ROOT / ".local/sudo/wrong.sops.json"
            )
            output.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                handoff.DeliveryHandoffError, "does not match public contracts"
            ):
                handoff.validate_handoff(output, SOURCE_ROOT)

            document["sudo_forgejo_tls_path"] = str(
                SOURCE_ROOT / ".local/sudo/delivery/forgejo-public-tls.sops.json"
            )
            document["service_ca_sha256"] = "0" * 64
            output.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(
                handoff.DeliveryHandoffError, "does not match public contracts"
            ):
                handoff.validate_handoff(output, SOURCE_ROOT)

    def test_public_reader_rejects_symlinked_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "contract.json").write_text("{}\n", encoding="utf-8")
            (root / "public").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(
                handoff.DeliveryHandoffError, "cannot read regular"
            ):
                handoff.read_public_file(
                    root,
                    "public/contract.json",
                    "test contract",
                )

if __name__ == "__main__":
    unittest.main()
