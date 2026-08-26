"""Test the public SUDO identity and access contracts."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import shutil
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
        for relative in (
            "init/ansible/playbooks/configure-identity-service.yml",
            "init/ansible/playbooks/configure-delivery-node.yml",
            "sudo/secrets/delivery-input-contract.json",
            "tar/manifests/delivery-supply.json",
            "make/contracts/service-node-handoff-requirements.json",
            "make/contracts/cluster-trust-requirements.json",
            "man/docs/adr/006-use-almalinux-9-for-freeipa-identity-host.md",
            "sudo/secrets/kubernetes-ecosystem-input-contract.json",
            "sudo/pki/shell-offline-root.crt.pem",
            "sudo/scripts/generate_k3s_server_tokens.py",
            "sudo/secrets/k3s-server-token-contract.json",
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE_ROOT / relative, target)

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

    def test_kubernetes_input_contract_validates_separate_private_handoffs(self) -> None:
        validator.validate_kubernetes_input_contract(self.root)
        path = self.root / "sudo/secrets/kubernetes-ecosystem-input-contract.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["clusters"]["gcp"]["handoff"] = ".local/sudo/wrong.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "cluster trust handoffs"
        ):
            validator.validate_kubernetes_input_contract(self.root)

    def test_delivery_inputs_use_sops_age_without_plaintext_values(self) -> None:
        validator.validate_delivery_input_contract(self.root)
        path = self.root / "sudo/secrets/delivery-input-contract.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("sops-age", document["private_custody"]["storage"])
        self.assertFalse(document["private_custody"]["plaintext_values_tracked"])
        self.assertEqual(
            ".local/sudo/delivery/bootstrap.sops.json",
            document["private_inputs"]["bootstrap"]["path"],
        )
        self.assertEqual(
            ".local/sudo/delivery/forgejo-public-tls.sops.json",
            document["private_inputs"]["forgejo_public_tls"]["path"],
        )
        self.assertEqual(
            ".local/sudo/delivery/forgejo-runner.sops.json",
            document["private_inputs"]["forgejo_runner"]["path"],
        )
        self.assertEqual(
            "0600",
            document["private_inputs"]["forgejo_runner"]["file_mode"],
        )
        self.assertEqual(
            "sops-age",
            document["classes"]["forgejo_runner"]["storage"],
        )
        self.assertEqual(
            ".local/sudo/delivery/forgejo-repository.sops.json",
            document["private_inputs"]["forgejo_repository"]["path"],
        )
        self.assertEqual(
            "0600",
            document["private_inputs"]["forgejo_repository"]["file_mode"],
        )
        self.assertTrue(document["classes"]["forgejo_repository"]["one_time_bootstrap"])
        self.assertEqual(
            "explicit-approved",
            document["classes"]["forgejo_repository"]["rotation"],
        )
        self.assertEqual(
            "plaintext-age-identity",
            document["private_inputs"]["age_key"]["storage"],
        )
        self.assertEqual(
            "SOPS_AGE_KEY_FILE",
            document["private_inputs"]["age_key"]["consumer"],
        )
        self.assertEqual(
            "service-generated-private-state",
            document["private_inputs"]["runtime"]["storage"],
        )
        serialized = json.dumps(document)
        self.assertNotRegex(
            serialized,
            r'"(?:admin_password|private_key|token)"\s*:',
        )
        self.assertNotIn("-----BEGIN", serialized)

        document["private_custody"]["storage"] = validator.UNDECIDED
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "private custody"
        ):
            validator.validate_delivery_input_contract(self.root)

        document = json.loads(
            (
                SOURCE_ROOT / "sudo/secrets/delivery-input-contract.json"
            ).read_text(encoding="utf-8")
        )
        document["classes"]["forgejo_repository"]["rotation"] = "automatic"
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "input classes changed"
        ):
            validator.validate_delivery_input_contract(self.root)

    def test_aggregate_gate_validates_the_k3s_server_token_contract(self) -> None:
        validator.validate_k3s_server_token_contract(self.root)
        contract = self.root / "sudo/secrets/k3s-server-token-contract.json"
        document = json.loads(contract.read_text(encoding="utf-8"))
        document["storage"]["file_mode"] = "0644"
        contract.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "server-token contract is invalid"
        ):
            validator.validate_k3s_server_token_contract(self.root)

    def test_rejects_unknown_fields_and_invalid_json(self) -> None:
        identity = self.altered("identity")
        identity["credential"] = "do-not-allow-new-fields"
        self.write("identity", identity)
        with self.assertRaisesRegex(validator.AccessContractError, "shape changed"):
            validator.validate_contracts(self.root)

        (self.access_root / validator.CONTRACT_FILES["identity"]).write_bytes(b"\xff")
        with self.assertRaisesRegex(validator.AccessContractError, "invalid JSON"):
            validator.validate_contracts(self.root)

    def test_rejects_duplicate_json_keys(self) -> None:
        delivery_path = self.access_root / validator.CONTRACT_FILES["delivery"]
        delivery_path.write_text(
            '{"schema_version":"0","schema_version":"1.0"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            validator.AccessContractError, "duplicate JSON key"
        ):
            validator.validate_contracts(self.root)

        self.write("delivery", self.documents["delivery"])
        delivery_input = self.root / "sudo/secrets/delivery-input-contract.json"
        delivery_input.write_text(
            '{"schema_version":"1.0","schema_version":"1.0"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            validator.AccessContractError, "duplicate JSON key"
        ):
            validator.validate_contracts(self.root)

        nested_duplicate = json.dumps(self.documents["delivery"]).replace(
            '"owner": "init", "playbook"',
            '"owner": "sudo", "owner": "init", "playbook"',
            1,
        )
        delivery_path.write_text(nested_duplicate, encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "duplicate JSON key"
        ):
            validator.validate_contracts(self.root)

    def test_rejects_contract_version_drift(self) -> None:
        freeipa = self.altered("freeipa")
        freeipa["contract_version"] = "1.0.0"
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(validator.AccessContractError, "version changed"):
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

    def test_rejects_changed_identity_and_delivery_service_policy(self) -> None:
        freeipa = self.altered("freeipa")
        freeipa["identity"]["realm"] = "OTHER.INTERNAL"  # type: ignore[index]
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(validator.AccessContractError, "FreeIPA realm"):
            validator.validate_contracts(self.root)

        self.write("freeipa", self.documents["freeipa"])
        delivery = self.altered("delivery")
        delivery["service"]["fqdn"] = "other.shell.internal"  # type: ignore[index]
        self.write("delivery", delivery)
        with self.assertRaisesRegex(validator.AccessContractError, "service contract"):
            validator.validate_contracts(self.root)

        self.write("delivery", self.documents["delivery"])
        input_path = self.root / "sudo/secrets/delivery-input-contract.json"
        input_contract = json.loads(input_path.read_text(encoding="utf-8"))
        input_contract["repository_policy"]["private_values_tracked"] = True
        input_path.write_text(json.dumps(input_contract), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "repository policy"
        ):
            validator.validate_contracts(self.root)

        input_contract["repository_policy"]["private_values_tracked"] = False
        input_contract["classes"]["forgejo_public_tls"]["issuer"] = "make"
        input_path.write_text(json.dumps(input_contract), encoding="utf-8")
        with self.assertRaisesRegex(
            validator.AccessContractError, "input classes"
        ):
            validator.validate_contracts(self.root)

    def test_rejects_dns_and_credential_status_drift(self) -> None:
        freeipa = self.altered("freeipa")
        freeipa["managed_dns_records"][0]["name"] = "delivery"  # type: ignore[index]
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(
            validator.AccessContractError, "DNS name does not match FQDN"
        ):
            validator.validate_contracts(self.root)

        freeipa = self.altered("freeipa")
        freeipa["required_contracts"]["identity_credentials"][  # type: ignore[index]
            "handoff_status"
        ] = "ready"
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(
            validator.AccessContractError, "required contracts"
        ):
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
        with self.assertRaisesRegex(
            validator.AccessContractError, "required contracts"
        ):
            validator.validate_contracts(self.root)

    def test_rejects_changed_execution_playbooks(self) -> None:
        freeipa = self.altered("freeipa")
        freeipa["execution"]["playbook"] = str(  # type: ignore[index]
            self.root.parent / "identity.yml"
        )
        self.write("freeipa", freeipa)
        with self.assertRaisesRegex(validator.AccessContractError, "reference changed"):
            validator.validate_contracts(self.root)

        self.write("freeipa", self.documents["freeipa"])
        delivery = self.altered("delivery")
        delivery["execution"]["status"] = "ready"  # type: ignore[index]
        self.write("delivery", delivery)
        with self.assertRaisesRegex(
            validator.AccessContractError, "execution boundary"
        ):
            validator.validate_contracts(self.root)

    def test_rejects_missing_or_unsafe_execution_playbooks(self) -> None:
        delivery_path = (
            self.root
            / (
                self.documents["delivery"]["execution"]["playbook"]  # type: ignore[index]
            )
        )
        delivery_path.unlink()
        with self.assertRaisesRegex(validator.AccessContractError, "missing regular"):
            validator.validate_contracts(self.root)

        outside_playbook = Path(self.temporary.name) / "delivery.yml"
        outside_playbook.write_text("---\n", encoding="utf-8")
        delivery_path.symlink_to(outside_playbook)
        with self.assertRaisesRegex(validator.AccessContractError, "missing regular"):
            validator.validate_contracts(self.root)

        delivery_path.unlink()
        shutil.rmtree(self.root / "init")
        outside_init = Path(self.temporary.name) / "outside-init"
        outside_target = outside_init / "ansible/playbooks/configure-delivery-node.yml"
        outside_target.parent.mkdir(parents=True)
        outside_target.write_text("---\n", encoding="utf-8")
        (outside_target.parent / "configure-identity-service.yml").write_text(
            "---\n",
            encoding="utf-8",
        )
        (self.root / "init").symlink_to(outside_init, target_is_directory=True)
        with self.assertRaisesRegex(
            validator.AccessContractError, "outside repository"
        ):
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

    def test_rejects_missing_or_symlinked_cross_owner_references(self) -> None:
        references = (
            "sudo/secrets/delivery-input-contract.json",
            "tar/manifests/delivery-supply.json",
            "make/contracts/service-node-handoff-requirements.json",
            "make/contracts/cluster-trust-requirements.json",
            "man/docs/adr/006-use-almalinux-9-for-freeipa-identity-host.md",
        )
        for relative in references:
            with self.subTest(reference=relative):
                target = self.root / relative
                source = SOURCE_ROOT / relative
                target.unlink()
                with self.assertRaisesRegex(
                    validator.AccessContractError, "missing regular"
                ):
                    validator.validate_contracts(self.root)

                outside = Path(self.temporary.name) / f"outside-{target.name}"
                shutil.copyfile(source, outside)
                target.symlink_to(outside)
                with self.assertRaisesRegex(
                    validator.AccessContractError, "missing regular"
                ):
                    validator.validate_contracts(self.root)
                target.unlink()
                shutil.copyfile(source, target)

    def test_rejects_cross_owner_reference_through_symlinked_ancestor(self) -> None:
        contracts = self.root / "make/contracts"
        real_contracts = self.root / "make/contracts-real"
        contracts.rename(real_contracts)
        outside = Path(self.temporary.name) / "outside-contracts"
        shutil.copytree(real_contracts, outside)
        contracts.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(
            validator.AccessContractError, "outside repository"
        ):
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

    def test_main_reports_all_validated_contracts(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(validator, "REPOSITORY_ROOT", self.root):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = validator.main()
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            stdout.getvalue(),
            "validated 4 SUDO access profiles and 3 handoff contracts\n",
        )


if __name__ == "__main__":
    unittest.main()
