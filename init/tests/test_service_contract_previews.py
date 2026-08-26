"""Test INIT's fail-closed identity and delivery contract previews."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


PLAYBOOK_DIRECTORY = Path(__file__).parents[1] / "ansible" / "playbooks"
PREVIEWS = {
    "delivery": PLAYBOOK_DIRECTORY / "configure-delivery-node.yml",
    "identity": PLAYBOOK_DIRECTORY / "configure-identity-service.yml",
}


class TestServiceContractPreviews(unittest.TestCase):
    # Source checks keep this test standard-library-only and avoid executing
    # either preview while its required contracts remain undefined.
    def test_preview_playbooks_gate_target_tasks(self) -> None:
        for boundary, playbook in PREVIEWS.items():
            with self.subTest(boundary=boundary):
                source = playbook.read_text(encoding="utf-8")
                pre_tasks = source.index("\n  pre_tasks:")
                refusal = source.index(f"\n    - name: Refuse {boundary} mutation")
                tasks = source.index("\n  tasks:")
                self.assertNotIn("\n  hosts: localhost", source)
                self.assertLess(pre_tasks, refusal)
                self.assertLess(refusal, tasks)
                gate = source[pre_tasks:tasks]
                self.assertIn("when: not ansible_check_mode", source[refusal:tasks])
                self.assertIn("ansible.builtin.fail:", source[refusal:tasks])
                expected_controller_tasks = 3 if boundary == "identity" else 8
                expected_always_tags = 5 if boundary == "identity" else 10
                self.assertEqual(
                    gate.count("delegate_to: localhost"), expected_controller_tasks
                )
                self.assertEqual(gate.count("run_once: true"), expected_controller_tasks)
                self.assertEqual(gate.count("become: false"), expected_controller_tasks)
                self.assertEqual(gate.count("tags: [always]"), expected_always_tags)
                required_checks = [
                    "shell_role | default('')",
                    "shell_cluster | default('')",
                    "shell_transport | default('')",
                    "(ansible_user | default('')) != 'root'",
                ]
                if boundary == "identity":
                    required_checks.extend(
                        [
                            "shell_identity_inventory_group",
                            "shell_identity_role",
                            "shell_identity_cluster",
                            "shell_identity_transport",
                            "shell_identity_profile.host.operating_system == 'almalinux-9'",
                            "shell_identity_profile.identity.domain == 'shell.internal'",
                            "identity_credentials.handoff_status",
                            "sudo/access/freeipa-host-profile.json",
                            "validate_access_contracts.py",
                        ]
                    )
                else:
                    required_checks.extend(
                        [
                            "shell_delivery_inventory_group",
                            "shell_delivery_role",
                            "shell_delivery_cluster",
                            "shell_delivery_transport",
                            "sudo/access/delivery-host-profile.json",
                            "sudo/secrets/delivery-input-contract.json",
                            "tar/manifests/delivery-supply.json",
                            "make/contracts/service-node-handoff-requirements.json",
                            "repository_policy.private_values_tracked",
                            "shell_delivery_supply.proof_status == 'source-reference-only'",
                            "validate_access_contracts.py",
                            "validate_delivery_supply.py",
                            "validate_service_node_handoff.py",
                        ]
                    )
                for required in required_checks:
                    self.assertIn(required, gate)
                expected_pre_task_modules = [
                    "ansible.builtin.command",
                    "ansible.builtin.include_vars",
                ]
                if boundary == "delivery":
                    expected_pre_task_modules.extend(
                        [
                            "ansible.builtin.include_vars",
                            "ansible.builtin.include_vars",
                            "ansible.builtin.include_vars",
                            "ansible.builtin.command",
                            "ansible.builtin.command",
                        ]
                    )
                expected_pre_task_modules.extend(
                    ["ansible.builtin.assert", "ansible.builtin.assert"]
                )
                self.assertEqual(
                    re.findall(
                        r"^      (ansible[.]builtin[.][a-z_]+):",
                        source[pre_tasks:refusal],
                        flags=re.MULTILINE,
                    ),
                    expected_pre_task_modules,
                )
                self.assertEqual(
                    re.findall(
                        r"^      (ansible[.]builtin[.][a-z_]+):",
                        source[tasks:],
                        flags=re.MULTILINE,
                    ),
                    ["ansible.builtin.debug", "ansible.builtin.meta"],
                )

    def test_contract_and_validator_paths_are_not_extra_var_overridable(self) -> None:
        vars_source = (
            PLAYBOOK_DIRECTORY.parent / "vars" / "contracts.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("shell_access_validator", vars_source)
        self.assertNotIn("shell_delivery_supply_validator", vars_source)
        self.assertNotIn("shell_service_handoff_validator", vars_source)
        path_variables = (
            "shell_repo_root",
            "shell_identity_profile_path",
            "shell_delivery_profile_path",
            "shell_delivery_input_contract_path",
            "shell_delivery_supply_path",
            "shell_service_handoff_path",
        )
        for variable in path_variables:
            self.assertNotIn(variable, vars_source)
        for playbook in PREVIEWS.values():
            source = playbook.read_text(encoding="utf-8")
            self.assertNotIn("shell_access_validator", source)
            self.assertNotIn("shell_delivery_supply_validator", source)
            self.assertNotIn("shell_service_handoff_validator", source)
            for variable in path_variables:
                self.assertNotIn(variable, source)


if __name__ == "__main__":
    unittest.main()
