"""Test INIT's exact K3s target and token boundary."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK_ROOT = SOURCE_ROOT / "init/ansible/playbooks"
CONFIGURE = PLAYBOOK_ROOT / "configure-k3s-runtime.yml"
VERIFY = PLAYBOOK_ROOT / "verify-k3s-runtime.yml"
TARGET_TASKS = PLAYBOOK_ROOT / "tasks/require-k3s-target.yml"
TOKEN_CONTRACT = SOURCE_ROOT / "sudo/secrets/k3s-server-token-contract.json"


class TestK3sRuntimeContract(unittest.TestCase):
    def test_every_k3s_play_requires_an_explicit_target(self) -> None:
        configure = CONFIGURE.read_text(encoding="utf-8")
        verify = VERIFY.read_text(encoding="utf-8")

        for source in (configure, verify):
            self.assertNotIn("default('gcp_k3s_servers')", source)
            self.assertNotIn("shell_k3s_token_path", source)
            self.assertEqual(
                source.count('hosts: "{{ shell_k3s_target_group }}"'),
                2,
            )
            self.assertEqual(
                source.count("import_tasks: tasks/require-k3s-target.yml"),
                2,
            )
            self.assertEqual(source.count("tags: [always]"), 2)

    def test_target_gate_binds_exact_clusters_nodes_and_metadata(self) -> None:
        source = TARGET_TASKS.read_text(encoding="utf-8")
        for required in (
            "shell_k3s_cluster_name in ['gcp', 'proxmox']",
            "shell_k3s_target_group == 'gcp_k3s_servers'",
            "shell_k3s_target_group == 'proxmox_k3s_servers'",
            "['gcp-k3s-01', 'gcp-k3s-02', 'gcp-k3s-03']",
            "['proxmox-k3s-01', 'proxmox-k3s-02', 'proxmox-k3s-03']",
            "ansible_play_hosts_all == groups[shell_k3s_target_group]",
            "hostvars[item].shell_role | default('') == 'k3s'",
            "hostvars[item].shell_cluster | default('') == shell_k3s_cluster_name",
            "hostvars[item].shell_operating_system | default('') == 'debian-13'",
            "hostvars[item].ansible_host == hostvars[item].shell_expected_address",
            "shell_k3s_api_endpoint == shell_inventory_k3s_api_endpoint",
            "shell_k3s_api_host == shell_inventory_k3s_api_host",
            "shell_k3s_api_host == shell_inventory_k3s_api_address",
            "hostvars[item].ansible_connection | default('ssh') == 'ssh'",
            "hostvars[item].ansible_user is defined",
            "hostvars[item].ansible_user != 'root'",
            "hostvars[item].ansible_ssh_common_args is defined",
            "search('StrictHostKeyChecking=yes')",
            "hostvars[item].shell_transport | default('') == 'gcp_iap'",
            "hostvars[item].shell_transport | default('') == 'proxmox_ssh'",
            'loop: "{{ groups[shell_k3s_target_group] }}"',
        ):
            self.assertIn(required, source)

        self.assertEqual(source.count("run_once: true"), 2)

        self.assertNotIn("groups[shell_k3s_target_group] | sort", source)
        for address in (
            "10.77.0.201",
            "10.77.0.202",
            "10.77.0.203",
            "10.66.0.201",
            "10.66.0.202",
            "10.66.0.203",
        ):
            self.assertIn(address, source)

    def test_configuration_gates_before_connection_and_token_read(self) -> None:
        source = CONFIGURE.read_text(encoding="utf-8")
        gate = source.index("import_tasks: tasks/require-k3s-target.yml")
        connection = source.index("ansible.builtin.wait_for_connection")
        token = source.index("lookup('ansible.builtin.file'")
        tasks = source.index("\n  tasks:")
        self.assertLess(gate, connection)
        self.assertLess(connection, token)
        self.assertLess(token, tasks)
        check_mode_exit = source.index(
            "Stop before K3s connection or mutation in check mode"
        )
        self.assertGreater(check_mode_exit, source.index("Require the Proxmox K3s API"))
        self.assertGreater(check_mode_exit, source.index("Keep the direct-GCP cluster"))
        self.assertLess(check_mode_exit, connection)
        self.assertIn("is match('^[0-9a-f]{64}$')", source)
        self.assertLess(
            source.index("Require private SUDO K3s token custody"),
            token,
        )

    def test_token_path_is_derived_from_the_sudo_contract(self) -> None:
        contract = json.loads(TOKEN_CONTRACT.read_text(encoding="utf-8"))
        for cluster in ("gcp", "proxmox"):
            self.assertEqual(
                contract["clusters"][cluster]["token_path"],
                f".local/sudo/k3s/{cluster}/server-token",
            )

        source = CONFIGURE.read_text(encoding="utf-8")
        self.assertIn("'.local/sudo/k3s/gcp/server-token'", source)
        self.assertIn("'.local/sudo/k3s/proxmox/server-token'", source)

    def test_verification_compares_the_pinned_version_exactly(self) -> None:
        source = VERIFY.read_text(encoding="utf-8")
        supply = json.loads(
            (
                SOURCE_ROOT / "tar/manifests/init-k3s-runtime-supply.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(supply["k3s_binary"]["version"], "v1.34.10+k3s1")
        self.assertIn("select('equalto', shell_k3s_version)", source)
        self.assertNotIn("select('search', shell_k3s_version)", source)


if __name__ == "__main__":
    unittest.main()
