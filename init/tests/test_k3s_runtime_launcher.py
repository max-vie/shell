"""Test the fixed INIT K3s controller launcher."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "init/scripts/run_k3s_runtime.py"
SPEC = importlib.util.spec_from_file_location("run_k3s_runtime", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load K3s runtime launcher: {SCRIPT}")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class TestK3sRuntimeLauncher(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for directory in (
            ".local",
            ".local/ansible",
            ".local/ansible/k3s-runtime",
            ".local/ansible/.k3s-runtime",
            ".local/tar",
            ".local/tar/init-k3s-runtime",
            ".local/tar/init-k3s-network",
            ".local/tar/init-k3s-network/charts",
            "tar/manifests",
            "init/ansible/playbooks",
        ):
            self._mkdir_private(self.root / directory)
        self._network_patches = [
            mock.patch.object(
                launcher.network_supply,
                "EXPECTED_HELM_BINARY",
                {
                    **launcher.network_supply.EXPECTED_HELM_BINARY,
                    "sha256": hashlib.sha256(b"test-helm").hexdigest(),
                    "size": len(b"test-helm"),
                },
            ),
            mock.patch.object(
                launcher.network_supply,
                "EXPECTED_CILIUM_CHART",
                {
                    **launcher.network_supply.EXPECTED_CILIUM_CHART,
                    "sha256": hashlib.sha256(b"test-cilium-chart").hexdigest(),
                    "size": len(b"test-cilium-chart"),
                },
            ),
        ]
        for patcher in self._network_patches:
            patcher.start()
        self._write_inputs()

    def tearDown(self) -> None:
        for patcher in reversed(self._network_patches):
            patcher.stop()
        self.temporary.cleanup()

    @staticmethod
    def _mkdir_private(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)

    @staticmethod
    def _write_private(path: Path, value: str | bytes) -> None:
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        path.chmod(0o600)

    def _write_inventory(self, cluster: str) -> None:
        contract = launcher.CLUSTERS[cluster]
        api_host = "10.77.0.200" if cluster == "gcp" else "10.66.0.200"
        inventory = {
            "all": {
                "children": {
                    "shell_nodes": {
                        "children": {
                            contract["target_group"]: {
                                "hosts": {
                                    name: {
                                        "ansible_host": contract["addresses"][name],
                                        "shell_expected_address": contract["addresses"][
                                            name
                                        ],
                                        "shell_role": "k3s",
                                        "shell_cluster": cluster,
                                        "shell_transport": contract["transport"],
                                        "shell_operating_system": "debian-13",
                                        **(
                                            {
                                                "gcp_project_id": "test-project",
                                                "gcp_zone": {
                                                    "gcp-k3s-01": "europe-west4-a",
                                                    "gcp-k3s-02": "europe-west4-b",
                                                    "gcp-k3s-03": "europe-west4-c",
                                                }[name],
                                            }
                                            if cluster == "gcp"
                                            else {}
                                        ),
                                    }
                                    for name in contract["hosts"]
                                },
                                "vars": {
                                    "shell_inventory_k3s_api_address": api_host,
                                    "shell_inventory_k3s_api_endpoint": f"https://{api_host}:6443",
                                    "shell_inventory_k3s_api_host": api_host,
                                },
                            }
                        }
                    }
                }
            }
        }
        self._write_private(
            self.root / ".local/ansible/inventory.json", json.dumps(inventory)
        )

    def _inventory_output(self, cluster: str = "gcp") -> dict[str, Any]:
        source = json.loads(
            (self.root / ".local/ansible/inventory.json").read_text(encoding="utf-8")
        )
        contract = launcher.CLUSTERS[cluster]
        group = source["all"]["children"]["shell_nodes"]["children"][
            contract["target_group"]
        ]
        common_args = (
            '-o ProxyCommand="gcloud compute start-iap-tunnel '
            "{{ inventory_hostname | quote }} %p --listen-on-stdin "
            "--project={{ gcp_project_id | quote }} "
            '--zone={{ gcp_zone | quote }}" '
            "-o StrictHostKeyChecking=yes"
            if cluster == "gcp"
            else "-o ProxyJump=proxmox-host -o StrictHostKeyChecking=yes"
        )
        hostvars = {
            name: {
                **host,
                **group["vars"],
                "ansible_user": "test-user",
                "ansible_connection": "ssh",
                "ansible_ssh_common_args": common_args,
            }
            for name, host in group["hosts"].items()
        }
        return {
            "_meta": {"hostvars": hostvars},
            contract["target_group"]: {"hosts": contract["hosts"]},
        }

    def _write_inputs(self) -> None:
        binary = b"test-k3s-binary"
        digest = hashlib.sha256(binary).hexdigest()
        binary_path = self.root / ".local/tar/init-k3s-runtime/k3s"
        self._write_private(binary_path, binary)
        helm = b"test-helm"
        helm_path = self.root / ".local/tar/init-k3s-network/helm"
        self._write_private(helm_path, helm)
        chart = b"test-cilium-chart"
        chart_path = self.root / ".local/tar/init-k3s-network/charts/cilium-1.18.2.tgz"
        self._write_private(chart_path, chart)
        lock = {
            "schema_version": "1.0",
            "contract_version": "1.0.0",
            "contract_id": "init-k3s-runtime-supply",
            "policy_owner": "tar",
            "execution_owner": "init",
            "proof_status": "source-reference-only",
            "k3s_binary": {
                "version": "v1.34.10+k3s1",
                "file_name": "k3s",
                "source": "https://github.com/k3s-io/k3s/releases/download/v1.34.10%2Bk3s1/k3s",
                "sha256": digest,
                "size": len(binary),
            },
            "kube_vip_image": {
                "repository": "ghcr.io/kube-vip/kube-vip",
                "tag": "v1.0.4",
                "platform": "linux/amd64",
                "digest": "sha256:" + "1" * 64,
            },
        }
        self._write_private(
            self.root / ".local/ansible/k3s-runtime-supply.json",
            json.dumps(
                {
                    "shell_k3s_version": "v1.34.10+k3s1",
                    "shell_k3s_binary_path": str(binary_path),
                    "shell_k3s_binary_sha256": digest,
                    "shell_k3s_api_vip_image_repository": "ghcr.io/kube-vip/kube-vip",
                    "shell_k3s_api_vip_image_digest": "sha256:" + "1" * 64,
                }
            ),
        )
        network_lock = {
            "schema_version": "1.0",
            "contract_version": "1.0.0",
            "contract_id": "init-k3s-network-supply",
            "policy_owner": "tar",
            "execution_owner": "init",
            "proof_status": "source-reference-only",
            "staging": {
                "mode": "local-verified-artifacts",
                "network_acquisition_owner": "tar",
                "consumer_network_acquisition": False,
                "artifact_directory": "init-k3s-network",
                "chart_cache_layout": "charts/{name}-{version}.tgz",
            },
            "helm_binary": dict(launcher.network_supply.EXPECTED_HELM_BINARY),
            "cilium_chart": dict(launcher.network_supply.EXPECTED_CILIUM_CHART),
            "cilium_images": launcher.network_supply.EXPECTED_CILIUM_IMAGES,
            "cilium_configuration": launcher.network_supply.EXPECTED_CILIUM_CONFIGURATION,
        }
        self._write_private(
            self.root / ".local/ansible/k3s-network-supply.json",
            json.dumps(
                {
                    "shell_k3s_helm_version": network_lock["helm_binary"]["version"],
                    "shell_k3s_helm_path": str(helm_path),
                    "shell_k3s_helm_sha256": network_lock["helm_binary"]["sha256"],
                    "shell_k3s_cilium_chart_path": str(chart_path),
                    "shell_k3s_cilium_chart_sha256": network_lock["cilium_chart"][
                        "sha256"
                    ],
                    "shell_k3s_cilium_chart_version": network_lock["cilium_chart"][
                        "version"
                    ],
                    "shell_k3s_cilium_images": network_lock["cilium_images"],
                    "shell_k3s_cilium_configuration": network_lock[
                        "cilium_configuration"
                    ],
                }
            ),
        )
        self._write_private(
            self.root / ".local/ansible/k3s-runtime/gcp.json",
            json.dumps(
                {
                    "shell_k3s_pod_cidr": "10.42.0.0/16",
                    "shell_k3s_service_cidr": "10.43.0.0/16",
                }
            ),
        )
        self._write_inventory("gcp")
        self._write_private(
            self.root / ".local/ansible/connection-inventory.yml",
            "all:\n"
            "  vars:\n"
            "    ansible_user: test-user\n"
            "    ansible_connection: ssh\n"
            "    ansible_ssh_common_args: >-\n"
            '      -o ProxyCommand="gcloud compute start-iap-tunnel\n'
            "      {{ inventory_hostname | quote }} %p --listen-on-stdin\n"
            "      --project={{ gcp_project_id | quote }}\n"
            '      --zone={{ gcp_zone | quote }}"\n'
            "      -o StrictHostKeyChecking=yes\n",
        )
        (self.root / "tar/manifests/init-k3s-runtime-supply.json").write_text(
            json.dumps(lock), encoding="utf-8"
        )
        (self.root / "tar/manifests/init-k3s-network-supply.json").write_text(
            json.dumps(network_lock), encoding="utf-8"
        )
        (self.root / "init/ansible/playbooks/configure-k3s-runtime.yml").write_text(
            "---\n", encoding="utf-8"
        )
        (self.root / "init/ansible/playbooks/verify-k3s-runtime.yml").write_text(
            "---\n", encoding="utf-8"
        )

    def test_configure_check_builds_fixed_command_and_cleans_private_vars(self) -> None:
        commands: list[list[str]] = []
        inventory_commands: list[list[str]] = []
        captured: dict[str, object] = {}

        def run(command: list[str], **_: object) -> SimpleNamespace:
            if command[0] == "ansible-inventory":
                inventory_commands.append(command)
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(self._inventory_output()),
                )
            commands.append(command)
            variables_path = Path(command[command.index("--extra-vars") + 1][1:])
            captured.update(json.loads(variables_path.read_text(encoding="utf-8")))
            self.assertEqual(stat.S_IMODE(variables_path.stat().st_mode), 0o600)
            return SimpleNamespace(returncode=0)

        result = launcher.execute(
            "configure",
            "gcp",
            repository_root=self.root,
            run_process=run,
            check=True,
        )

        self.assertEqual(result, 0)
        self.assertEqual(inventory_commands[0][-1], "--list")
        self.assertEqual(inventory_commands[0].count("--inventory"), 2)
        self.assertEqual(len(commands), 1)
        command = commands[0]
        self.assertEqual(command[0], "ansible-playbook")
        self.assertIn("--check", command)
        self.assertEqual(command.count("--inventory"), 2)
        self.assertNotIn("--limit", command)
        self.assertNotIn("--start-at-task", command)
        self.assertEqual(captured["shell_k3s_cluster_name"], "gcp")
        self.assertEqual(captured["shell_k3s_target_group"], "gcp_k3s_servers")
        self.assertEqual(captured["shell_k3s_cilium_chart_version"], "1.18.2")
        configuration = cast(dict[str, Any], captured["shell_k3s_cilium_configuration"])
        self.assertTrue(configuration["cni_exclusive"])
        self.assertNotIn("shell_k3s_token_path", captured)
        self.assertEqual(
            list((self.root / ".local/ansible/.k3s-runtime").iterdir()), []
        )

    def test_verify_does_not_add_check_mode_or_allow_target_override(self) -> None:
        commands: list[list[str]] = []

        def run(command: list[str], **_: object) -> SimpleNamespace:
            commands.append(command)
            if command[0] == "ansible-inventory":
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(self._inventory_output()),
                )
            return SimpleNamespace(returncode=0)

        result = launcher.execute(
            "verify", "gcp", repository_root=self.root, run_process=run
        )

        self.assertEqual(result, 0)
        command = commands[-1]
        self.assertNotIn("--check", command)
        self.assertNotIn("--limit", command)
        self.assertEqual(
            command[-1],
            str(self.root / "init/ansible/playbooks/verify-k3s-runtime.yml"),
        )

    def test_rejects_unsafe_effective_connection_inventory(self) -> None:
        inventory_path = self.root / ".local/ansible/inventory.json"
        connection_path = self.root / ".local/ansible/connection-inventory.yml"
        target = "gcp-k3s-01"
        cases = (
            ("ansible_connection", "local", "SSH connection plugin"),
            ("ansible_user", "root", "non-root SSH user"),
            ("ansible_ssh_common_args", "-o ProxyCommand=unsafe", "strict SSH"),
            ("gcp_project_id", "other-project", "generated variable"),
            ("unsupported_connection_setting", "unsafe", "unsupported variables"),
        )
        for key, value, message in cases:
            with self.subTest(key=key):
                document = self._inventory_output()
                document["_meta"]["hostvars"][target][key] = value

                def run(command: list[str], **_: object) -> SimpleNamespace:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(document),
                    )

                with self.assertRaisesRegex(launcher.RuntimeLauncherError, message):
                    launcher.validate_connection_inventory(
                        inventory_path,
                        connection_path,
                        "gcp",
                        self.root,
                        run,
                    )

    def test_rejects_an_unreserved_gcp_api_endpoint(self) -> None:
        path = self.root / ".local/ansible/inventory.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        variables = inventory["all"]["children"]["shell_nodes"]["children"][
            "gcp_k3s_servers"
        ]["vars"]
        variables["shell_inventory_k3s_api_address"] = "203.0.113.10"
        variables["shell_inventory_k3s_api_endpoint"] = "https://203.0.113.10:6443"
        variables["shell_inventory_k3s_api_host"] = "203.0.113.10"
        self._write_private(path, json.dumps(inventory))

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "unreserved"):
            launcher.load_inventory(path, "gcp", self.root)

    def test_rejects_gcp_service_frontend_addresses_as_api_endpoints(self) -> None:
        for address in ("10.77.0.221", "10.77.0.222"):
            with self.subTest(address=address):
                self._write_inventory("gcp")
                path = self.root / ".local/ansible/inventory.json"
                inventory = json.loads(path.read_text(encoding="utf-8"))
                variables = inventory["all"]["children"]["shell_nodes"]["children"][
                    "gcp_k3s_servers"
                ]["vars"]
                variables["shell_inventory_k3s_api_address"] = address
                variables["shell_inventory_k3s_api_endpoint"] = (
                    f"https://{address}:6443"
                )
                variables["shell_inventory_k3s_api_host"] = address
                self._write_private(path, json.dumps(inventory))
                with self.assertRaisesRegex(
                    launcher.RuntimeLauncherError, "unreserved"
                ):
                    launcher.load_inventory(path, "gcp", self.root)

    def test_accepts_the_proxmox_inventory_contract(self) -> None:
        self._write_inventory("proxmox")

        endpoint, api_host = launcher.load_inventory(
            self.root / ".local/ansible/inventory.json", "proxmox", self.root
        )

        self.assertEqual(endpoint, "https://10.66.0.200:6443")
        self.assertEqual(api_host, "10.66.0.200")

    def test_rejects_a_changed_supply_checksum(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime-supply.json"
        handoff = json.loads(path.read_text(encoding="utf-8"))
        handoff["shell_k3s_binary_sha256"] = "0" * 64
        self._write_private(path, json.dumps(handoff))

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "checksum changed"):
            launcher.load_supply(
                path,
                self.root / "tar/manifests/init-k3s-runtime-supply.json",
                self.root,
            )

    def test_rejects_a_changed_supply_version(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime-supply.json"
        handoff = json.loads(path.read_text(encoding="utf-8"))
        handoff["shell_k3s_version"] = "v1.34.11+k3s1"
        self._write_private(path, json.dumps(handoff))

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "version changed"):
            launcher.load_supply(
                path,
                self.root / "tar/manifests/init-k3s-runtime-supply.json",
                self.root,
            )

    def test_rejects_a_changed_cilium_handoff_checksum(self) -> None:
        path = self.root / ".local/ansible/k3s-network-supply.json"
        handoff = json.loads(path.read_text(encoding="utf-8"))
        handoff["shell_k3s_cilium_chart_sha256"] = "0" * 64
        self._write_private(path, json.dumps(handoff))

        with self.assertRaisesRegex(
            launcher.RuntimeLauncherError, "Cilium chart checksum"
        ):
            launcher.load_network_supply(
                path,
                self.root / "tar/manifests/init-k3s-network-supply.json",
                self.root,
            )

    def test_rejects_an_invalid_supply_source_url(self) -> None:
        path = self.root / "tar/manifests/init-k3s-runtime-supply.json"
        lock = json.loads(path.read_text(encoding="utf-8"))
        lock["k3s_binary"]["source"] = "https://example.com/k3s"
        path.write_text(json.dumps(lock), encoding="utf-8")

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "official HTTPS"):
            launcher.load_supply(
                self.root / ".local/ansible/k3s-runtime-supply.json",
                path,
                self.root,
            )

    def test_rejects_a_boolean_supply_size(self) -> None:
        path = self.root / "tar/manifests/init-k3s-runtime-supply.json"
        lock = json.loads(path.read_text(encoding="utf-8"))
        lock["k3s_binary"]["size"] = True
        path.write_text(json.dumps(lock), encoding="utf-8")

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "size is invalid"):
            launcher.load_supply(
                self.root / ".local/ansible/k3s-runtime-supply.json",
                path,
                self.root,
            )

    def test_rejects_overlapping_runtime_cidrs(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime/gcp.json"
        runtime = json.loads(path.read_text(encoding="utf-8"))
        runtime["shell_k3s_service_cidr"] = "10.42.1.0/24"
        self._write_private(path, json.dumps(runtime))

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "must not overlap"):
            launcher.load_runtime_vars(path, "gcp", self.root)

    def test_rejects_runtime_cidrs_overlapping_declared_host_networks(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime/gcp.json"
        runtime = json.loads(path.read_text(encoding="utf-8"))
        runtime["shell_k3s_pod_cidr"] = "10.77.0.0/24"
        self._write_private(path, json.dumps(runtime))

        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "host network"):
            launcher.load_runtime_vars(path, "gcp", self.root)

    def test_rejects_permissive_runtime_input(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime/gcp.json"
        path.chmod(0o640)
        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "mode 0600"):
            launcher.load_runtime_vars(path, "gcp", self.root)

    def test_proxmox_runtime_variables_enable_only_the_fixed_vip(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime/proxmox.json"
        self._write_private(
            path,
            json.dumps(
                {
                    "shell_k3s_pod_cidr": "10.52.0.0/16",
                    "shell_k3s_service_cidr": "10.53.0.0/16",
                    "shell_k3s_api_vip_interface": "vmbr-shell",
                }
            ),
        )
        runtime = launcher.load_runtime_vars(path, "proxmox", self.root)
        values = launcher.build_extra_vars(
            "proxmox",
            "https://10.66.0.200:6443",
            "10.66.0.200",
            {
                "shell_k3s_version": "v1.34.10+k3s1",
                "shell_k3s_binary_path": "/unused/k3s",
                "shell_k3s_binary_sha256": "a" * 64,
                "shell_k3s_api_vip_image_repository": "ghcr.io/kube-vip/kube-vip",
                "shell_k3s_api_vip_image_digest": "sha256:" + "1" * 64,
            },
            {
                "shell_k3s_helm_version": "v3.18.4",
                "shell_k3s_helm_path": "/unused/helm",
                "shell_k3s_helm_sha256": "b" * 64,
                "shell_k3s_cilium_chart_path": "/unused/cilium.tgz",
                "shell_k3s_cilium_chart_sha256": "c" * 64,
                "shell_k3s_cilium_chart_version": "1.18.2",
                "shell_k3s_cilium_images": {},
                "shell_k3s_cilium_configuration": {},
            },
            runtime,
        )
        self.assertTrue(values["shell_k3s_api_vip_enabled"])
        self.assertEqual(values["shell_k3s_api_vip_address"], "10.66.0.200")
        self.assertEqual(values["shell_k3s_api_vip_interface"], "vmbr-shell")

    def test_rejects_duplicate_json_keys(self) -> None:
        path = self.root / ".local/ansible/k3s-runtime/gcp.json"
        self._write_private(
            path,
            '{"shell_k3s_pod_cidr":"10.42.0.0/16",'
            '"shell_k3s_pod_cidr":"10.44.0.0/16",'
            '"shell_k3s_service_cidr":"10.43.0.0/16"}',
        )
        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "duplicate"):
            launcher.load_runtime_vars(path, "gcp", self.root)

    def test_rejects_changed_inventory_host(self) -> None:
        path = self.root / ".local/ansible/inventory.json"
        inventory = json.loads(path.read_text(encoding="utf-8"))
        inventory["all"]["children"]["shell_nodes"]["children"]["gcp_k3s_servers"][
            "hosts"
        ]["gcp-k3s-03"]["ansible_host"] = "10.77.0.204"
        self._write_private(path, json.dumps(inventory))
        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "address changed"):
            launcher.load_inventory(path, "gcp", self.root)

    def test_rejects_unknown_cluster(self) -> None:
        with self.assertRaisesRegex(launcher.RuntimeLauncherError, "gcp, proxmox"):
            launcher._cluster_contract("other")

    def test_temporary_variables_are_removed_after_process_failure(self) -> None:
        def fail(*_: object, **__: object) -> None:
            raise OSError("test process failure")

        with self.assertRaises(OSError):
            launcher.execute(
                "configure",
                "gcp",
                repository_root=self.root,
                run_process=fail,
            )
        self.assertEqual(
            list((self.root / ".local/ansible/.k3s-runtime").iterdir()), []
        )


if __name__ == "__main__":
    unittest.main()
