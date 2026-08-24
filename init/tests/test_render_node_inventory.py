"""Test the SHELL OpenTofu-to-Ansible inventory handoff."""

from __future__ import annotations

import copy
import importlib.util
import io
import ipaddress
import json
import shutil
import stat

# The integration test invokes one fixed local executable without a shell.
import subprocess  # nosec B404
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast


# The script is intentionally a standalone INIT utility, so load it by path
# instead of making `init/scripts` a Python package.
SCRIPT = Path(__file__).parents[1] / "scripts" / "render_node_inventory.py"
SPEC = importlib.util.spec_from_file_location("render_node_inventory", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load renderer: {SCRIPT}")
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)
ANSIBLE_INVENTORY = shutil.which("ansible-inventory")


class TestRenderNodeInventory(unittest.TestCase):
    # These fixtures model the current output shapes and node names without
    # reading local state. Proxmox placement values remain synthetic.
    def shared_nodes(self) -> dict[str, Any]:
        return {
            "identity-01": {
                "name": "identity-01",
                "zone": "europe-west4-a",
                "internal_ip": "10.77.0.210",
                "project_id": "shell-platform",
            },
            "delivery-01": {
                "name": "delivery-01",
                "zone": "europe-west4-b",
                "internal_ip": "10.77.0.211",
                "project_id": "shell-platform",
            },
        }

    def gcp_k3s_nodes(self) -> dict[str, Any]:
        return {
            f"gcp-k3s-0{index}": {
                "name": f"gcp-k3s-0{index}",
                "zone": zone,
                "internal_ip": f"10.77.0.20{index}",
                "project_id": "shell-platform",
            }
            for index, zone in enumerate(
                ("europe-west4-a", "europe-west4-b", "europe-west4-c"),
                start=1,
            )
        }

    def proxmox_k3s_nodes(self) -> dict[str, Any]:
        return {
            f"proxmox-k3s-0{index}": {
                "name": f"proxmox-k3s-0{index}",
                "vm_id": 319 + index,
                "address": f"10.66.0.20{index}/24",
                "node": "pve-01",
            }
            for index in range(1, 4)
        }

    def proxmox_host(self) -> dict[str, Any]:
        return {
            "instance_name": "proxmox-host",
            "zone": "europe-west4-a",
            "internal_ip": "10.77.0.220",
            "project_id": "shell-platform",
        }

    def args(
        self,
        root: Path,
        shared: dict[str, Any] | None = None,
        gcp_k3s: dict[str, Any] | None = None,
        proxmox_k3s: dict[str, Any] | None = None,
        proxmox_host: dict[str, Any] | None = None,
        wrapped: bool = False,
    ) -> SimpleNamespace:
        # Test both `tofu output -json NAME` maps and complete output objects;
        # temporary files keep the tests independent from .local state.
        values = [
            (
                "shared.json",
                self.shared_nodes() if shared is None else shared,
                "shared_nodes",
            ),
            (
                "gcp-k3s.json",
                self.gcp_k3s_nodes() if gcp_k3s is None else gcp_k3s,
                "k3s_nodes",
            ),
            (
                "proxmox-k3s.json",
                self.proxmox_k3s_nodes() if proxmox_k3s is None else proxmox_k3s,
                "nodes",
            ),
            (
                "proxmox-host.json",
                self.proxmox_host() if proxmox_host is None else proxmox_host,
                None,
            ),
        ]
        paths: list[Path] = []
        for filename, value, key in values:
            path = root / filename
            payload = (
                {
                    key: {
                        "sensitive": False,
                        "type": ["map", ["object", {}]],
                        "value": value,
                    }
                }
                if wrapped
                else value
            )
            if key is None and wrapped:
                payload = {
                    "proxmox_host": {
                        "sensitive": False,
                        "type": ["object", {}],
                        "value": value,
                    }
                }
            path.write_text(json.dumps(payload), encoding="utf-8")
            paths.append(path)
        return SimpleNamespace(
            shared_nodes_file=paths[0],
            gcp_k3s_file=paths[1],
            proxmox_k3s_file=paths[2],
            proxmox_host_file=paths[3],
            output=root / "inventory.json",
        )

    def build(self, **changes: Any) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), **changes)
            return cast(dict[str, Any], renderer.build_inventory(args))

    def rendered_hosts(self, value: dict[str, Any]) -> dict[str, Any]:
        groups = value["all"]["children"]["shell_nodes"]["children"]
        return {
            name: hostvars
            for group in groups.values()
            for name, hostvars in group["hosts"].items()
        }

    def test_valid_topology_produces_all_groups(self) -> None:
        value = self.build()
        hostvars = self.rendered_hosts(value)
        hosts = set(hostvars)
        self.assertEqual(
            hosts,
            {
                "identity-01",
                "delivery-01",
                "gcp-k3s-01",
                "gcp-k3s-02",
                "gcp-k3s-03",
                "proxmox-k3s-01",
                "proxmox-k3s-02",
                "proxmox-k3s-03",
            },
        )
        # Independent cluster groups must remain separate for later playbooks.
        self.assertEqual(
            list(value["all"]["children"]["shell_nodes"]["children"]),
            ["gcp_shared_nodes", "gcp_k3s_servers", "proxmox_k3s_servers"],
        )
        self.assertEqual(
            list(value["all"]["children"]["gcp_guests"]["children"]),
            ["gcp_shared_nodes", "gcp_k3s_servers"],
        )
        self.assertEqual(hostvars["identity-01"]["shell_role"], "identity")
        self.assertEqual(hostvars["gcp-k3s-01"]["shell_transport"], "gcp_iap")
        self.assertEqual(hostvars["gcp-k3s-01"]["gcp_project_id"], "shell-platform")
        self.assertEqual(hostvars["proxmox-k3s-01"]["proxmox_vm_id"], 320)
        self.assertEqual(
            value["all"]["children"]["proxmox_host"]["hosts"]["proxmox-host"][
                "shell_transport"
            ],
            "gcp_iap",
        )

    def test_complete_output_wrappers_are_accepted(self) -> None:
        value = self.build(wrapped=True)
        self.assertEqual(len(self.rendered_hosts(value)), 8)
        self.assertIn("proxmox-host", value["all"]["children"]["proxmox_host"]["hosts"])

    def test_complete_output_requires_expected_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), wrapped=True)
            payload = json.loads(args.shared_nodes_file.read_text(encoding="utf-8"))
            payload["other_nodes"] = payload.pop("shared_nodes")
            args.shared_nodes_file.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                renderer.InventoryError, "missing shared_nodes"
            ):
                renderer.build_inventory(args)

    def test_complete_output_rejects_malformed_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), wrapped=True)
            payload = {"shared_nodes": {"value": self.shared_nodes()}}
            args.shared_nodes_file.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(renderer.InventoryError, "malformed"):
                renderer.build_inventory(args)

    def test_complete_host_output_requires_expected_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary), wrapped=True)
            payload = json.loads(args.proxmox_host_file.read_text(encoding="utf-8"))
            payload["other_host"] = payload.pop("proxmox_host")
            args.proxmox_host_file.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                renderer.InventoryError, "missing proxmox_host"
            ):
                renderer.build_inventory(args)

    def test_missing_or_extra_node_is_rejected(self) -> None:
        shared = self.shared_nodes()
        del shared["delivery-01"]
        shared["unexpected"] = copy.deepcopy(self.shared_nodes()["identity-01"])
        with self.assertRaisesRegex(
            renderer.InventoryError, "shared GCP node set differs"
        ):
            self.build(shared=shared)

    def test_gcp_contract_address_drift_is_rejected(self) -> None:
        shared = self.shared_nodes()
        shared["identity-01"]["internal_ip"] = "10.77.0.212"
        with self.assertRaisesRegex(renderer.InventoryError, "contract address"):
            self.build(shared=shared)

        gcp_k3s = self.gcp_k3s_nodes()
        gcp_k3s["gcp-k3s-01"]["internal_ip"] = "10.77.0.204"
        with self.assertRaisesRegex(renderer.InventoryError, "contract address"):
            self.build(gcp_k3s=gcp_k3s)

    def test_invalid_gcp_zone_is_rejected(self) -> None:
        gcp_k3s = self.gcp_k3s_nodes()
        gcp_k3s["gcp-k3s-01"]["zone"] = "europe-west4-a;invalid"
        with self.assertRaisesRegex(renderer.InventoryError, "invalid zone"):
            self.build(gcp_k3s=gcp_k3s)

    def test_invalid_or_mismatched_gcp_project_is_rejected(self) -> None:
        shared = self.shared_nodes()
        shared["identity-01"]["project_id"] = "invalid project"
        with self.assertRaisesRegex(renderer.InventoryError, "invalid GCP project_id"):
            self.build(shared=shared)

        gcp_k3s = self.gcp_k3s_nodes()
        gcp_k3s["gcp-k3s-01"]["project_id"] = "other-platform"
        with self.assertRaisesRegex(renderer.InventoryError, "GCP project_id"):
            self.build(gcp_k3s=gcp_k3s)

    def test_empty_node_map_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            renderer.InventoryError, "shared GCP node set differs"
        ):
            self.build(shared={})

    def test_duplicate_gcp_address_is_rejected_as_contract_drift(self) -> None:
        gcp_k3s = self.gcp_k3s_nodes()
        gcp_k3s["gcp-k3s-02"]["internal_ip"] = "10.77.0.201"
        with self.assertRaisesRegex(renderer.InventoryError, "contract address"):
            self.build(gcp_k3s=gcp_k3s)

    def test_proxmox_host_must_use_gcp_subnet(self) -> None:
        host = self.proxmox_host()
        host["internal_ip"] = "10.78.0.220"
        with self.assertRaisesRegex(renderer.InventoryError, "10.77.0.0/24"):
            self.build(proxmox_host=host)

    def test_proxmox_host_contract_address_drift_is_rejected(self) -> None:
        host = self.proxmox_host()
        host["internal_ip"] = "10.77.0.219"
        with self.assertRaisesRegex(renderer.InventoryError, "contract address"):
            self.build(proxmox_host=host)

    def test_special_purpose_addresses_are_rejected(self) -> None:
        # These are rejection fixtures, not network bind addresses.
        for address in (
            "127.0.0.1",
            "169.254.1.1",
            str(ipaddress.IPv4Address(0)),
            "192.0.2.1",
        ):
            with self.subTest(address=address):
                gcp_k3s = self.gcp_k3s_nodes()
                gcp_k3s["gcp-k3s-01"]["internal_ip"] = address
                with self.assertRaisesRegex(renderer.InventoryError, "RFC1918"):
                    self.build(gcp_k3s=gcp_k3s)

    def test_invalid_cidr_prefix_is_rejected(self) -> None:
        proxmox_k3s = self.proxmox_k3s_nodes()
        proxmox_k3s["proxmox-k3s-01"]["address"] = "10.66.0.201/33"
        with self.assertRaisesRegex(renderer.InventoryError, "invalid address"):
            self.build(proxmox_k3s=proxmox_k3s)

    def test_proxmox_address_requires_usable_host_cidr(self) -> None:
        for address in ("10.66.0.201", "10.66.0.0/24", "10.66.0.255/24"):
            with self.subTest(address=address):
                proxmox_k3s = self.proxmox_k3s_nodes()
                proxmox_k3s["proxmox-k3s-01"]["address"] = address
                with self.assertRaisesRegex(
                    renderer.InventoryError, "usable host CIDR"
                ):
                    self.build(proxmox_k3s=proxmox_k3s)

    def test_proxmox_guest_must_use_declared_guest_network(self) -> None:
        proxmox_k3s = self.proxmox_k3s_nodes()
        proxmox_k3s["proxmox-k3s-01"]["address"] = "10.67.0.201/24"
        with self.assertRaisesRegex(renderer.InventoryError, "10.66.0.0/24"):
            self.build(proxmox_k3s=proxmox_k3s)

    def test_proxmox_contract_address_drift_is_rejected(self) -> None:
        proxmox_k3s = self.proxmox_k3s_nodes()
        proxmox_k3s["proxmox-k3s-01"]["address"] = "10.66.0.204/24"
        with self.assertRaisesRegex(renderer.InventoryError, "contract address"):
            self.build(proxmox_k3s=proxmox_k3s)

    def test_duplicate_proxmox_vm_ids_are_rejected(self) -> None:
        proxmox_k3s = self.proxmox_k3s_nodes()
        proxmox_k3s["proxmox-k3s-03"]["vm_id"] = 321
        with self.assertRaisesRegex(renderer.InventoryError, "VM IDs must be unique"):
            self.build(proxmox_k3s=proxmox_k3s)

    def test_proxmox_vm_id_requires_positive_json_integer(self) -> None:
        for vm_id in (True, "320", 320.5, 0):
            with self.subTest(vm_id=vm_id):
                proxmox_k3s = self.proxmox_k3s_nodes()
                proxmox_k3s["proxmox-k3s-01"]["vm_id"] = vm_id
                with self.assertRaisesRegex(
                    renderer.InventoryError, "positive JSON integer"
                ):
                    self.build(proxmox_k3s=proxmox_k3s)

    def test_default_output_is_anchored_to_repository_root(self) -> None:
        expected = SCRIPT.parents[2] / ".local" / "ansible" / "inventory.json"
        self.assertEqual(renderer.DEFAULT_OUTPUT, expected)
        self.assertTrue(renderer.DEFAULT_OUTPUT.is_absolute())

    def test_cli_validates_without_writing_and_reports_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary))
            command = [
                "--shared-nodes-file",
                str(args.shared_nodes_file),
                "--gcp-k3s-file",
                str(args.gcp_k3s_file),
                "--proxmox-k3s-file",
                str(args.proxmox_k3s_file),
                "--proxmox-host-file",
                str(args.proxmox_host_file),
                "--output",
                str(args.output),
                "--validate-only",
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = renderer.main(command)
            self.assertEqual(status, 0)
            self.assertFalse(args.output.exists())
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

            args.shared_nodes_file.write_text("{", encoding="utf-8")
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = renderer.main(command)
            self.assertEqual(status, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("inventory handoff failed", stderr.getvalue())

    def test_input_symlink_ancestor_and_invalid_utf8_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_parent = root / "real"
            real_parent.mkdir()
            input_file = real_parent / "nodes.json"
            input_file.write_text("{}", encoding="utf-8")
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(renderer.InventoryError, "symlink"):
                renderer.load_json(linked_parent / "nodes.json", "nodes")

            invalid_utf8 = root / "invalid.json"
            invalid_utf8.write_bytes(b"\xff")
            with self.assertRaisesRegex(renderer.InventoryError, "UTF-8"):
                renderer.load_json(invalid_utf8, "nodes")

    @unittest.skipUnless(ANSIBLE_INVENTORY, "ansible-inventory unavailable")
    def test_generated_inventory_is_accepted_by_ansible(self) -> None:
        if ANSIBLE_INVENTORY is None:
            self.fail("ansible-inventory disappeared after test discovery")
        ansible_inventory = ANSIBLE_INVENTORY
        with tempfile.TemporaryDirectory() as temporary:
            args = self.args(Path(temporary))
            renderer.atomic_write(args.output, renderer.build_inventory(args))
            completed = subprocess.run(  # nosec B603
                [ansible_inventory, "-i", str(args.output), "--list"],
                check=True,
                capture_output=True,
                text=True,
            )
            inventory = json.loads(completed.stdout)
            self.assertEqual(len(inventory["_meta"]["hostvars"]), 9)
            self.assertEqual(
                {
                    host
                    for child in inventory["gcp_guests"]["children"]
                    for host in inventory[child]["hosts"]
                },
                {
                    "identity-01",
                    "delivery-01",
                    "gcp-k3s-01",
                    "gcp-k3s-02",
                    "gcp-k3s-03",
                },
            )
            self.assertIn("proxmox_k3s_servers", inventory)

    def test_atomic_output_is_private_and_symlinks_are_rejected(self) -> None:
        # Generated inventory is a private handoff and must never follow a
        # symlink supplied by an unsafe output path.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "inventory.json"
            renderer.atomic_write(output, {"safe": True})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")), {"safe": True}
            )

            target = root / "target.json"
            target.write_text("existing", encoding="utf-8")
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(renderer.InventoryError, "symlink"):
                renderer.atomic_write(linked, {"changed": True})

            permissive = root / "permissive"
            permissive.mkdir(mode=0o755)
            with self.assertRaisesRegex(renderer.InventoryError, "private"):
                renderer.atomic_write(permissive / "inventory.json", {"safe": False})

            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(renderer.InventoryError, "symlink"):
                renderer.atomic_write(
                    linked_parent / "nested" / "inventory.json",
                    {"safe": False},
                )


if __name__ == "__main__":
    unittest.main()
