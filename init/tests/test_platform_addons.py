"""Test the fixed INIT platform add-on boundary without Ansible execution."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_platform_addons", ROOT / "init/scripts/run_platform_addons.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform launcher")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)

FILTER_SPEC = importlib.util.spec_from_file_location(
    "platform_disk",
    ROOT / "init/ansible/playbooks/filter_plugins/platform_disk.py",
)
if FILTER_SPEC is None or FILTER_SPEC.loader is None:
    raise RuntimeError("cannot load platform disk filter")
disk_filter = importlib.util.module_from_spec(FILTER_SPEC)
FILTER_SPEC.loader.exec_module(disk_filter)


class PlatformAddonsTests(unittest.TestCase):
    def test_actions_map_only_to_fixed_playbooks(self) -> None:
        self.assertEqual(
            set(launcher.PLAYBOOKS),
            {"configure", "verify", "registry-trust", "registry-trust-verify"},
        )
        for name in launcher.PLAYBOOKS.values():
            self.assertTrue((ROOT / "init/ansible/playbooks" / name).is_file())

    def test_service_addresses_and_workload_mutation_are_deferred(self) -> None:
        source = (ROOT / "init/ansible/vars/platform-addons.yml").read_text(
            encoding="utf-8"
        )
        playbook = (
            ROOT / "init/ansible/playbooks/configure-platform-addons.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("10.77.0.221", source)
        self.assertNotIn("10.77.0.222", source)
        self.assertNotIn("helm upgrade", playbook)
        self.assertNotIn("kubectl\n          - apply", playbook)

    def test_playbooks_do_not_accept_an_arbitrary_cluster(self) -> None:
        source = (
            ROOT / "init/ansible/playbooks/configure-platform-addons.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("shell_platform_target_group == 'gcp_k3s_servers'", source)
        self.assertIn("ansible_play_hosts_all == groups.gcp_k3s_servers", source)
        self.assertNotIn("shell_platform_target_group | default", source)

    def test_disk_guard_uses_the_behavior_tested_filter(self) -> None:
        playbook = (
            ROOT / "init/ansible/playbooks/configure-platform-addons.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("shell_platform_safe_disk_topology", playbook)

    def test_safe_disk_topology_matrix(self) -> None:
        target = "/var/lib/longhorn"

        def topology(
            mounts: list[object], *, children: list[object] | None = None
        ) -> dict[str, object]:
            device: dict[str, object] = {
                "name": "sdb",
                "type": "disk",
                "mountpoints": mounts,
            }
            if children is not None:
                device["children"] = children
            return {"blockdevices": [device]}

        cases = [
            ("formatted unmounted", topology([None]), 0, True),
            ("formatted at target", topology([target]), 0, True),
            ("formatted foreign mount", topology(["/srv/data"]), 0, False),
            ("unformatted unmounted", topology([None]), 2, True),
            ("unformatted mounted", topology([target]), 2, False),
            ("multiple mounts", topology([target, target]), 0, False),
            (
                "partitioned",
                topology([], children=[{"name": "sdb1", "type": "part"}]),
                0,
                False,
            ),
        ]
        for label, value, filesystem_rc, expected in cases:
            with self.subTest(case=label):
                self.assertEqual(
                    disk_filter.safe_disk_topology(value, filesystem_rc, target),
                    expected,
                )

    def test_canonical_rendered_inventory_is_accepted(self) -> None:
        inventory: dict[str, Any] = {
            "all": {
                "children": {
                    "shell_nodes": {
                        "children": {
                            "gcp_k3s_servers": {
                                "hosts": {
                                    "gcp-k3s-01": {},
                                    "gcp-k3s-02": {},
                                    "gcp-k3s-03": {},
                                }
                            }
                        }
                    }
                }
            }
        }
        with mock.patch.object(launcher, "load_inventory", return_value=inventory):
            launcher.validate_inventory(Path("inventory.json"))

    def test_data_disk_format_gate_is_configure_only(self) -> None:
        with self.assertRaisesRegex(launcher.PlatformLauncherError, "configure"):
            launcher.run("verify", check=False, format_data_disk=True)

    def test_mutation_requires_launcher_approval(self) -> None:
        with self.assertRaisesRegex(launcher.PlatformLauncherError, "approval"):
            with (
                mock.patch.object(launcher, "validate_inventory"),
                mock.patch.object(launcher, "private_file"),
                mock.patch.object(
                    launcher.k3s_runtime, "validate_connection_inventory"
                ),
            ):
                launcher.run("configure", check=False)

    def test_launcher_selects_the_reviewed_collection_path(self) -> None:
        with (
            mock.patch.object(launcher, "validate_inventory"),
            mock.patch.object(launcher, "private_file"),
            mock.patch.object(
                launcher.k3s_runtime, "validate_connection_inventory"
            ) as validate_connection,
            mock.patch.object(
                launcher.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as run,
        ):
            launcher.run("verify", check=True)
        self.assertEqual(
            run.call_args.kwargs["env"]["ANSIBLE_COLLECTIONS_PATH"],
            launcher.COLLECTIONS_PATH,
        )
        self.assertIs(validate_connection.call_args.args[-1], launcher.run_ansible)

    def test_collection_version_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ansible_collections"
            collection = root / "ansible/posix"
            collection.mkdir(parents=True)
            manifest = collection / "MANIFEST.json"
            manifest.write_text(
                json.dumps(
                    {
                        "collection_info": {
                            "namespace": "ansible",
                            "name": "posix",
                            "version": "2.1.0",
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(launcher, "COLLECTIONS_ROOT", root):
                with self.assertRaisesRegex(
                    launcher.PlatformLauncherError, "version 2.2.0"
                ):
                    launcher.validate_ansible_posix()


if __name__ == "__main__":
    unittest.main()
