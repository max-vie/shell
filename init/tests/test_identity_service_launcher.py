"""Test the fixed INIT FreeIPA controller boundary."""

from __future__ import annotations

import importlib.util
import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "init/scripts/run_identity_service.py"
SPEC = importlib.util.spec_from_file_location("run_identity_service", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load identity service launcher")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


class TestIdentityServiceLauncher(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        for relative in (
            ".local",
            ".local/ansible",
            ".local/ansible/.identity-service",
            ".local/sudo",
            ".local/sudo/identity",
            "sudo/access",
            "init/ansible/playbooks",
        ):
            path = self.root / relative
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        shutil.copyfile(
            ROOT / "sudo/access/freeipa-host-profile.json",
            self.root / "sudo/access/freeipa-host-profile.json",
        )
        self._write_private(self.root / ".local/ansible/inventory.json", "inventory")
        self._write_private(
            self.root / ".local/ansible/connection-inventory.yml", "connection"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_private(path: Path, value: str | bytes) -> None:
        if isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(value, encoding="utf-8")
        path.chmod(0o600)

    @staticmethod
    def inventory_output() -> dict[str, Any]:
        common_args = (
            '-o ProxyCommand="gcloud compute start-iap-tunnel '
            "{{ inventory_hostname | quote }} %p --listen-on-stdin "
            "--project={{ gcp_project_id | quote }} "
            '--zone={{ gcp_zone | quote }}" '
            "-o StrictHostKeyChecking=yes"
        )
        return {
            "_meta": {
                "hostvars": {
                    "identity-01": {
                        "ansible_host": "10.77.0.210",
                        "shell_expected_address": "10.77.0.210",
                        "shell_role": "identity",
                        "shell_cluster": "shared",
                        "shell_transport": "gcp_iap",
                        "shell_operating_system": "almalinux-9",
                        "gcp_project_id": "test-project",
                        "gcp_zone": "europe-west4-a",
                        "ansible_connection": "ssh",
                        "ansible_user": "test-user",
                        "ansible_ssh_common_args": common_args,
                    }
                }
            },
            "identity_nodes": {"hosts": ["identity-01"]},
        }

    def run_inventory(self, *_: object, **__: object) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(self.inventory_output()),
        )

    def test_inventory_accepts_only_the_fixed_identity_target(self) -> None:
        host = launcher.validate_inventory(
            self.root / ".local/ansible/inventory.json",
            self.root / ".local/ansible/connection-inventory.yml",
            repository_root=self.root,
            run_process=self.run_inventory,
        )
        self.assertEqual(host["shell_role"], "identity")
        self.assertEqual(host["gcp_zone"], "europe-west4-a")

    def test_check_mode_builds_fixed_command_without_private_inputs(self) -> None:
        commands: list[list[str]] = []

        def run(command: list[str], **kwargs: object) -> SimpleNamespace:
            if command[0] == "ansible-inventory":
                return self.run_inventory(**kwargs)
            commands.append(command)
            extra = Path(command[command.index("--extra-vars") + 1][1:])
            self.assertEqual(stat.S_IMODE(extra.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(extra.read_text(encoding="utf-8")),
                {"shell_identity_approval": ""},
            )
            return SimpleNamespace(returncode=0)

        result = launcher.execute(
            "configure",
            check=True,
            repository_root=self.root,
            run_process=run,
        )
        self.assertEqual(result, 0)
        self.assertEqual(len(commands), 1)
        self.assertIn("--check", commands[0])
        self.assertTrue(commands[0][-1].endswith("configure-identity-service.yml"))
        self.assertEqual(
            list((self.root / ".local/ansible/.identity-service").iterdir()), []
        )

    def test_apply_requires_approval_before_private_inputs(self) -> None:
        with self.assertRaisesRegex(launcher.IdentityLauncherError, "approval must be"):
            launcher.execute(
                "configure",
                approval="wrong",
                repository_root=self.root,
                run_process=self.run_inventory,
            )

    def test_apply_requires_private_inputs_after_approval(self) -> None:
        with self.assertRaisesRegex(
            launcher.IdentityLauncherError, "private FreeIPA input"
        ):
            launcher.execute(
                "configure",
                approval=launcher.APPROVAL,
                repository_root=self.root,
                run_process=self.run_inventory,
            )

    def test_verify_uses_the_fixed_read_only_playbook(self) -> None:
        commands: list[list[str]] = []

        def run(command: list[str], **_: object) -> SimpleNamespace:
            if command[0] == "ansible-inventory":
                return self.run_inventory()
            commands.append(command)
            return SimpleNamespace(returncode=0)

        self.assertEqual(
            launcher.execute("verify", repository_root=self.root, run_process=run),
            0,
        )
        self.assertEqual(len(commands), 1)
        self.assertNotIn("--check", commands[0])
        self.assertTrue(commands[0][-1].endswith("verify-identity-service.yml"))

    def test_bind_check_uses_the_fixed_playbook_without_private_inputs(self) -> None:
        commands: list[list[str]] = []

        def run(command: list[str], **_: object) -> SimpleNamespace:
            if command[0] == "ansible-inventory":
                return self.run_inventory()
            commands.append(command)
            return SimpleNamespace(returncode=0)

        self.assertEqual(
            launcher.execute(
                "bind",
                check=True,
                repository_root=self.root,
                run_process=run,
            ),
            0,
        )
        self.assertEqual(len(commands), 1)
        self.assertIn("--check", commands[0])
        self.assertTrue(commands[0][-1].endswith("configure-keycloak-ldap-bind.yml"))

    def test_inventory_rejects_root_and_wrong_address(self) -> None:
        for key, value, message in (
            ("ansible_user", "root", "non-root"),
            ("ansible_host", "10.77.0.211", "address changed"),
        ):
            with self.subTest(key=key):
                document = self.inventory_output()
                document["_meta"]["hostvars"]["identity-01"][key] = value

                def run(*_: object, **__: object) -> SimpleNamespace:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(document),
                    )

                with self.assertRaisesRegex(launcher.IdentityLauncherError, message):
                    launcher.validate_inventory(
                        self.root / ".local/ansible/inventory.json",
                        self.root / ".local/ansible/connection-inventory.yml",
                        repository_root=self.root,
                        run_process=run,
                    )


if __name__ == "__main__":
    unittest.main()
