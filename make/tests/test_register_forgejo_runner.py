"""Test the controller-side Forgejo runner registration boundary."""

from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "make/scripts/register_forgejo_runner.py"
SPEC = importlib.util.spec_from_file_location("register_forgejo_runner", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load Forgejo runner registrar: {SCRIPT}")
registrar = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = registrar
SPEC.loader.exec_module(registrar)


def runner_config() -> dict[str, str]:
    return {
        "address": registrar.DELIVERY_URL,
        "uuid": "37633331-3539-3165-3862-363732323561",
        "token": "7c31591e8b67225a116d4a4519ea8e507e08f71f",
        "name": registrar.RUNNER_NAME,
    }


def runner_document() -> dict[str, object]:
    config = runner_config()
    return {
        "schema_version": "1.0",
        "contract_id": "delivery-input-contract",
        "class": "forgejo_runner",
        "issuer": "forgejo-after-bootstrap",
        "deployment_target": registrar.DELIVERY_NODE,
        "one_time_bootstrap": True,
        "forgejo_runner": {
            "url": registrar.DELIVERY_URL,
            "name": registrar.RUNNER_NAME,
            "uuid": config["uuid"],
            "token": config["token"],
            "runner_config": config,
        },
    }


class TestForgejoRunner(unittest.TestCase):
    def test_runner_constants_match_the_current_delivery_supply(self) -> None:
        self.assertIn(
            "sha256:7fb853bfe73c229be6349398359c0a7bd01fadfd17c106607b2221150b799ed2",
            registrar.RUNNER_IMAGE,
        )
        self.assertEqual(
            "docker:docker://docker.io/library/node:24-bookworm",
            registrar.RUNNER_LABEL,
        )
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn(":latest", source)
        self.assertNotIn("--limit", source)
        self.assertNotIn("register_forgejo_repository", source)

    def test_runner_handoff_shape_is_strict_and_project_bound(self) -> None:
        document = runner_document()
        self.assertIs(registrar.validate_runner_document(document), document)

        altered = json.loads(json.dumps(document))
        altered["deployment_target"] = "some-other-host"
        with self.assertRaisesRegex(registrar.RunnerError, "target changed"):
            registrar.validate_runner_document(altered)

    def test_private_files_require_mode_0600_and_no_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private.sops.json"
            private.write_text("{}", encoding="utf-8")
            private.chmod(0o600)
            self.assertEqual(private, registrar.require_private_file(private, "input"))

            private.chmod(0o644)
            with self.assertRaisesRegex(registrar.RunnerError, "mode 0600"):
                registrar.require_private_file(private, "input")

            private.chmod(0o600)
            link = root / "link.sops.json"
            link.symlink_to(private)
            with self.assertRaisesRegex(registrar.RunnerError, "symlinked"):
                registrar.require_private_file(link, "input")

    def test_existing_handoff_is_reused_without_guest_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_root = root / "delivery"
            private_root.mkdir(mode=0o700)
            handoff = private_root / "forgejo-runner.sops.json"
            handoff.write_text("ciphertext", encoding="utf-8")
            handoff.chmod(0o600)
            age_key = private_root / "age-key.txt"
            age_key.write_text("identity", encoding="utf-8")
            age_key.chmod(0o600)

            with (
                mock.patch.object(registrar, "decrypt_document", return_value=runner_document()),
                mock.patch.object(registrar, "resolve_connection") as resolve,
                mock.patch.object(registrar, "offline_register") as register,
            ):
                result = registrar.register(
                    age_key,
                    handoff,
                    [root / "inventory.json"],
                )

            self.assertEqual(runner_document(), result)
            resolve.assert_not_called()
            register.assert_not_called()

    def test_validate_only_fails_closed_when_handoff_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_root = root / "delivery"
            private_root.mkdir(mode=0o700)
            age_key = private_root / "age-key.txt"
            age_key.write_text("identity", encoding="utf-8")
            age_key.chmod(0o600)
            with self.assertRaisesRegex(registrar.RunnerError, "handoff is missing"):
                registrar.register(
                    age_key,
                    private_root / "missing.sops.json",
                    [root / "inventory.json"],
                    validate_only=True,
                )

    def test_inventory_resolution_requires_the_fixed_delivery_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "inventory.json"
            inventory.write_text("{}", encoding="utf-8")
            inventory.chmod(0o600)
            common_args = (
                '-o ProxyCommand="gcloud compute start-iap-tunnel delivery-01 %p '
                '--listen-on-stdin --project=environment-gcp --zone=europe-west4-b" '
                "-o UserKnownHostsFile=/tmp/known_hosts -o StrictHostKeyChecking=yes"
            )
            host = {
                "ansible_host": registrar.DELIVERY_ADDRESS,
                "ansible_user": "operator",
                "ansible_ssh_common_args": common_args,
            }
            with mock.patch.object(registrar, "run", return_value=json.dumps(host)) as run:
                connection = registrar.resolve_connection([inventory])

            self.assertEqual("operator@10.77.0.211", connection.target)
            self.assertTrue(
                any(
                    option.startswith(
                        "ProxyCommand=gcloud compute start-iap-tunnel delivery-01"
                    )
                    for option in connection.options
                )
            )
            run.assert_called_once()

            unsafe = dict(host)
            unsafe["ansible_host"] = "10.77.0.212"
            with mock.patch.object(registrar, "run", return_value=json.dumps(unsafe)):
                with self.assertRaisesRegex(registrar.RunnerError, "wrong delivery address"):
                    registrar.resolve_connection([inventory])

            unsafe = dict(host)
            unsafe["ansible_ssh_common_args"] = common_args.replace(
                "--zone=europe-west4-b", "--zone=europe-west4-b;touch /tmp/bad"
            )
            with mock.patch.object(registrar, "run", return_value=json.dumps(unsafe)):
                with self.assertRaisesRegex(registrar.RunnerError, "fixed delivery IAP route"):
                    registrar.resolve_connection([inventory])

    def test_remote_commands_receive_secrets_on_stdin_only(self) -> None:
        connection = registrar.DeliveryConnection("operator@10.77.0.211", ())
        secret = "7c31591e8b67225a116d4a4519ea8e507e08f71f"
        expected_uuid = "37633331-3539-3165-3862-363732323561"
        with mock.patch.object(registrar, "ssh", return_value=expected_uuid) as ssh:
            runner_uuid = registrar.offline_register(secret, connection)
        self.assertEqual(expected_uuid, runner_uuid)
        command = ssh.call_args.args[0]
        self.assertNotIn(secret, command)
        self.assertIn("RUNNER_SECRET", command)
        self.assertIn("--secret-stdin stdin", command)
        self.assertEqual(f"{secret}\n", ssh.call_args.kwargs["input_text"])

    def test_registration_requires_approval_before_external_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            with (
                self.assertRaisesRegex(registrar.RunnerError, "exact runner"),
                mock.patch.object(registrar, "resolve_connection") as resolve,
            ):
                registrar.register(
                    private_root / "age-key.txt",
                    private_root / "runner.sops.json",
                    [private_root / "inventory.json"],
                )
            resolve.assert_not_called()

    def test_registration_and_rotation_publish_the_registered_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            age_key = private_root / "age-key.txt"
            age_key.write_text("identity", encoding="utf-8")
            age_key.chmod(0o600)
            handoff = private_root / "runner.sops.json"
            connection = registrar.DeliveryConnection("operator@10.77.0.211", ())
            captured: dict[str, object] = {}

            def encrypt(document: dict[str, object], *_: object) -> None:
                captured["document"] = document

            def decrypt(*_: object) -> dict[str, object]:
                return cast(
                    dict[str, object],
                    captured.get("document", runner_document()),
                )

            with (
                mock.patch.object(registrar, "resolve_connection", return_value=connection),
                mock.patch.object(registrar, "offline_register", return_value=runner_config()["uuid"]),
                mock.patch.object(registrar, "encrypt_document", side_effect=encrypt),
                mock.patch.object(registrar, "decrypt_document", side_effect=decrypt),
                mock.patch.object(registrar.secrets, "token_hex", return_value="a" * 40),
            ):
                created = registrar.register(
                    age_key,
                    handoff,
                    [private_root / "inventory.json"],
                    approval=registrar.RUNNER_APPROVAL,
                )

            created_runner = cast(dict[str, str], created["forgejo_runner"])
            self.assertEqual("a" * 40, created_runner["token"])
            captured.clear()
            handoff.write_text("ciphertext", encoding="utf-8")
            handoff.chmod(0o600)
            with (
                mock.patch.object(registrar, "resolve_connection", return_value=connection),
                mock.patch.object(registrar, "offline_register", return_value=runner_config()["uuid"]),
                mock.patch.object(registrar, "encrypt_document", side_effect=encrypt),
                mock.patch.object(registrar, "decrypt_document", side_effect=decrypt),
                mock.patch.object(registrar.secrets, "token_hex", return_value="b" * 24),
            ):
                rotated = registrar.register(
                    age_key,
                    handoff,
                    [private_root / "inventory.json"],
                    approval=registrar.RUNNER_APPROVAL,
                    rotate=True,
                )

            old_token = runner_config()["token"]
            rotated_runner = cast(dict[str, str], rotated["forgejo_runner"])
            self.assertEqual(old_token[:16] + "b" * 24, rotated_runner["token"])

    def test_encrypt_output_is_private_and_does_not_leave_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            age_key = private_root / "age-key.txt"
            age_key.write_text("identity", encoding="utf-8")
            age_key.chmod(0o600)
            output = private_root / "runner.sops.json"

            def fake_run(command: list[str], **_: object) -> str:
                if command[:2] == ["age-keygen", "-y"]:
                    return "age1example\n"
                encrypted = Path(command[command.index("--output") + 1])
                encrypted.write_text("encrypted", encoding="utf-8")
                return ""

            with mock.patch.object(registrar, "run", side_effect=fake_run):
                registrar.encrypt_document(runner_document(), output, age_key)

            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            self.assertNotIn(runner_config()["uuid"], output.read_text(encoding="utf-8"))
            self.assertEqual([], list(private_root.glob("*.plaintext.*")))


if __name__ == "__main__":
    unittest.main()
