"""Test the controller-side Forgejo repository registration boundary."""

from __future__ import annotations

import importlib.util
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import cast
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_ROOT = SOURCE_ROOT / "make/scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))
SCRIPT = SCRIPTS_ROOT / "register_forgejo_repository.py"
SPEC = importlib.util.spec_from_file_location("register_forgejo_repository", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load Forgejo repository registrar: {SCRIPT}")
registrar = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = registrar
SPEC.loader.exec_module(registrar)


def repository_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "contract_id": "delivery-input-contract",
        "class": "forgejo_repository",
        "issuer": "forgejo-after-bootstrap",
        "deployment_target": "delivery-node-only",
        "one_time_bootstrap": True,
        "rotation": "explicit-approved",
        "forgejo_repository": {
            "url": registrar.REPOSITORY_URL,
            "username": registrar.BOT_USERNAME,
            "api_token": "a" * 40,
        },
    }


class TestForgejoRepository(unittest.TestCase):
    def test_repository_handoff_shape_is_strict_and_project_bound(self) -> None:
        document = repository_document()
        self.assertIs(registrar.validate_repository_document(document), document)

        altered = json.loads(json.dumps(document))
        altered["deployment_target"] = "delivery-01"
        with self.assertRaisesRegex(registrar.RepositoryError, "target changed"):
            registrar.validate_repository_document(altered)

        altered = json.loads(json.dumps(document))
        altered["forgejo_repository"]["url"] = (
            "https://forgejo.shell.internal/other/repository.git"
        )
        with self.assertRaisesRegex(registrar.RepositoryError, "URL changed"):
            registrar.validate_repository_document(altered)

    def test_source_has_no_broad_selector_or_deferred_workload(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn(":latest", source)
        self.assertNotIn("--limit", source)
        self.assertNotIn("kubectl", source)
        self.assertNotIn("openbao", source.lower())

    def test_repository_url_matches_the_sudo_contract(self) -> None:
        contract = json.loads(
            (
                SOURCE_ROOT / "sudo/secrets/delivery-input-contract.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            registrar.REPOSITORY_URL,
            contract["classes"]["forgejo_repository"]["repository_url"],
        )
        self.assertEqual(
            "explicit-approved",
            contract["classes"]["forgejo_repository"]["rotation"],
        )

    def test_existing_handoff_is_reused_without_remote_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            handoff = private_root / "forgejo-repository.sops.json"
            handoff.write_text("ciphertext", encoding="utf-8")
            handoff.chmod(0o600)
            age_key = private_root / "age-key.txt"
            age_key.write_text("identity", encoding="utf-8")
            age_key.chmod(0o600)

            with (
                mock.patch.object(
                    registrar.delivery,
                    "decrypt_document",
                    return_value=repository_document(),
                ),
                mock.patch.object(registrar.delivery, "resolve_connection") as resolve,
                mock.patch.object(registrar, "ensure_repository") as ensure,
            ):
                result = registrar.register(
                    Path(temporary) / "bootstrap.sops.json",
                    age_key,
                    handoff,
                    [Path(temporary) / "inventory.json"],
                )

            self.assertEqual(repository_document(), result)
            resolve.assert_not_called()
            ensure.assert_not_called()

    def test_private_handoff_requires_mode_0600_and_no_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            handoff = private_root / "repository.sops.json"
            handoff.write_text("ciphertext", encoding="utf-8")
            handoff.chmod(0o644)
            with self.assertRaisesRegex(registrar.delivery.RunnerError, "mode 0600"):
                registrar.register(
                    Path(temporary) / "bootstrap.sops.json",
                    handoff,
                    handoff,
                    [Path(temporary) / "inventory.json"],
                )

            handoff.chmod(0o600)
            link = private_root / "link.sops.json"
            link.symlink_to(handoff)
            with self.assertRaisesRegex(registrar.delivery.RunnerError, "symlinked"):
                registrar.delivery.require_private_file(link, "repository handoff")

    def test_api_keeps_credentials_and_payload_out_of_remote_command(self) -> None:
        connection = registrar.delivery.DeliveryConnection("operator@10.77.0.211", ())
        with mock.patch.object(registrar.delivery, "ssh", return_value="201\n{}") as ssh:
            code, body = registrar.api(
                "POST",
                "/api/v1/orgs",
                "admin-user",
                "admin-password",
                connection,
                payload={"password": "bot-password"},
                ok_codes=(201,),
            )

        self.assertEqual((201, "{}"), (code, body))
        command = ssh.call_args.args[0]
        self.assertNotIn("admin-user", command)
        self.assertNotIn("admin-password", command)
        self.assertNotIn("bot-password", command)
        input_lines = ssh.call_args.kwargs["input_text"].splitlines()
        self.assertEqual("admin-user", input_lines[0])
        self.assertEqual("admin-password", input_lines[1])
        self.assertEqual(
            {"password": "bot-password"},
            json.loads(base64.b64decode(input_lines[2])),
        )

    def test_seed_keeps_bot_token_out_of_remote_command(self) -> None:
        connection = registrar.delivery.DeliveryConnection("operator@10.77.0.211", ())
        with mock.patch.object(registrar.delivery, "ssh") as ssh:
            registrar.seed_repository("b" * 40, connection)
        command = ssh.call_args.args[0]
        self.assertNotIn("b" * 40, command)
        self.assertEqual("b" * 40, ssh.call_args.kwargs["input_text"][:-1])
        self.assertIn("cmp --silent README.md", command)
        self.assertIn("cmp --silent .forgejo/workflows/ci.yml", command)

    def test_token_creation_reconciles_and_limits_the_token_to_make(self) -> None:
        connection = registrar.delivery.DeliveryConnection(
            "operator@10.77.0.211", ()
        )
        with mock.patch.object(
            registrar,
            "api_json",
            side_effect=[
                (200, [{"id": 7, "name": registrar.TOKEN_NAME}]),
                (204, None),
                (201, {"sha1": "c" * 40}),
            ],
        ) as api:
            token = registrar.create_bot_token("admin", "password", connection)

        self.assertEqual("c" * 40, token)
        self.assertEqual(
            f"/api/v1/admin/users/{registrar.BOT_USERNAME}/tokens/7",
            api.call_args_list[1].args[1],
        )
        payload = api.call_args_list[2].kwargs["payload"]
        self.assertEqual(["write:repository"], payload["scopes"])
        self.assertEqual(
            [{"owner": registrar.ORG_NAME, "name": registrar.REPOSITORY_NAME}],
            payload["repositories"],
        )

    def test_bootstrap_failure_stops_before_later_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            connection = registrar.delivery.DeliveryConnection(
                "operator@10.77.0.211", ()
            )
            bootstrap: dict[str, object] = {
                "class": "forgejo_bootstrap",
                "forgejo_bootstrap": {
                    "admin_username": "admin",
                    "admin_password": "password",
                },
            }
            with (
                mock.patch.object(
                    registrar.delivery,
                    "decrypt_document",
                    return_value=bootstrap,
                ),
                mock.patch.object(
                    registrar.delivery,
                    "resolve_connection",
                    return_value=connection,
                ),
                mock.patch.object(
                    registrar,
                    "ensure_bot_user",
                    side_effect=registrar.RepositoryError("bot failed"),
                ),
                mock.patch.object(registrar, "ensure_organization") as org,
                mock.patch.object(registrar, "ensure_repository") as repository,
                mock.patch.object(registrar, "create_bot_token") as token,
            ):
                with self.assertRaisesRegex(registrar.RepositoryError, "bot failed"):
                    registrar.register(
                        private_root / "bootstrap.sops.json",
                        private_root / "age-key.txt",
                        private_root / "repository.sops.json",
                        [private_root / "inventory.json"],
                        approval=registrar.REPOSITORY_APPROVAL,
                    )
            org.assert_not_called()
            repository.assert_not_called()
            token.assert_not_called()

    def test_rotation_replaces_the_encrypted_repository_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            handoff = private_root / "forgejo-repository.sops.json"
            handoff.write_text("ciphertext", encoding="utf-8")
            handoff.chmod(0o600)
            connection = registrar.delivery.DeliveryConnection(
                "operator@10.77.0.211", ()
            )
            captured: dict[str, object] = {}
            bootstrap: dict[str, object] = {
                "class": "forgejo_bootstrap",
                "forgejo_bootstrap": {
                    "admin_username": "admin",
                    "admin_password": "password",
                },
            }

            def decrypt(path: Path, *_: object) -> dict[str, object]:
                if path.name == "bootstrap.sops.json":
                    return bootstrap
                return cast(
                    dict[str, object],
                    captured.get("document", repository_document()),
                )

            def encrypt(document: dict[str, object], *_: object) -> None:
                captured["document"] = document

            with (
                mock.patch.object(
                    registrar.delivery,
                    "decrypt_document",
                    side_effect=decrypt,
                ),
                mock.patch.object(
                    registrar.delivery,
                    "resolve_connection",
                    return_value=connection,
                ),
                mock.patch.object(registrar, "ensure_bot_user"),
                mock.patch.object(registrar, "ensure_organization"),
                mock.patch.object(registrar, "ensure_repository"),
                mock.patch.object(registrar, "grant_bot_write"),
                mock.patch.object(
                    registrar,
                    "create_bot_token",
                    return_value="d" * 40,
                ),
                mock.patch.object(registrar, "seed_repository"),
                mock.patch.object(registrar, "verify_repository"),
                mock.patch.object(
                    registrar.delivery,
                    "encrypt_document",
                    side_effect=encrypt,
                ),
            ):
                rotated = registrar.register(
                    private_root / "bootstrap.sops.json",
                    private_root / "age-key.txt",
                    handoff,
                    [private_root / "inventory.json"],
                    approval=registrar.REPOSITORY_APPROVAL,
                    rotate=True,
                )
            rotated_repository = cast(
                dict[str, str], rotated["forgejo_repository"]
            )
            self.assertEqual("d" * 40, rotated_repository["api_token"])

    def test_verify_only_requires_an_existing_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            private_root = Path(temporary) / "delivery"
            private_root.mkdir(mode=0o700)
            age_key = private_root / "age-key.txt"
            age_key.write_text("identity", encoding="utf-8")
            age_key.chmod(0o600)
            with self.assertRaisesRegex(registrar.RepositoryError, "handoff is missing"):
                registrar.register(
                    Path(temporary) / "bootstrap.sops.json",
                    age_key,
                    private_root / "missing.sops.json",
                    [Path(temporary) / "inventory.json"],
                    verify_only=True,
                )
if __name__ == "__main__":
    unittest.main()
