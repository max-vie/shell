"""Test MAKE cluster-trust command and certificate boundaries."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


intermediate = load(
    "apply_cluster_intermediate",
    SOURCE_ROOT / "make/scripts/apply_cluster_intermediate.py",
)
certificate = load(
    "apply_consumer_certificate",
    SOURCE_ROOT / "make/scripts/apply_consumer_certificate.py",
)


class TestClusterTrustScripts(unittest.TestCase):
    def test_secret_manifest_contains_the_three_tls_values(self) -> None:
        manifest, encoded = intermediate.secret_manifest(
            {
                "certificate": "CERTIFICATE",
                "private_key": "PRIVATE KEY",
                "root_ca": "ROOT CA",
            }
        )
        document = json.loads(manifest)
        self.assertEqual(document["type"], "kubernetes.io/tls")
        self.assertEqual(
            set(document["data"]),
            {"tls.crt", "tls.key", "ca.crt"},
        )
        self.assertEqual(
            base64.b64decode(encoded["tls.key"]).decode(), "PRIVATE KEY"
        )

    def test_intermediate_apply_requires_exact_approval(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            result = intermediate.main(
                ["apply", "--cluster", "gcp", "--approval", "wrong"]
            )
        self.assertEqual(result, 2)
        self.assertIn("exact cluster-trust approval", error.getvalue())

    def test_intermediate_apply_uses_server_side_apply_and_readback(self) -> None:
        payload = {
            "certificate": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            "private_key": (
                "-----BEGIN " + "PRIVATE KEY-----\nkey\n-----END "
                + "PRIVATE KEY-----"
            ),
            "root_ca": "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
        }
        commands: list[list[str]] = []
        manifest, encoded = intermediate.secret_manifest(payload)

        def run(command: list[str], **kwargs: object) -> str:
            commands.append(command)
            if "secret" in command and "get" in command:
                return json.dumps(
                    {
                        "metadata": {
                            "name": "shell-cluster-intermediate",
                            "namespace": "cert-manager",
                            "labels": {"shell.platform/owner": "sudo"},
                        },
                        "type": "kubernetes.io/tls",
                        "data": encoded,
                    }
                )
            if "wait" in command:
                return "condition met"
            if "clusterissuer" in command and "get" in command:
                return json.dumps(
                    {
                        "metadata": {
                            "name": "shell-cluster-intermediate",
                            "annotations": {
                                "shell.platform/owner": "sudo",
                                "shell.platform/input": "kubernetes-ecosystem-input-contract",
                            },
                        },
                        "spec": {"ca": {"secretName": "shell-cluster-intermediate"}},
                    }
                )
            if "--filename" in command and command[-1] == "-":
                input_text = kwargs["input_text"]
                if not isinstance(input_text, str):
                    self.fail("kubectl apply input must be text")
                if "--dry-run=server" in command:
                    self.assertIn(manifest, input_text)
                    self.assertIn("ClusterIssuer", input_text)
                else:
                    self.assertEqual(input_text, manifest)
            return ""

        with (
            patch.object(intermediate, "decrypt_handoff", return_value=payload),
            patch.object(intermediate, "kubectl_base", return_value=["kubectl"]),
            patch.object(intermediate, "require_private_file"),
            patch.object(intermediate, "require_public_file"),
        ):
            intermediate.apply("gcp", run_command=run)

        apply_commands = [
            command
            for command in commands
            if "apply" in command and "--dry-run=server" not in command
        ]
        self.assertEqual(len(apply_commands), 2)
        for command in apply_commands:
            self.assertIn("--server-side", command)
            self.assertIn("--field-manager=make-cluster-trust", command)

        prerequisite_commands = [
            command
            for command in commands
            if command[-1:] == ["name"] and "get" in command
        ]
        self.assertEqual(len(prerequisite_commands), 3)

    def test_certificate_apply_requires_exact_approval(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            result = certificate.main(
                ["apply", "--cluster", "proxmox", "--approval", "wrong"]
            )
        self.assertEqual(result, 2)
        self.assertIn("exact cluster-trust approval", error.getvalue())

    def test_certificate_secret_readback_decodes_public_pem_only(self) -> None:
        root = "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----"
        chain = (
            "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----"
        )
        data = {
            "tls.crt": base64.b64encode(chain.encode()).decode(),
            "tls.key": base64.b64encode(
                (
                    "-----BEGIN "
                    + "PRIVATE KEY-----\nprivate\n-----END "
                    + "PRIVATE KEY-----"
                ).encode()
            ).decode(),
            "ca.crt": base64.b64encode(root.encode()).decode(),
        }
        with patch.object(certificate, "kubectl_base", return_value=["kubectl"]):
            result = certificate.read_secret(
                "gcp",
                run_command=lambda *_args, **_kwargs: json.dumps(
                    {
                        "metadata": {"name": "forgejo-tls", "namespace": "default"},
                        "type": "kubernetes.io/tls",
                        "data": data,
                    }
                ),
            )
        self.assertEqual(result, {"tls.crt": chain, "ca.crt": root})

    def test_consumer_apply_checks_prerequisites_before_mutation(self) -> None:
        commands: list[list[str]] = []

        def run(command: list[str], **_kwargs: object) -> str:
            commands.append(command)
            if "clusterissuer" in command and "get" in command:
                return json.dumps(
                    {
                        "metadata": {
                            "name": "shell-cluster-intermediate",
                            "annotations": {"shell.platform/owner": "sudo"},
                        },
                        "spec": {"ca": {"secretName": "shell-cluster-intermediate"}},
                    }
                )
            if "wait" in command:
                return "condition met"
            return ""

        with patch.object(certificate, "kubectl_base", return_value=["kubectl"]):
            certificate.apply_certificate("gcp", run_command=run)

        self.assertEqual(commands[-1][-1], str(certificate.MANIFEST))
        self.assertEqual(
            [command[1] for command in commands[:5]],
            ["get", "get", "get", "get", "wait"],
        )

    def test_certificate_chain_requires_an_intermediate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root.pem"
            root.write_text("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----", encoding="ascii")
            with (
                patch.object(certificate, "ROOT_CERTIFICATE", root),
                patch.object(certificate, "require_public_file"),
            ):
                with self.assertRaisesRegex(
                    certificate.ConsumerCertificateError, "intermediate chain"
                ):
                    certificate.verify_chain(
                        {
                            "tls.crt": "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
                            "ca.crt": root.read_text(encoding="ascii"),
                        }
                    )


if __name__ == "__main__":
    unittest.main()
