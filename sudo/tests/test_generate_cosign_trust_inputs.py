"""Test Cosign trust generation without real keys or external state."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = ROOT / "sudo/scripts"
sys.path.insert(0, str(SCRIPT_ROOT))
SPEC = importlib.util.spec_from_file_location(
    "generate_cosign_trust_inputs", SCRIPT_ROOT / "generate_cosign_trust_inputs.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Cosign trust generator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CosignTrustGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        for relative in (
            ".local",
            ".local/sudo",
            ".local/sudo/kubernetes",
            ".local/sudo/kubernetes/cosign",
            ".local/tar",
            ".local/tar/kubernetes",
            ".local/tar/kubernetes/tools",
        ):
            path = self.root / relative
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        self.age_key = self.root / ".local/sudo/kubernetes/cosign/age-key.txt"
        self.age_key.write_text("AGE-SECRET-KEY-test\n", encoding="utf-8")
        self.age_key.chmod(0o600)
        self.cosign = self.root / ".local/tar/kubernetes/tools/cosign"
        self.cosign.write_bytes(b"fake-cosign")
        self.cosign.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, command: list[str], **kwargs: object) -> str:
        if command[0] == str(self.cosign):
            directory = Path(str(kwargs["cwd"]))
            (directory / "cosign.key").write_text(
                "-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----\nprivate\n-----END ENCRYPTED SIGSTORE PRIVATE KEY-----\n",
                encoding="ascii",
            )
            (directory / "cosign.pub").write_text(
                "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n",
                encoding="ascii",
            )
            return ""
        if command[0] == "age-keygen":
            return "age1testrecipient\n"
        return json.dumps({"sops": {"age": []}})

    def test_generation_publishes_two_private_handoffs(self) -> None:
        checksum = hashlib.sha256(self.cosign.read_bytes()).hexdigest()
        lock = {"tools": {"cosign": {"size": self.cosign.stat().st_size, "source_sha256": checksum}}}
        with (
            mock.patch.object(module, "COSIGN_BINARY", self.cosign),
            mock.patch.object(module.supply, "validate_public", return_value=lock),
            mock.patch.object(module.contracts, "validate_contracts", return_value={}),
        ):
            private, public = module.generate(
                approval=module.APPROVAL,
                repository_root=self.root,
                age_key=self.age_key,
                cosign=self.cosign,
                run_command=self.run_command,
            )
        self.assertEqual(private.name, "cosign.sops.json")
        self.assertEqual(public.name, "cosign-public.sops.json")
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(public.stat().st_mode & 0o777, 0o600)
        self.assertIn('"sops"', private.read_text(encoding="utf-8"))
        self.assertIn('"sops"', public.read_text(encoding="utf-8"))

    def test_wrong_approval_is_rejected(self) -> None:
        with self.assertRaisesRegex(module.CosignInputError, "approval must be"):
            module.generate(approval="wrong")


if __name__ == "__main__":
    unittest.main()
