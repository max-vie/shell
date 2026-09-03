"""Test Cosign public trust Secret handling without a cluster."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "make/scripts/apply_cosign_trust.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("apply_cosign_trust", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Cosign trust controller")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


PUBLIC = "-----BEGIN PUBLIC KEY-----\npublic\n-----END PUBLIC KEY-----\n"


class CosignTrustTests(unittest.TestCase):
    def test_manifest_contains_only_public_key_data(self) -> None:
        document = json.loads(module.secret_manifest(PUBLIC))
        self.assertEqual(document["metadata"]["namespace"], "shell-trust")
        self.assertEqual(document["metadata"]["name"], "cosign-public-keys")
        self.assertEqual(document["stringData"], {"cosign.pub": PUBLIC})

    def test_existing_mismatched_key_is_refused(self) -> None:
        encoded = base64.b64encode(b"different").decode()
        existing = json.dumps(
            {
                "metadata": {"name": "cosign-public-keys", "namespace": "shell-trust"},
                "type": "Opaque",
                "data": {"cosign.pub": encoded},
            }
        )
        with self.assertRaisesRegex(module.CosignTrustError, "differs"):
            module.decode_existing(existing, PUBLIC)

    def test_apply_approval_is_checked_before_decryption(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(module.validate_cosign_admission, "validate"),
            mock.patch.object(module, "public_key") as decrypt,
            redirect_stderr(stderr),
        ):
            result = module.main(["apply", "--approval", "wrong"])
        self.assertEqual(result, 2)
        decrypt.assert_not_called()
        self.assertIn("approval must be", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
