"""Test Velero GCS credential handling without private files or cluster access."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "make/scripts/apply_velero_credentials.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("apply_velero_credentials", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Velero credential controller")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def credential() -> dict[str, str]:
    return {
        "type": "service_account",
        "project_id": "shell-project",
        "private_key_id": "key-id",
        "private_key": "fake-private-key",
        "client_email": "velero-backup@shell-project.iam.gserviceaccount.com",
        "client_id": "123456789",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/velero",
    }


class VeleroCredentialTests(unittest.TestCase):
    def test_secret_manifest_contains_the_private_json_only_in_memory(self) -> None:
        document = yaml.safe_load(module.secret_manifest(credential()))
        self.assertEqual(document["metadata"]["namespace"], "velero")
        self.assertEqual(document["metadata"]["name"], "velero-object-store")
        self.assertEqual(json.loads(document["stringData"]["cloud"]), credential())

    def test_invalid_shape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            path.write_text(json.dumps({"type": "service_account"}), encoding="utf-8")
            with mock.patch.object(module.sops_helpers, "private_file", return_value=path):
                with self.assertRaisesRegex(module.VeleroCredentialError, "keys changed"):
                    module.credentials(path)

    def test_apply_approval_is_checked_before_private_read(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(module.validate_velero, "validate"),
            mock.patch.object(module, "credentials") as read,
            redirect_stderr(stderr),
        ):
            result = module.main(["apply", "--approval", "wrong"])
        self.assertEqual(result, 2)
        read.assert_not_called()
        self.assertIn("approval must be", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
