"""Test WATCH platform add-on policy without a cluster."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "watch/scripts"))
SPEC = importlib.util.spec_from_file_location(
    "validate_platform_addons", ROOT / "watch/scripts/validate_platform_addons.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load platform add-on validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_platform_addons", ROOT / "watch/scripts/verify_platform_addons.py"
)
if VERIFY_SPEC is None or VERIFY_SPEC.loader is None:
    raise RuntimeError("cannot load platform add-on verifier")
verifier = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(verifier)


class PlatformAddonsWatchTests(unittest.TestCase):
    def test_contract_validates(self) -> None:
        document = module.validate()
        self.assertEqual(
            document["cluster"]["nodes"],
            ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
        )
        self.assertEqual(
            document["add_ons"]["longhorn"]["data_path"], "/var/lib/longhorn"
        )

    def test_contract_rejects_extra_fields(self) -> None:
        source = json.loads(module.CONTRACT.read_text(encoding="utf-8"))
        source["unexpected"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(module.PlatformAddonsWatchError, "shape changed"):
                module.validate(path)

    def test_verifier_is_read_only(self) -> None:
        source = (ROOT / "watch/scripts/verify_platform_addons.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("kubectl apply", source)
        self.assertNotIn("kubectl delete", source)
        self.assertTrue(callable(verifier.verify))


if __name__ == "__main__":
    unittest.main()
