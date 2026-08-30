"""Test release-feed WATCH policy without contacting Kubernetes."""

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
    "watch_validate_release_feed", ROOT / "watch/scripts/validate_release_feed.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load WATCH release-feed validator")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
VERIFY_SPEC = importlib.util.spec_from_file_location(
    "watch_verify_release_feed", ROOT / "watch/scripts/verify_release_feed.py"
)
if VERIFY_SPEC is None or VERIFY_SPEC.loader is None:
    raise RuntimeError("cannot load WATCH release-feed verifier")
verifier = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(verifier)


class ReleaseFeedWatchTests(unittest.TestCase):
    def test_live_verifier_imports(self) -> None:
        self.assertTrue(callable(verifier.verify))

    def test_live_verifier_uses_the_declared_tls_endpoint(self) -> None:
        source = (ROOT / "watch/scripts/verify_release_feed.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("tls_server_name", source)
        self.assertIn("--resolve", source)
        self.assertNotIn("port-forward", source)

    def test_contract_and_alert_validate(self) -> None:
        contract = module.validate()
        self.assertEqual(contract["service"]["address"], "10.77.0.222")
        self.assertIn(
            "ShellReleaseFeedUnavailable", module.RULE.read_text(encoding="utf-8")
        )

    def test_source_manifest_keeps_one_replica_and_retention(self) -> None:
        source = (ROOT / "make/apps/release-feed/k8s/base/statefulset.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("replicas: 1", source)
        self.assertIn("whenDeleted: Retain", source)
        self.assertIn("storageClassName: longhorn", source)

    def test_alert_covers_down_and_absent_targets(self) -> None:
        source = module.RULE.read_text(encoding="utf-8")
        self.assertIn("up{namespace=\"release-feed\",service=\"release-feed\"} == 0", source)
        self.assertIn("absent(up{namespace=\"release-feed\",service=\"release-feed\"})", source)
        self.assertIn("ShellReleaseFeedCapacityLow", source)
        self.assertIn(
            'release_feed_capacity_remaining{namespace="release-feed",service="release-feed"} < 100',
            source,
        )
        self.assertIn("or absent(release_feed_capacity_remaining", source)

    def test_contract_rejects_extra_fields(self) -> None:
        document = json.loads(module.CONTRACT.read_text(encoding="utf-8"))
        document["unexpected"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(module.ReleaseFeedWatchError, "shape changed"):
                module.validate(path)


if __name__ == "__main__":
    unittest.main()
