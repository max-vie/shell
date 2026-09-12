"""Test explicit deployment identity in operational Google roots."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OPERATIONAL_ROOTS = (
    ROOT / "init/opentofu/gcp/network",
    ROOT / "init/opentofu/gcp/shared-nodes",
    ROOT / "init/opentofu/gcp/k3s",
    ROOT / "init/opentofu/gcp/proxmox-host",
    ROOT / "init/opentofu/gcs-backup",
)
EXPECTED_PROVIDER_SETTING = (
    'impersonate_service_account = '
    '"shell-local-deployer@${var.project_id}.iam.gserviceaccount.com"'
)


class GoogleIdentityContractTests(unittest.TestCase):
    def test_operational_google_roots_pin_the_deployment_account(self) -> None:
        for root in OPERATIONAL_ROOTS:
            source = (root / "versions.tf").read_text(encoding="utf-8")
            self.assertIn(EXPECTED_PROVIDER_SETTING, source, root)

    def test_bootstrap_root_remains_the_human_creation_boundary(self) -> None:
        source = (
            ROOT / "init/opentofu/gcp/bootstrap/versions.tf"
        ).read_text(encoding="utf-8")
        self.assertNotIn("impersonate_service_account =", source)


if __name__ == "__main__":
    unittest.main()
