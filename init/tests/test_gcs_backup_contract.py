"""Test the source-only Velero GCS OpenTofu root."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GCS_ROOT = ROOT / "init/opentofu/gcs-backup"


class GCSBackupContractTests(unittest.TestCase):
    def test_root_has_the_separate_state_and_required_files(self) -> None:
        for name in ("versions.tf", "variables.tf", "main.tf", "outputs.tf", "terraform.tfvars.example"):
            self.assertTrue((GCS_ROOT / name).is_file(), name)
        versions = (GCS_ROOT / "versions.tf").read_text(encoding="utf-8")
        self.assertIn("gcs-backup/terraform.tfstate", versions)
        self.assertIn('version = "~> 7.41"', versions)

    def test_bucket_is_private_versioned_and_non_destructive(self) -> None:
        source = (GCS_ROOT / "main.tf").read_text(encoding="utf-8")
        self.assertIn("uniform_bucket_level_access = true", source)
        self.assertIn('public_access_prevention    = "enforced"', source)
        self.assertIn("force_destroy               = false", source)
        self.assertIn("enabled = var.enable_versioning", source)
        self.assertIn('role   = "roles/storage.objectAdmin"', source)
        self.assertIn('resource "google_service_account_key" "velero"', source)

    def test_sensitive_credential_output_is_marked_sensitive(self) -> None:
        source = (GCS_ROOT / "outputs.tf").read_text(encoding="utf-8")
        self.assertIn('output "credentials_json"', source)
        self.assertIn("sensitive   = true", source)
        self.assertNotIn("private_key =", source)


if __name__ == "__main__":
    unittest.main()
