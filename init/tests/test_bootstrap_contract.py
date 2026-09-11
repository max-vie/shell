"""Test the source-only GCP bootstrap OpenTofu root."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_ROOT = ROOT / "init/opentofu/gcp/bootstrap"
PROFILE = ROOT / "sudo/access/operator-access-profile.json"


class BootstrapContractTests(unittest.TestCase):
    def test_root_has_the_separate_state_and_required_files(self) -> None:
        for name in (
            "versions.tf",
            "variables.tf",
            "main.tf",
            "outputs.tf",
            "terraform.tfvars.example",
            ".terraform.lock.hcl",
        ):
            self.assertTrue((BOOTSTRAP_ROOT / name).is_file(), name)
        versions = (BOOTSTRAP_ROOT / "versions.tf").read_text(encoding="utf-8")
        self.assertIn("bootstrap/terraform.tfstate", versions)
        self.assertIn('version = "~> 7.41"', versions)

    def test_project_is_created_without_an_organization(self) -> None:
        source = (BOOTSTRAP_ROOT / "main.tf").read_text(encoding="utf-8")
        self.assertIn('resource "google_project" "bootstrap"', source)
        self.assertNotIn("org_id", source)
        self.assertNotIn("folder_id", source)
        self.assertIn("prevent_destroy = true", source)

    def test_billing_budget_and_apis_are_declared(self) -> None:
        source = (BOOTSTRAP_ROOT / "main.tf").read_text(encoding="utf-8")
        self.assertIn('resource "google_billing_project_info" "bootstrap"', source)
        self.assertIn('resource "google_billing_budget" "bootstrap"', source)
        self.assertIn('resource "google_project_service" "required"', source)
        self.assertIn("disable_on_destroy = false", source)
        self.assertIn("threshold_percent = threshold_rules.value", source)

    def test_custom_role_permissions_come_from_the_sudo_profile(self) -> None:
        source = (BOOTSTRAP_ROOT / "main.tf").read_text(encoding="utf-8")
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        permissions = [
            permission
            for role_class in profile["access_boundary"]["deployment_service_account"][
                "role_classes"
            ]
            for permission in role_class["permissions"]
        ]
        self.assertIn("operator-access-profile.json", source)
        self.assertIn("role_class.permissions", source)
        self.assertIn("compute.networks.updatePolicy", permissions)
        self.assertIn("iap.tunnelInstances.accessViaIAP", permissions)

    def test_impersonation_binding_is_service_account_scoped(self) -> None:
        source = (BOOTSTRAP_ROOT / "main.tf").read_text(encoding="utf-8")
        self.assertIn('resource "google_service_account_iam_member" "operator"', source)
        self.assertIn("roles/iam.serviceAccountTokenCreator", source)
        self.assertIn("user:${var.operator_email}", source)

    def test_example_uses_placeholders_only(self) -> None:
        example = (BOOTSTRAP_ROOT / "terraform.tfvars.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("replace-with-gcp-project-id", example)
        self.assertIn("replace-with-billing-account-id", example)
        self.assertIn("replace-with-operator-email", example)
        self.assertNotIn("shell-live-20260908-89e0", example)


if __name__ == "__main__":
    unittest.main()
