"""Test the GCP and Proxmox node source contracts."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
NETWORK_ROOT = SOURCE_ROOT / "init/opentofu/gcp/network"
SHARED_NODES_ROOT = SOURCE_ROOT / "init/opentofu/gcp/shared-nodes"
GCP_K3S_ROOT = SOURCE_ROOT / "init/opentofu/gcp/k3s"
PROXMOX_K3S_ROOT = SOURCE_ROOT / "init/opentofu/proxmox/k3s"


def resource_block(source: str, name: str, next_marker: str | None) -> str:
    start = source.index(f'resource "google_compute_firewall" "{name}"')
    end = source.index(next_marker, start) if next_marker else len(source)
    return source[start:end]


def port_lists(source: str) -> list[list[int]]:
    return [
        [int(port) for port in re.findall(r'"([0-9]+)"', values)]
        for values in re.findall(r"ports\s*=\s*\[([^]]+)\]", source)
    ]


class TestSharedNodeContract(unittest.TestCase):
    def test_shared_nodes_select_separate_operating_systems(self) -> None:
        variables = (SHARED_NODES_ROOT / "variables.tf").read_text(encoding="utf-8")
        example = (SHARED_NODES_ROOT / "terraform.tfvars.example").read_text(
            encoding="utf-8"
        )
        outputs = (SHARED_NODES_ROOT / "outputs.tf").read_text(encoding="utf-8")

        self.assertIn("operating_system  = string", variables)
        self.assertIn('== "almalinux-9"', variables)
        self.assertIn('== "debian-13"', variables)
        self.assertIn("projects/almalinux-cloud/global/images/almalinux-9", variables)
        self.assertIn("projects/debian-cloud/global/images/debian-13", variables)
        self.assertIn('operating_system  = "almalinux-9"', example)
        self.assertIn('operating_system  = "debian-13"', example)
        self.assertIn("operating_system = var.shared_nodes[name]", outputs)

    def test_k3s_roots_export_operating_system_and_image_identity(self) -> None:
        gcp_variables = (GCP_K3S_ROOT / "variables.tf").read_text(encoding="utf-8")
        gcp_example = (GCP_K3S_ROOT / "terraform.tfvars.example").read_text(
            encoding="utf-8"
        )
        gcp_outputs = (GCP_K3S_ROOT / "outputs.tf").read_text(encoding="utf-8")
        proxmox_outputs = (PROXMOX_K3S_ROOT / "outputs.tf").read_text(
            encoding="utf-8"
        )

        self.assertIn("operating_system  = string", gcp_variables)
        self.assertIn("projects/debian-cloud/global/images/debian-13", gcp_variables)
        self.assertEqual(gcp_example.count('operating_system  = "debian-13"'), 3)
        self.assertIn("operating_system = var.k3s_nodes[name]", gcp_outputs)
        self.assertIn("source_image     = var.k3s_nodes[name]", gcp_outputs)
        self.assertIn('operating_system = "debian-13"', proxmox_outputs)
        self.assertIn("image_file_name  = var.debian_image.file_name", proxmox_outputs)
        self.assertIn("image_sha256     = var.debian_image.sha256", proxmox_outputs)

    def test_role_firewalls_match_public_service_contracts(self) -> None:
        source = (NETWORK_ROOT / "main.tf").read_text(encoding="utf-8")
        identity_profile = json.loads(
            (SOURCE_ROOT / "sudo/access/freeipa-host-profile.json").read_text(
                encoding="utf-8"
            )
        )
        delivery_profile = json.loads(
            (SOURCE_ROOT / "sudo/access/delivery-host-profile.json").read_text(
                encoding="utf-8"
            )
        )

        shared = resource_block(
            source,
            "shared_internal",
            'resource "google_compute_firewall" "identity_internal"',
        )
        identity = resource_block(
            source,
            "identity_internal",
            'resource "google_compute_firewall" "delivery_internal"',
        )
        delivery = resource_block(source, "delivery_internal", None)

        self.assertIn('target_tags   = ["shell-identity"]', identity)
        self.assertEqual(
            port_lists(identity),
            [
                identity_profile["network"]["tcp_ports"],
                identity_profile["network"]["udp_ports"],
            ],
        )
        self.assertIn('target_tags   = ["shell-delivery"]', delivery)
        self.assertEqual(port_lists(delivery), [[delivery_profile["service"]["port"]]])
        self.assertIn(
            "google_compute_firewall.identity_internal",
            shared,
        )
        self.assertIn(
            "google_compute_firewall.delivery_internal",
            shared,
        )

    def test_network_and_shared_nodes_have_separate_ownership(self) -> None:
        network = (NETWORK_ROOT / "main.tf").read_text(encoding="utf-8")
        shared_nodes = (SHARED_NODES_ROOT / "main.tf").read_text(encoding="utf-8")

        self.assertNotIn('resource "google_project_service"', network)
        self.assertNotIn('resource "google_project_service"', shared_nodes)
        self.assertIn(
            'path = "../../../../.local/opentofu/gcp/network/terraform.tfstate"',
            shared_nodes,
        )
        self.assertIn(
            'path = "../../../../.local/opentofu/gcp/network/terraform.tfstate"',
            (GCP_K3S_ROOT / "main.tf").read_text(encoding="utf-8"),
        )
        self.assertIn(
            'path = "../../../../.local/opentofu/gcp/network/terraform.tfstate"',
            (SOURCE_ROOT / "init/opentofu/gcp/proxmox-host/main.tf").read_text(
                encoding="utf-8"
            ),
        )

    def test_network_outputs_and_inventory_output_keep_their_names(self) -> None:
        network_outputs = (NETWORK_ROOT / "outputs.tf").read_text(encoding="utf-8")
        shared_outputs = (SHARED_NODES_ROOT / "outputs.tf").read_text(encoding="utf-8")

        for name in (
            "network_name",
            "network_self_link",
            "subnetwork_name",
            "subnetwork_self_link",
            "subnet_cidr",
            "proxy_only_subnetwork_self_link",
            "proxy_only_subnet_cidr",
            "region",
            "project_id",
        ):
            self.assertIn(f'output "{name}"', network_outputs)
        self.assertIn('output "shared_nodes"', shared_outputs)
        self.assertNotIn('output "shared_nodes"', network_outputs)


if __name__ == "__main__":
    unittest.main()
