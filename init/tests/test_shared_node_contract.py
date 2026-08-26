"""Test the shared GCP identity and delivery source contract."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SHARED_ROOT = SOURCE_ROOT / "init/opentofu/gcp/shared"


def resource_block(source: str, name: str, next_marker: str) -> str:
    start = source.index(f'resource "google_compute_firewall" "{name}"')
    end = source.index(next_marker, start)
    return source[start:end]


def port_lists(source: str) -> list[list[int]]:
    return [
        [int(port) for port in re.findall(r'"([0-9]+)"', values)]
        for values in re.findall(r"ports\s*=\s*\[([^]]+)\]", source)
    ]


class TestSharedNodeContract(unittest.TestCase):
    def test_shared_nodes_select_separate_operating_systems(self) -> None:
        variables = (SHARED_ROOT / "variables.tf").read_text(encoding="utf-8")
        example = (SHARED_ROOT / "terraform.tfvars.example").read_text(
            encoding="utf-8"
        )
        outputs = (SHARED_ROOT / "outputs.tf").read_text(encoding="utf-8")

        self.assertIn("operating_system  = string", variables)
        self.assertIn('== "almalinux-9"', variables)
        self.assertIn('== "debian-13"', variables)
        self.assertIn("projects/almalinux-cloud/global/images/almalinux-9", variables)
        self.assertIn("projects/debian-cloud/global/images/debian-13", variables)
        self.assertIn('operating_system  = "almalinux-9"', example)
        self.assertIn('operating_system  = "debian-13"', example)
        self.assertIn("operating_system = var.shared_nodes[name]", outputs)

    def test_role_firewalls_match_public_service_contracts(self) -> None:
        source = (SHARED_ROOT / "main.tf").read_text(encoding="utf-8")
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
        delivery = resource_block(source, "delivery_internal", 'module "shared_nodes"')

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


if __name__ == "__main__":
    unittest.main()
