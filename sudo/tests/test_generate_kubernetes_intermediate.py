"""Test the per-cluster SUDO Kubernetes intermediate boundary."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SOURCE_ROOT / "sudo/scripts/generate_kubernetes_intermediate.py"
SPEC = importlib.util.spec_from_file_location("generate_kubernetes_intermediate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load Kubernetes intermediate generator: {SCRIPT}")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class TestGenerateKubernetesIntermediate(unittest.TestCase):
    def test_handoff_payload_binds_cluster_and_contains_no_root_key(self) -> None:
        payload = json.loads(
            generator.handoff_payload(
                cluster="gcp",
                certificate="-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
                private_key="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
                root_ca="-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----",
            )
        )
        self.assertEqual(payload["cluster"], "gcp")
        self.assertEqual(payload["issuer"], "shell-cluster-intermediate")
        self.assertNotIn("root_key", payload)
        self.assertEqual(
            set(payload["cluster_intermediate"]),
            {"certificate", "private_key", "root_ca"},
        )

    def test_clusters_have_distinct_handoff_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gcp = generator.cluster_paths(root, "gcp")
            proxmox = generator.cluster_paths(root, "proxmox")
            self.assertNotEqual(gcp["handoff"], proxmox["handoff"])
            self.assertNotEqual(
                gcp["intermediate_certificate"], proxmox["intermediate_certificate"]
            )

    def test_unknown_cluster_is_rejected(self) -> None:
        with self.assertRaisesRegex(generator.GenerationError, "gcp, proxmox"):
            generator.cluster_paths(SOURCE_ROOT, "other")

    def test_private_directory_creation_closes_all_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            target = root / ".local/sudo/kubernetes/gcp"
            generator.ensure_private_directory(
                target, "cluster private root", repository_root=root
            )
            for relative in (
                ".local",
                ".local/sudo",
                ".local/sudo/kubernetes",
                ".local/sudo/kubernetes/gcp",
            ):
                self.assertEqual(
                    stat.S_IMODE((root / relative).stat().st_mode),
                    generator.PRIVATE_DIRECTORY_MODE,
                )

    def test_private_directory_rejects_symlinked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / ".local").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(generator.GenerationError, "symlink"):
                generator.ensure_private_directory(
                    root / ".local/sudo/kubernetes",
                    "Kubernetes private root",
                    repository_root=root,
                )


if __name__ == "__main__":
    unittest.main()
