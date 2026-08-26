"""Test the source-only boundaries of the Forgejo delivery playbooks."""

from __future__ import annotations

import unittest
from pathlib import Path


MAKE_ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = MAKE_ROOT / "Makefile"
PLAYBOOKS = {
    "deploy": MAKE_ROOT / "forgejo/deploy-forgejo.yml",
    "verify": MAKE_ROOT / "forgejo/verify-forgejo.yml",
}


class TestForgejoPlaybooks(unittest.TestCase):
    def test_playbooks_are_fixed_to_delivery_services(self) -> None:
        for name, path in PLAYBOOKS.items():
            with self.subTest(playbook=name):
                source = path.read_text(encoding="utf-8")
                self.assertIn("hosts: delivery_nodes", source)
                self.assertIn("delivery-01", source)
                self.assertIn("forgejo.service", source)
                self.assertIn("caddy.service", source)
                self.assertNotIn("forgejo_runner", source)
                self.assertNotIn("runner", source.lower())
                self.assertNotIn("docker.sock", source)
                self.assertNotIn(":latest", source)
                self.assertNotIn("kubectl", source)
                self.assertNotIn("openbao", source.lower())
                self.assertNotIn("--limit", source)
                self.assertNotIn("$(id -u", source)

    def test_deploy_uses_digest_pinned_rootless_quadlets_and_rescue(self) -> None:
        source = PLAYBOOKS["deploy"].read_text(encoding="utf-8")
        self.assertIn("UserNS=keep-id", source)
        self.assertIn("Image={{ make_forgejo_image }}", source)
        self.assertIn("Image={{ make_caddy_image }}", source)
        self.assertIn("make_forgejo_repository }}:{{ make_forgejo_tag }}@", source)
        self.assertIn("make_caddy_repository }}:{{ make_caddy_tag }}@", source)
        self.assertIn("mode: \"0600\"", source)
        self.assertIn("--cacert", source)
        self.assertIn("rescue:", source)
        self.assertIn("state: absent", source)
        self.assertIn("when: ansible_check_mode", source)
        self.assertIn("--env-file", source)
        self.assertIn("FORGEJO_ADMIN_PASSWORD_B64", source)
        self.assertNotIn('- "{{ make_forgejo_admin_password }}"', source)
        self.assertIn(
            '- "{{ make_forgejo_admin_environment_file }}"',
            source,
        )

    def test_verify_checks_public_ca_https_and_private_files(self) -> None:
        source = PLAYBOOKS["verify"].read_text(encoding="utf-8")
        self.assertIn("openssl", source)
        self.assertIn("-verify_hostname", source)
        self.assertIn("mode == '0644'", source)
        self.assertIn("mode == '0600'", source)
        self.assertIn("not make_root_ca_state.stat.islnk", source)
        self.assertIn("not make_secret_file.stat.islnk", source)
        self.assertIn(
            "XDG_RUNTIME_DIR=/run/user/{{ make_service_uid.stdout | trim }}",
            source,
        )
        self.assertIn("make_quadlet_files", source)
        self.assertIn("make_quadlet_contents", source)
        self.assertIn("item.item.expected_image", source)
        self.assertIn("make_delivery_supply.images.forgejo.digest", source)
        self.assertIn("make_delivery_supply.images.caddy.digest", source)

    def test_make_checks_playbooks_and_keeps_verify_read_only(self) -> None:
        source = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("check: test trust-preview forgejo-check", source)
        self.assertIn("forgejo-verify: delivery-handoff-validate", source)
        self.assertNotIn("forgejo-verify: delivery-handoff\n", source)


if __name__ == "__main__":
    unittest.main()
