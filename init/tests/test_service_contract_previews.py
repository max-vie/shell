"""Test INIT's fail-closed identity and delivery contract previews."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


PLAYBOOK_DIRECTORY = Path(__file__).parents[1] / "ansible" / "playbooks"
PREVIEWS = {
    "delivery": PLAYBOOK_DIRECTORY / "configure-delivery-node.yml",
    "identity": PLAYBOOK_DIRECTORY / "configure-identity-service.yml",
}


class TestServiceContractPreviews(unittest.TestCase):
    # Source checks keep this test standard-library-only and avoid executing
    # either preview while its required contracts remain undefined.
    def test_preview_playbooks_gate_target_tasks(self) -> None:
        for boundary, playbook in PREVIEWS.items():
            with self.subTest(boundary=boundary):
                source = playbook.read_text(encoding="utf-8")
                pre_tasks = source.index("\n  pre_tasks:")
                refusal = source.index(f"\n    - name: Refuse {boundary} mutation")
                tasks = source.index("\n  tasks:")
                self.assertNotIn("\n  hosts: localhost", source)
                self.assertLess(pre_tasks, refusal)
                self.assertLess(refusal, tasks)
                gate = source[pre_tasks:tasks]
                self.assertIn("when: not ansible_check_mode", source[refusal:tasks])
                self.assertIn("ansible.builtin.fail:", source[refusal:tasks])
                self.assertEqual(gate.count("delegate_to: localhost"), 3)
                self.assertEqual(gate.count("run_once: true"), 3)
                self.assertEqual(gate.count("become: false"), 3)
                self.assertEqual(gate.count("tags: [always]"), 5)
                for required in (
                    "shell_role | default('')",
                    "shell_cluster | default('') == 'shared'",
                    "shell_transport | default('') == 'gcp_iap'",
                    "(ansible_user | default('')) != 'root'",
                ):
                    self.assertIn(required, gate)
                self.assertEqual(
                    re.findall(
                        r"^      (ansible[.]builtin[.][a-z_]+):",
                        source[pre_tasks:refusal],
                        flags=re.MULTILINE,
                    ),
                    [
                        "ansible.builtin.command",
                        "ansible.builtin.include_vars",
                        "ansible.builtin.assert",
                        "ansible.builtin.assert",
                    ],
                )
                self.assertEqual(
                    re.findall(
                        r"^      (ansible[.]builtin[.][a-z_]+):",
                        source[tasks:],
                        flags=re.MULTILINE,
                    ),
                    ["ansible.builtin.debug", "ansible.builtin.meta"],
                )


if __name__ == "__main__":
    unittest.main()
