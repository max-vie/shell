"""Test FreeIPA input generation without private values or SOPS."""

from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_ROOT = ROOT / "sudo/scripts"
sys.path.insert(0, str(SCRIPT_ROOT))
SPEC = importlib.util.spec_from_file_location(
    "generate_freeipa_inputs", SCRIPT_ROOT / "generate_freeipa_inputs.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load FreeIPA input generator")
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class TestGenerateFreeIPAInputs(unittest.TestCase):
    def private_root(self, temporary: str) -> tuple[Path, Path, Path]:
        root = Path(temporary)
        root.chmod(0o700)
        identity = root / ".local/sudo/identity"
        identity.mkdir(parents=True, mode=0o700)
        for parent in (root / ".local", root / ".local/sudo", identity):
            parent.chmod(0o700)
        age_key = identity / "age-key.txt"
        age_key.write_text("AGE-SECRET-KEY-test\n", encoding="utf-8")
        age_key.chmod(0o600)
        return root, age_key, identity / "freeipa.sops.json"

    @staticmethod
    def profile() -> dict[str, object]:
        return json.loads(
            (ROOT / "sudo/access/freeipa-host-profile.json").read_text(encoding="utf-8")
        )

    @staticmethod
    def fake_run(command: list[str], **_: object) -> str:
        if command[0] == "age-keygen":
            return "age1testrecipient\n"
        return json.dumps({"data": "encrypted", "sops": {"version": 3}})

    def test_check_only_requires_no_private_key(self) -> None:
        with mock.patch.object(
            generator.contracts,
            "validate_contracts",
            return_value={"freeipa": self.profile()},
        ):
            self.assertEqual(
                0,
                generator.main(["--check-only", "--approval", "source-only"]),
            )

    def test_generation_publishes_a_private_encrypted_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, age_key, output = self.private_root(temporary)
            with mock.patch.object(
                generator.contracts,
                "validate_contracts",
                return_value={"freeipa": self.profile()},
            ):
                result = generator.generate(
                    approval=generator.APPROVAL,
                    repository_root=root,
                    age_key=age_key,
                    output=output,
                    run_command=self.fake_run,
                )
            self.assertEqual(result, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertNotIn("AGE-SECRET-KEY", output.read_text(encoding="utf-8"))
            self.assertIn('"sops"', output.read_text(encoding="utf-8"))

    def test_generation_is_create_only_until_rotation_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root, age_key, output = self.private_root(temporary)
            validate = mock.patch.object(
                generator.contracts,
                "validate_contracts",
                return_value={"freeipa": self.profile()},
            )
            with validate:
                generator.generate(
                    approval=generator.APPROVAL,
                    repository_root=root,
                    age_key=age_key,
                    output=output,
                    run_command=self.fake_run,
                )
                with self.assertRaisesRegex(
                    generator.FreeIPAInputError, "pass --rotate"
                ):
                    generator.generate(
                        approval=generator.APPROVAL,
                        repository_root=root,
                        age_key=age_key,
                        output=output,
                        run_command=self.fake_run,
                    )
                generator.generate(
                    approval=generator.APPROVAL,
                    repository_root=root,
                    age_key=age_key,
                    output=output,
                    rotate=True,
                    run_command=self.fake_run,
                )

    def test_wrong_approval_is_rejected(self) -> None:
        with self.assertRaisesRegex(generator.FreeIPAInputError, "approval must be"):
            generator.generate(approval="wrong")


if __name__ == "__main__":
    unittest.main()
