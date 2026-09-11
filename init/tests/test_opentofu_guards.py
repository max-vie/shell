"""Test the source-level guards around the GCP foundation roots."""

from __future__ import annotations

import os
import json
import shlex
import shutil
import subprocess  # nosec B404
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INIT_ROOT = ROOT / "init"
MAKE = "make"


class OpenTofuGuardTests(unittest.TestCase):
    def cleanup_private_plan_base(self, private_base: Path) -> None:
        shutil.rmtree(private_base, ignore_errors=True)
        for parent in (
            private_base.parent,
            private_base.parent.parent,
            private_base.parent.parent.parent,
        ):
            try:
                parent.rmdir()
            except OSError:
                pass

    def private_plan_base(self, base: Path) -> Path:
        private_base = (
            ROOT / ".local/opentofu/gcp/test-guards" / base.parent.name.replace(" ", "-")
        )
        for directory in (
            ROOT / ".local",
            ROOT / ".local/opentofu",
            ROOT / ".local/opentofu/gcp",
            private_base.parent,
            private_base,
        ):
            directory.mkdir(mode=0o700, exist_ok=True)
            directory.chmod(0o700)
        self.addCleanup(self.cleanup_private_plan_base, private_base)
        return private_base

    def fake_tofu(self, directory: Path) -> tuple[Path, Path]:
        log = directory / "tofu.log"
        log_literal = shlex.quote(str(log))
        executable = directory / "tofu"
        executable.write_text(
            f"""#!/bin/sh
set -eu
mode=''
plan=''
for argument in "$@"; do
  case "$argument" in
    plan|apply|output) mode="$argument" ;;
    -out=*) plan="${{argument#-out}}" ;;
  esac
done
if [ -n "$mode" ]; then
  printf '%s\\n' "$mode" >> {log_literal}
fi
if [ "$mode" = plan ] && [ -n "$plan" ]; then
  plan="${{plan#=}}"
  printf '%s\\n' source-only-plan > "$plan"
fi
if [ "$mode" = output ]; then
  printf '%s\\n' '{{}}'
fi
""",
            encoding="utf-8",
        )
        executable.chmod(0o700)
        return executable, log

    def common_arguments(
        self,
        base: Path,
        fake: Path,
        *,
        root: str = "network",
        project: str = "shell-platform",
        commit: str | None = None,
        approval: str | None = None,
        digest: str = "",
        plan: Path | None = None,
        dirty: bool = False,
    ) -> list[str]:
        current_head = subprocess.check_output(  # nosec B603
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        if commit is None:
            commit = current_head
        if approval is None:
            approval = f"environment-gcp/init/tofu/{root}"
        base.mkdir(parents=True, exist_ok=True)
        private_base = self.private_plan_base(base)
        git = base / "git"
        status_result = "printf '%s\\n' ' M init/dirty.tf'" if dirty else "exit 0"
        git.write_text(
            "#!/bin/sh\n"
            "case \"$*\" in\n"
            f"  *'status --porcelain=v1 --untracked-files=all'*) {status_result} ;;\n"
            f"  *'rev-parse --verify HEAD'*) printf '%s\\n' '{current_head}' ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        git.chmod(0o700)
        values = {
            "GIT": str(git),
            "TOFU": str(fake),
            "TOFU_PLAN_BASE": str(private_base),
            "TOFU_PROJECT": project,
            "TOFU_ROOT": root,
            "TOFU_COMMIT": commit,
            "TOFU_APPROVAL": approval,
            "TOFU_VARS": str(private_base / "test.tfvars"),
            "TOFU_PLAN": str(private_base / root / f"{project}-{commit}.tfplan"),
            "TOFU_STATE_GATE": str(private_base / "state-gate"),
            "TOFU_API_GATE": str(private_base / "api-gate"),
        }
        variables = private_base / "test.tfvars"
        variables.write_text("region = \"europe-west4\"\n", encoding="utf-8")
        variables.chmod(0o600)
        state_gate = private_base / "state-gate"
        api_gate = private_base / "api-gate"
        state_gate.write_text("fresh\n", encoding="utf-8")
        api_gate.write_text(
            "bootstrap=approved\n" if root == "bootstrap" else "compute.googleapis.com=enabled\n",
            encoding="utf-8",
        )
        state_gate.chmod(0o600)
        api_gate.chmod(0o600)
        if digest:
            values["TOFU_PLAN_DIGEST"] = digest
            plan_path = Path(values["TOFU_PLAN"])
            approval_record = plan_path.with_name(f"{plan_path.name}.approval.json")
            action_summary = plan_path.with_name(f"{plan_path.name}.summary.txt")
            approval_record.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "status": "approved",
                        "project_id": project,
                        "root": root,
                        "commit": commit,
                        "approval": approval,
                        "plan_sha256": digest,
                        "approved_at": "2026-09-09T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            action_summary.write_text("network resources reviewed\n", encoding="utf-8")
            approval_record.chmod(0o600)
            action_summary.chmod(0o600)
            values["TOFU_APPROVAL_RECORD"] = str(approval_record)
            values["TOFU_ACTION_SUMMARY"] = str(action_summary)
        if plan is not None:
            values["TOFU_PLAN"] = str(plan)
        return [f"{key}={value}" for key, value in values.items()]

    def run_target(
        self,
        target: str,
        base: Path,
        fake: Path,
        root: str = "network",
        project: str = "shell-platform",
        commit: str | None = None,
        approval: str | None = None,
        digest: str = "",
        plan: Path | None = None,
        dirty: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("TF_VAR_project_id", None)
        arguments = [MAKE, "-C", str(INIT_ROOT), target]
        arguments.extend(
            self.common_arguments(
                base,
                fake,
                root=root,
                project=project,
                commit=commit,
                approval=approval,
                digest=digest,
                plan=plan,
                dirty=dirty,
            )
        )
        return subprocess.run(  # nosec B603
            arguments,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_plan_apply_and_verify_bind_the_saved_plan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            base = directory / "plans"

            planned = self.run_target("tofu-plan", base, fake)
            self.assertEqual(planned.returncode, 0, planned.stderr)

            commit = subprocess.check_output(  # nosec B603
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip()
            plan = self.private_plan_base(base) / "network" / f"shell-platform-{commit}.tfplan"
            digest = plan.with_name(f"{plan.name}.sha256").read_text(
                encoding="utf-8"
            ).strip()
            self.assertEqual(len(digest), 64)

            applied = self.run_target(
                "tofu-apply", base, fake, digest=digest
            )
            verified = self.run_target(
                "tofu-verify", base, fake, digest=digest
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["plan", "apply", "output", "plan"],
            )

    def test_refuses_an_unallowlisted_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            result = self.run_target("tofu-plan", directory / "plans", fake, root="shared")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("root is not allow-listed", result.stderr)
            self.assertFalse(log.exists())

    def test_bootstrap_root_plans_applies_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            base = directory / "plans"

            planned = self.run_target("tofu-plan", base, fake, root="bootstrap")
            self.assertEqual(planned.returncode, 0, planned.stderr)

            commit = subprocess.check_output(  # nosec B603
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip()
            plan = self.private_plan_base(base) / "bootstrap" / f"shell-platform-{commit}.tfplan"
            digest = plan.with_name(f"{plan.name}.sha256").read_text(
                encoding="utf-8"
            ).strip()
            self.assertEqual(len(digest), 64)

            applied = self.run_target(
                "tofu-apply", base, fake, root="bootstrap", digest=digest
            )
            verified = self.run_target(
                "tofu-verify", base, fake, root="bootstrap", digest=digest
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                ["plan", "apply", "output", "plan"],
            )

    def test_bootstrap_root_refuses_the_compute_api_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            base = directory / "plans"
            arguments = [MAKE, "-C", str(INIT_ROOT), "tofu-plan"]
            arguments.extend(
                self.common_arguments(base, fake, root="bootstrap")
            )
            api_gate = self.private_plan_base(base) / "api-gate"
            api_gate.write_text("compute.googleapis.com=enabled\n", encoding="utf-8")
            api_gate.chmod(0o600)
            result = subprocess.run(  # nosec B603
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("API gate is not approved", result.stderr)
            self.assertFalse(log.exists())

    def test_refuses_project_environment_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            environment = os.environ.copy()
            environment["TF_VAR_project_id"] = "other-project"
            arguments = [MAKE, "-C", str(INIT_ROOT), "tofu-plan"]
            arguments.extend(self.common_arguments(directory / "plans", fake))
            result = subprocess.run(  # nosec B603
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TF_VAR_project_id", result.stderr)
            self.assertFalse(log.exists())

    def test_refuses_a_dirty_source_tree(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            arguments = [MAKE, "-C", str(INIT_ROOT), "tofu-plan"]
            arguments.extend(
                self.common_arguments(directory / "plans", fake, dirty=True)
            )
            result = subprocess.run(  # nosec B603
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=os.environ.copy(),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source tree is dirty", result.stderr)
            self.assertFalse(log.exists())

    def test_refuses_commit_and_approval_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            wrong_commit = "0" * 40

            commit_result = self.run_target(
                "tofu-plan", directory / "plans", fake, commit=wrong_commit
            )
            approval_result = self.run_target(
                "tofu-plan",
                directory / "plans",
                fake,
                approval="environment-gcp/init/tofu/shared-nodes",
            )

            self.assertNotEqual(commit_result.returncode, 0)
            self.assertIn("commit is not HEAD", commit_result.stderr)
            self.assertNotEqual(approval_result.returncode, 0)
            self.assertIn("approval does not match", approval_result.stderr)
            self.assertFalse(log.exists())

    def test_refuses_noncanonical_plan_and_changed_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="tofu guards ") as name:
            directory = Path(name)
            fake, log = self.fake_tofu(directory)
            base = directory / "plans"
            canonical = self.run_target("tofu-plan", base, fake)
            self.assertEqual(canonical.returncode, 0, canonical.stderr)
            plan = next((self.private_plan_base(base) / "network").glob("*.tfplan"))
            digest = plan.with_name(f"{plan.name}.sha256").read_text(
                encoding="utf-8"
            ).strip()

            wrong_path = self.run_target(
                "tofu-apply",
                base,
                fake,
                digest=digest,
                plan=self.private_plan_base(base) / "network" / "wrong.tfplan",
            )
            plan.write_text("changed-plan\n", encoding="utf-8")
            changed_digest = self.run_target(
                "tofu-apply", base, fake, digest=digest
            )

            self.assertNotEqual(wrong_path.returncode, 0)
            self.assertIn("saved plan path is not exact", wrong_path.stderr)
            self.assertNotEqual(changed_digest.returncode, 0)
            self.assertIn("saved plan digest changed", changed_digest.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["plan"])


if __name__ == "__main__":
    unittest.main()
