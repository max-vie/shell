"""Test the INIT OpenTofu source-validation target."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INIT_ROOT = ROOT / "init"
MAKE = shutil.which("make") or "make"
ROOTS = (
    "opentofu/gcp/shared",
    "opentofu/gcp/k3s",
    "opentofu/gcp/proxmox-host",
    "opentofu/proxmox/k3s",
    "opentofu/gcs-backup",
)


class OpenTofuCheckTests(unittest.TestCase):
    def fake_tofu(
        self,
        directory: Path,
        *,
        fail_root: str | None = None,
        signal_root: str | None = None,
    ) -> tuple[Path, Path]:
        log = directory / "tofu.log"
        log_literal = shlex.quote(str(log))
        executable = directory / "tofu"
        failure = ""
        if fail_root is not None:
            failure = f"""
case "$*" in
  *"/{fail_root} init"*) exit 17 ;;
esac
"""
        signal = ""
        if signal_root is not None:
            signal = f"""
case "$*" in
  *"/{signal_root} init"*) kill -TERM "$PPID"; sleep 1; exit 20 ;;
esac
"""
        executable.write_text(
            f"""#!/bin/sh
set -eu
printf 'ARGS' >> {log_literal}
for argument in "$@"; do printf ' <%s>' "$argument" >> {log_literal}; done
printf '\\n' >> {log_literal}
env | LC_ALL=C sort >> {log_literal}
printf '%s\\n' '---' >> {log_literal}
directory=''
for argument in "$@"; do
  case "$argument" in -chdir=*) directory=${{argument#-chdir=}} ;; esac
done
if [ -n "$directory" ] && grep -R -q 'private-opentofu-sentinel' "$directory"; then
  printf '%s\\n' PRIVATE_INPUT_COPIED >> {log_literal}
fi
case "$directory" in
  */init/opentofu)
    test -f "$directory/gcp/shared/main.tf" || exit 18
    test -f "$directory/modules/gcp-private-node/main.tf" || exit 19
    ;;
  */init/opentofu/gcp/shared|*/init/opentofu/gcp/k3s)
    test -f "$directory/../../../../tar/manifests/platform-addons-supply.json" || exit 20
    ;;
esac
case "$directory" in
  */init/opentofu/*)
    test -f "$directory/.terraform.lock.hcl" || exit 21
    ;;
esac
{failure}
{signal}
""",
            encoding="utf-8",
        )
        executable.chmod(0o700)
        return executable, log

    def run_target(
        self,
        executable: Path,
        cache: Path,
        *,
        git: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GOOGLE_APPLICATION_CREDENTIALS": "/private/google.json",
                "PROXMOX_VE_API_TOKEN": "x" * 16,
                "TF_CLI_ARGS": "-backend=true",
                "TF_VAR_private": "private-value",
            }
        )
        arguments = [
            MAKE,
            "-C",
            str(INIT_ROOT),
            "opentofu-check",
            f"TOFU={executable}",
            f"OPENTOFU_CACHE={cache}",
        ]
        if git is not None:
            arguments.append(f"GIT={git}")
        return subprocess.run(  # nosec B603
            arguments,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_validates_exact_roots_without_private_inputs(self) -> None:
        sentinel = INIT_ROOT / "opentofu/gcs-backup" / f"{uuid.uuid4()}.tfvars"
        sentinel.write_text("private-opentofu-sentinel", encoding="utf-8")
        try:
            with tempfile.TemporaryDirectory(prefix="open tofu ") as directory_name:
                directory = Path(directory_name)
                executable, log = self.fake_tofu(directory)
                result = self.run_target(executable, directory / "cache")
                self.assertEqual(result.returncode, 0, result.stderr)
                output = log.read_text(encoding="utf-8")
        finally:
            sentinel.unlink(missing_ok=True)

        calls = [line for line in output.splitlines() if line.startswith("ARGS")]
        self.assertEqual(len(calls), 11)
        self.assertIn(
            "/opentofu> <fmt> <-check> <-diff> <-recursive> <-no-color>", calls[0]
        )
        for index, root in enumerate(ROOTS):
            init_call = calls[1 + index * 2]
            validate_call = calls[2 + index * 2]
            self.assertIn(f"/{root}> <init>", init_call)
            self.assertIn(
                "<-backend=false> <-input=false> <-lockfile=readonly> <-no-color>",
                init_call,
            )
            self.assertIn(f"/{root}> <validate> <-no-color>", validate_call)
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", output)
        self.assertNotIn("PROXMOX_VE_API_TOKEN", output)
        self.assertNotIn("TF_CLI_ARGS", output)
        self.assertNotIn("TF_VAR_private", output)
        self.assertNotIn("PRIVATE_INPUT_COPIED", output)
        self.assertIn("TF_IN_AUTOMATION=1", output)
        self.assertIn(f"TF_PLUGIN_CACHE_DIR={directory / 'cache'}", output)
        self.assertIn("TF_DATA_DIR=", output)
        home = next(
            Path(line.removeprefix("HOME="))
            for line in output.splitlines()
            if line.startswith("HOME=")
        )
        self.assertFalse(home.parent.exists())

    def test_stops_after_the_first_failed_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            executable, log = self.fake_tofu(directory, fail_root="opentofu/gcp/k3s")
            result = self.run_target(executable, directory / "cache")
            self.assertNotEqual(result.returncode, 0)
            output = log.read_text(encoding="utf-8")

        self.assertIn("/opentofu/gcp/shared> <validate>", output)
        self.assertIn("/opentofu/gcp/k3s> <init>", output)
        self.assertNotIn("/opentofu/gcp/k3s> <validate>", output)
        self.assertNotIn("/opentofu/gcp/proxmox-host>", output)
        home = next(
            Path(line.removeprefix("HOME="))
            for line in output.splitlines()
            if line.startswith("HOME=")
        )
        self.assertFalse(home.parent.exists())

    def test_source_discovery_failure_stops_before_tofu(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            executable, log = self.fake_tofu(directory)
            git = directory / "git"
            git.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
            git.chmod(0o700)
            result = self.run_target(executable, directory / "cache", git=git)

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(log.exists())

    def test_signal_stops_and_removes_the_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            executable, log = self.fake_tofu(
                directory, signal_root="opentofu/gcp/k3s"
            )
            result = self.run_target(executable, directory / "cache")
            output = log.read_text(encoding="utf-8")

        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("/opentofu/gcp/k3s> <validate>", output)
        self.assertNotIn("/opentofu/gcp/proxmox-host>", output)
        home = next(
            Path(line.removeprefix("HOME="))
            for line in output.splitlines()
            if line.startswith("HOME=")
        )
        self.assertFalse(home.parent.exists())


if __name__ == "__main__":
    unittest.main()
