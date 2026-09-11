#!/usr/bin/env python3
"""Run the read-only SHELL GCP bootstrap checks (slices 0, 1, and verify)."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, Callable, cast


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
PROJECT_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
ZONE_PATTERN = re.compile(r"^[a-z][a-z0-9-]+[0-9]-[a-z]$")
REGION = "europe-west4"
REQUIRED_APIS = {
    "compute.googleapis.com",
    "iamcredentials.googleapis.com",
    "iap.googleapis.com",
    "oslogin.googleapis.com",
    "storage.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
    "cloudbilling.googleapis.com",
    "billingbudgets.googleapis.com",
}
MACHINE_SHAPES = ("e2-standard-2", "n2-standard-4", "n2-standard-8")
LEDGER_FIELDS = {
    "schema_version",
    "trial_start",
    "trial_end",
    "credit_amount",
    "credit_percent",
    "warning_threshold",
    "screenshot",
}


class BootstrapLauncherError(ValueError):
    """A read-only GCP bootstrap check cannot be executed safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapLauncherError(message)


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "JSON contains duplicate object keys")
        value[key] = item
    return value


def _check_path_components(path: Path, root: Path, label: str) -> None:
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise BootstrapLauncherError(f"{label} escaped the repository") from error
    current = root
    for component in relative.parts:
        current /= component
        require(not current.is_symlink(), f"{label} contains a symlink")


def _require_private_file(path: Path, root: Path, label: str) -> None:
    _check_path_components(path, root, label)
    require(not path.is_symlink() and path.is_file(), f"{label} is not a regular file")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must be mode 0600",
    )
    _require_private_directory(path.parent, root, f"{label} parent")


def _require_private_directory(path: Path, root: Path, label: str) -> None:
    _check_path_components(path, root, label)
    require(path.is_dir(), f"{label} is not a directory")
    metadata = path.stat()
    require(metadata.st_uid == os.geteuid(), f"{label} has the wrong owner")
    require(
        stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
        f"{label} must be mode 0700",
    )


def _read_private_json(path: Path, root: Path, label: str) -> dict[str, Any]:
    _require_private_file(path, root, label)
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_pairs,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BootstrapLauncherError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _gcloud(
    arguments: list[str],
    *,
    run_process: Callable[..., Any],
    project: str,
) -> subprocess.CompletedProcess[str]:
    command = ["gcloud", *arguments, "--project", project, "--format", "json"]
    return cast(
        subprocess.CompletedProcess[str],
        run_process(command, capture_output=True, text=True, check=False),
    )


def _require_success(completed: subprocess.CompletedProcess[str], label: str) -> None:
    require(completed.returncode == 0, f"{label} failed: {completed.stderr.strip()}")


def _parse_json(completed: subprocess.CompletedProcess[str], label: str) -> Any:
    _require_success(completed, label)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BootstrapLauncherError(f"{label} returned invalid JSON") from error


def _project_id(path: Path, root: Path) -> str:
    value = _read_private_json(path, root, "private bootstrap input")
    require(set(value) == {"project_id"}, "private bootstrap input fields changed")
    project = value["project_id"]
    require(
        isinstance(project, str) and PROJECT_PATTERN.fullmatch(project) is not None,
        "project_id is invalid",
    )
    return project


def _ledger(path: Path, root: Path) -> dict[str, Any]:
    value = _read_private_json(path, root, "private ledger")
    require(set(value) == LEDGER_FIELDS, "ledger fields changed")
    require(value["schema_version"] == "1.0", "ledger schema changed")
    for field in ("trial_start", "trial_end", "credit_amount", "credit_percent", "warning_threshold"):
        require(isinstance(value[field], str) and value[field].strip(), f"ledger {field} is missing")
    require(isinstance(value["screenshot"], str) and value["screenshot"].strip(), "ledger screenshot is missing")
    screenshot = root / value["screenshot"]
    _check_path_components(screenshot, root, "ledger screenshot")
    require(screenshot.is_file() and not screenshot.is_symlink(), "ledger screenshot is missing")
    return value


def discover(
    *,
    repository_root: Path = REPOSITORY_ROOT,
    run_process: Callable[..., Any] = subprocess.run,
) -> int:
    repository_root = repository_root.resolve(strict=True)
    private_root = repository_root / ".local/gcp-bootstrap"
    _require_private_directory(private_root, repository_root, "private bootstrap directory")
    project = _project_id(private_root / "project.json", repository_root)

    checks: list[tuple[str, str]] = []
    completed = _gcloud(["auth", "list", "--filter", "status:ACTIVE"], run_process=run_process, project=project)
    _require_success(completed, "active gcloud identity")
    checks.append(("active identity", "present"))

    completed = _gcloud(["compute", "regions", "describe", REGION], run_process=run_process, project=project)
    region = _parse_json(completed, "region description")
    require(region.get("status") == "UP", "region is not UP")
    checks.append(("region", f"{REGION} UP"))

    completed = _gcloud(["compute", "zones", "list", "--filter", f"name:{REGION}-*"], run_process=run_process, project=project)
    zones = _parse_json(completed, "zone listing")
    require(isinstance(zones, list) and len(zones) == 3, "zone set changed")
    for zone in zones:
        require(zone.get("status") == "UP", f"zone {zone.get('name')} is not UP")
    checks.append(("zones", "a, b, c UP"))

    completed = _gcloud(["compute", "regions", "describe", REGION], run_process=run_process, project=project)
    quotas = _parse_json(completed, "quota listing")
    required_quotas = {
        "E2_CPUS": 4,
        "N2_CPUS": 20,
        "DISKS_TOTAL_GB": 742,
        "INSTANCES": 6,
    }
    for quota in quotas.get("quotas", []):
        metric = quota.get("metric")
        if metric in required_quotas:
            require(
                quota.get("limit", 0) >= required_quotas[metric],
                f"quota {metric} is below the declared node set",
            )
    checks.append(("quota", "sufficient for the declared node set"))

    completed = _gcloud(
        ["compute", "machine-types", "list", "--zones", f"{REGION}-a,{REGION}-b,{REGION}-c"],
        run_process=run_process,
        project=project,
    )
    shapes = _parse_json(completed, "machine shape listing")
    available = {shape.get("name") for shape in shapes}
    require(set(MACHINE_SHAPES) <= available, "a declared machine shape is unavailable")
    checks.append(("machine shapes", ", ".join(MACHINE_SHAPES)))

    completed = _gcloud(["compute", "images", "list", "--project", "debian-cloud", "--filter", "family=debian-13"], run_process=run_process, project=project)
    debian = _parse_json(completed, "Debian image listing")
    require(isinstance(debian, list) and len(debian) >= 1, "Debian 13 image is missing")
    checks.append(("Debian 13 image", debian[0].get("name", "present")))

    completed = _gcloud(["compute", "images", "list", "--project", "almalinux-cloud", "--filter", "family=almalinux-9"], run_process=run_process, project=project)
    alma = _parse_json(completed, "AlmaLinux image listing")
    require(isinstance(alma, list) and len(alma) >= 1, "AlmaLinux 9 image is missing")
    checks.append(("AlmaLinux 9 image", alma[0].get("name", "present")))

    completed = _gcloud(["services", "list", "--available"], run_process=run_process, project=project)
    services = _parse_json(completed, "service availability")
    available_services = {service.get("config", {}).get("name") for service in services}
    require(REQUIRED_APIS <= available_services, "a required API is unavailable")
    checks.append(("service coverage", f"{len(REQUIRED_APIS)} required APIs available"))

    for label, result in checks:
        print(f"{label}: {result}")
    print("discover: all checks pass")
    return 0


def ledger(
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> int:
    repository_root = repository_root.resolve(strict=True)
    private_root = repository_root / ".local/gcp-bootstrap"
    _require_private_directory(private_root, repository_root, "private bootstrap directory")
    value = _ledger(private_root / "ledger.json", repository_root)
    print("ledger: schema 1.0, trial window, credit, threshold, and screenshot present")
    print("ledger: values withheld from output")
    return 0


def verify(
    *,
    repository_root: Path = REPOSITORY_ROOT,
    run_process: Callable[..., Any] = subprocess.run,
) -> int:
    repository_root = repository_root.resolve(strict=True)
    private_root = repository_root / ".local/gcp-bootstrap"
    _require_private_directory(private_root, repository_root, "private bootstrap directory")
    project = _project_id(private_root / "project.json", repository_root)

    completed = _gcloud(["billing", "projects", "describe"], run_process=run_process, project=project)
    billing = _parse_json(completed, "billing description")
    require(billing.get("billingEnabled") is True, "billing is not enabled")
    print("billing: enabled")

    completed = _gcloud(["services", "list", "--enabled"], run_process=run_process, project=project)
    services = _parse_json(completed, "enabled service listing")
    enabled = {service.get("config", {}).get("name") for service in services}
    require(REQUIRED_APIS <= enabled, "a required API is not enabled")
    print(f"services: {len(REQUIRED_APIS)} required APIs enabled")

    completed = _gcloud(["iam", "service-accounts", "list"], run_process=run_process, project=project)
    accounts = _parse_json(completed, "service account listing")
    require(
        any(account.get("email", "").startswith("shell-local-deployer@") for account in accounts),
        "deployment service account is missing",
    )
    print("service account: shell-local-deployer present")

    completed = _gcloud(["iam", "roles", "list"], run_process=run_process, project=project)
    roles = _parse_json(completed, "custom role listing")
    require(
        any(role.get("name", "").endswith("/roles/shell_local_deployer") for role in roles),
        "custom role is missing",
    )
    print("custom role: shell_local_deployer present")

    completed = _gcloud(["compute", "regions", "describe", REGION], run_process=run_process, project=project)
    _require_success(completed, "impersonation verification")
    print("impersonation: token issuance and read access verified")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("discover", help="run the read-only Slice 1 discovery checks")
    actions.add_parser("ledger", help="validate the private Slice 0 ledger")
    actions.add_parser("verify", help="verify the Slice 3 operator boundary")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action == "discover":
            return discover()
        if args.action == "ledger":
            return ledger()
        return verify()
    except (OSError, BootstrapLauncherError) as error:
        print(f"INIT bootstrap launcher refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
