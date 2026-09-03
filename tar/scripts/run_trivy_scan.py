#!/usr/bin/env python3
"""Run an immutable-image Trivy scan against an offline vulnerability DB."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path
from typing import Any, cast


DIGEST = re.compile(r"^[^\s@]+(?:/[^\s@]+)*@sha256:[0-9a-f]{64}$")
SEVERITIES = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


class ScanError(RuntimeError):
    """A Trivy scan or report gate failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ScanError(message)


def validate_cache(cache: Path) -> Path:
    require(not cache.is_symlink(), "Trivy cache must not be a symlink")
    cache = cache.resolve()
    require(cache.is_dir(), "Trivy cache must be a directory")
    require(stat.S_IMODE(cache.stat().st_mode) == 0o700, "Trivy cache must be mode 0700")
    for relative in ("db/trivy.db", "db/metadata.json"):
        path = cache / relative
        require(path.is_file() and not path.is_symlink(), f"Trivy cache file is missing: {relative}")
    return cache


def validate_docker_config(path: Path) -> Path:
    require(path.name == "config.json", "Docker config must be named config.json")
    require(path.is_file() and not path.is_symlink(), "Docker config is missing")
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "Docker config must be mode 0600")
    require(path.parent.is_dir() and not path.parent.is_symlink(), "Docker config directory is unsafe")
    require(stat.S_IMODE(path.parent.stat().st_mode) == 0o700, "Docker config directory must be mode 0700")
    return path.resolve()


def validate_report(report: dict[str, Any], image: str) -> dict[str, int]:
    require(report.get("SchemaVersion") == 2, "Trivy report schema is not v2")
    require(report.get("ArtifactType") == "container_image", "Trivy report is not an image report")
    results_value = report.get("Results")
    require(isinstance(report.get("Metadata"), dict) and isinstance(results_value, list), "Trivy report shape changed")
    results = cast(list[Any], results_value)
    require(bool(results), "Trivy report contains no scan result")
    require(report.get("ArtifactName") == image, "Trivy report image identity changed")
    counts = {severity: 0 for severity in SEVERITIES}
    for result in results:
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        require(isinstance(vulnerabilities, list), "Trivy vulnerability result shape changed")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            severity_value = vulnerability.get("Severity")
            require(isinstance(severity_value, str) and severity_value in counts, "Trivy report contains an unknown severity")
            severity = cast(str, severity_value)
            counts[severity] += 1
    require(counts["HIGH"] + counts["CRITICAL"] == 0, "Trivy HIGH/CRITICAL gate failed")
    return counts


def build_command(trivy: str, image: str, cache: Path, output: Path) -> list[str]:
    return [
        trivy,
        "image",
        "--quiet",
        "--scanners",
        "vuln",
        "--skip-db-update",
        "--ignore-unfixed",
        "--cache-dir",
        str(cache),
        "--format",
        "json",
        "--output",
        str(output),
        image,
    ]


def scan(
    image: str,
    report_path: Path,
    cache: Path,
    *,
    trivy: str = "trivy",
    docker_config: Path | None = None,
) -> dict[str, int]:
    require(DIGEST.fullmatch(image) is not None, "image must be an immutable digest reference")
    require(not report_path.exists() and not report_path.is_symlink(), "refusing to overwrite Trivy evidence")
    report_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not report_path.parent.is_symlink(), "Trivy evidence directory must not be a symlink")
    report_path.parent.chmod(0o700)
    cache = validate_cache(cache)
    environment = os.environ.copy()
    if docker_config is not None:
        docker_config = validate_docker_config(docker_config)
        environment["DOCKER_CONFIG"] = str(docker_config.parent)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{report_path.name}.", dir=report_path.parent
    )
    temporary = Path(temporary_name)
    os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
    os.close(descriptor)
    try:
        result = subprocess.run(  # nosec B603
            build_command(trivy, image, cache, temporary),
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode:
            if temporary.is_file() and not temporary.is_symlink():
                os.replace(temporary, report_path)
                report_path.chmod(0o600)
            raise ScanError("Trivy scan failed")
        require(temporary.is_file() and not temporary.is_symlink(), "Trivy did not produce a report")
        os.replace(temporary, report_path)
        report_path.chmod(0o600)
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ScanError("Trivy report is not valid JSON") from error
        require(isinstance(report, dict), "Trivy report is not a JSON object")
        return validate_report(report, image)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--docker-config", type=Path)
    parser.add_argument("--trivy", default="trivy")
    args = parser.parse_args()
    try:
        counts = scan(
            args.image,
            args.report,
            args.cache_dir,
            trivy=args.trivy,
            docker_config=args.docker_config,
        )
        print(json.dumps({"report": str(args.report), "findings": counts}, sort_keys=True))
        return 0
    except (OSError, ScanError, ValueError) as error:
        print(f"Trivy scan failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
