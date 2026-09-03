#!/usr/bin/env python3
"""Preview or run the bounded MAKE k6 release-feed load check."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess  # nosec B404
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[2]
WATCH_SCRIPTS = ROOT / "watch/scripts"
if str(WATCH_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(WATCH_SCRIPTS))
import k6_load  # noqa: E402


KUBECONFIG = ROOT / ".local/ansible/kubeconfig/gcp.yaml"


class K6RunError(RuntimeError):
    """The MAKE k6 operation failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise K6RunError(message)


def fixed_kubeconfig(path: Path) -> Path:
    value = Path(os.path.abspath(path))
    expected = Path(os.path.abspath(KUBECONFIG))
    require(value == expected, "GCP kubeconfig path changed")
    require(value.is_file() and not value.is_symlink(), "GCP kubeconfig is missing")
    require(stat.S_IMODE(value.stat().st_mode) == 0o600, "GCP kubeconfig must be mode 0600")
    return value


def kubectl(kubeconfig: Path, *arguments: str) -> list[str]:
    return ["kubectl", "--kubeconfig", str(kubeconfig), *arguments]


def run_command(
    command: list[str], *, input_text: str | None = None, timeout: int = 60
) -> str:
    try:
        result = subprocess.run(  # nosec B603
            command,
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise K6RunError("kubectl operation could not complete") from error
    if result.returncode:
        raise K6RunError("kubectl operation failed")
    return result.stdout


def wait_for_job(base: list[str], name: str, namespace: str, timeout: int = 240) -> None:
    deadline = time.monotonic() + timeout
    while True:
        raw = run_command([*base, "get", "job", name, "-n", namespace, "-o", "json"])
        try:
            status = json.loads(raw).get("status", {})
        except json.JSONDecodeError as error:
            raise K6RunError("k6 Job status is invalid JSON") from error
        if status.get("succeeded", 0) == 1 or status.get("failed", 0) == 1:
            return
        require(time.monotonic() < deadline, "k6 Job did not finish before the deadline")
        time.sleep(2)


def run(
    kubeconfig: Path,
    evidence: Path,
    approval: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    document = k6_load.contract()
    require(approval == document["approval"], f"approval must be {document['approval']}")
    kubeconfig = fixed_kubeconfig(kubeconfig)
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    documents = k6_load.resources(run_id)
    serialized = yaml.safe_dump_all(documents, sort_keys=False)
    base = kubectl(kubeconfig)
    job_name = f"shell-k6-{run_id}"
    applied = False
    try:
        applied = True
        run_command(
            [*base, "apply", "--server-side", "--field-manager=make-k6", "-f", "-"],
            input_text=serialized,
            timeout=60,
        )
        wait_for_job(base, job_name, document["namespace"])
        logs = run_command([*base, "logs", f"job/{job_name}", "-n", document["namespace"]])
        summary = k6_load.summary_from_logs(logs)
        try:
            metrics = k6_load.validate_summary(summary, document)
        except (K6RunError, k6_load.K6Error) as error:
            k6_load.write_evidence(
                evidence,
                {
                    "schema_version": "1.0",
                    "contract": document["contract_id"],
                    "environment": document["environment"],
                    "run_id": run_id,
                    "result": "fail",
                    "error": str(error),
                },
            )
            raise
        result = {
            "schema_version": "1.0",
            "contract": document["contract_id"],
            "environment": document["environment"],
            "run_id": run_id,
            "result": "pass",
            "metrics": metrics,
        }
        k6_load.write_evidence(evidence, result)
        return result
    finally:
        if applied:
            run_command(
                [*base, "delete", "--ignore-not-found", "--wait=true", "-f", "-"],
                input_text=serialized,
                timeout=60,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preview", "run"))
    parser.add_argument("--kubeconfig", type=Path, default=KUBECONFIG)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--approval", default="")
    parser.add_argument("--run-id")
    args = parser.parse_args(argv)
    try:
        if args.action == "preview":
            k6_load.resources("20990101000000")
            print("validated k6 release-feed load contract (600 requests, 2 minutes)")
            return 0
        require(args.evidence is not None, "--evidence is required for a k6 run")
        result = run(args.kubeconfig, args.evidence, args.approval, args.run_id)
        print(json.dumps({"result": result["result"], "metrics": result["metrics"]}, sort_keys=True))
        return 0
    except (K6RunError, k6_load.K6Error, OSError, ValueError) as error:
        print(f"MAKE k6 operation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
