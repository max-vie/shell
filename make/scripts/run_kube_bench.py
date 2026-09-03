#!/usr/bin/env python3
"""Preview or run the temporary, host-read-only kube-bench audit."""

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
import kube_bench  # noqa: E402


KUBECONFIG = ROOT / ".local/ansible/kubeconfig/gcp.yaml"


class KubeBenchRunError(RuntimeError):
    """The MAKE kube-bench operation failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KubeBenchRunError(message)


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
        raise KubeBenchRunError("kubectl operation could not complete") from error
    if result.returncode:
        raise KubeBenchRunError("kubectl operation failed")
    return result.stdout


def payload(run_id: str) -> tuple[list[dict[str, Any]], str]:
    documents = kube_bench.resources(run_id)
    return documents, yaml.safe_dump_all(documents, sort_keys=False)


def pod_reports(
    base: list[str], run_id: str, namespace: str, timeout: int = 240
) -> list[tuple[dict[str, Any], str]]:
    deadline = time.monotonic() + timeout
    while True:
        raw = run_command(
            [*base, "get", "pods", "-n", namespace, "-l", f"shell.platform/run-id={run_id}", "-o", "json"]
        )
        try:
            pods = json.loads(raw).get("items", [])
        except json.JSONDecodeError as error:
            raise KubeBenchRunError("kube-bench pod listing is invalid JSON") from error
        reports: list[tuple[dict[str, Any], str]] = []
        for pod in pods:
            if not isinstance(pod, dict) or pod.get("status", {}).get("phase") != "Running":
                continue
            name = pod.get("metadata", {}).get("name")
            if not isinstance(name, str):
                continue
            logs = run_command(
                [*base, "logs", name, "-n", namespace, "-c", "kube-bench"],
                timeout=60,
            )
            if "__SHELL_KUBE_BENCH_DONE__" in logs:
                reports.append((pod, logs))
        daemonset = run_command(
            [*base, "get", "daemonset", f"shell-kube-bench-{run_id}", "-n", namespace, "-o", "json"]
        )
        try:
            desired = json.loads(daemonset).get("status", {}).get("desiredNumberScheduled", 0)
        except json.JSONDecodeError as error:
            raise KubeBenchRunError("kube-bench DaemonSet status is invalid JSON") from error
        if type(desired) is int and desired > 0 and len(reports) == desired:
            return reports
        require(time.monotonic() < deadline, "kube-bench DaemonSet did not finish before the deadline")
        time.sleep(2)


def run(
    kubeconfig: Path,
    evidence: Path,
    approval: str,
    run_id: str | None = None,
) -> dict[str, Any]:
    document = kube_bench.contract()
    require(approval == document["approval"], f"approval must be {document['approval']}")
    kubeconfig = fixed_kubeconfig(kubeconfig)
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    documents, serialized = payload(run_id)
    base = kubectl(kubeconfig)
    applied = False
    try:
        applied = True
        run_command(
            [*base, "apply", "--server-side", "--field-manager=make-kube-bench", "-f", "-"],
            input_text=serialized,
            timeout=60,
        )
        reports = pod_reports(base, run_id, document["namespace"])
        checks = {name: 0 for name in ("PASS", "FAIL", "WARN", "INFO", "NOT_APPLICABLE", "MANUAL")}
        nodes: list[dict[str, Any]] = []
        for pod, logs in reports:
            counts = kube_bench.parse_report(logs)
            for key, value in counts.items():
                checks[key] += value
            nodes.append(
                {
                    "pod": pod.get("metadata", {}).get("name"),
                    "phase": pod.get("status", {}).get("phase"),
                    "checks": counts,
                }
            )
        passed = checks["FAIL"] <= document["gate"]["max_fail"] and checks["WARN"] <= document["gate"]["max_warn"]
        result = {
            "schema_version": "1.0",
            "contract": document["contract_id"],
            "environment": document["environment"],
            "run_id": run_id,
            "result": "pass" if passed else "fail",
            "nodes": nodes,
            "checks": checks,
        }
        kube_bench.write_evidence(evidence, result)
        require(passed, "kube-bench CIS gate failed")
        return result
    finally:
        if applied:
            cleanup = [item for item in documents if item.get("kind") != "Namespace"]
            run_command(
                [*base, "delete", "--ignore-not-found", "--wait=true", "-f", "-"],
                input_text=yaml.safe_dump_all(cleanup, sort_keys=False),
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
            kube_bench.resources("20990101000000")
            print("validated kube-bench K3s audit contract")
            return 0
        require(args.evidence is not None, "--evidence is required for a kube-bench run")
        result = run(args.kubeconfig, args.evidence, args.approval, args.run_id)
        print(json.dumps({"result": result["result"], "checks": result["checks"]}, sort_keys=True))
        return 0
    except (KubeBenchRunError, kube_bench.KubeBenchError, OSError, ValueError) as error:
        print(f"MAKE kube-bench operation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
