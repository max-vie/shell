#!/usr/bin/env python3
"""Validate the source-only Grafana recovery policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parent
CONTRACT_PATH = ROOT / "contracts/grafana-recovery-drill.json"
RULE_PATH = ROOT / "monitoring/grafana-recovery.rules.yaml"
MAKE_SCRIPTS = REPOSITORY_ROOT / "make/scripts"
WATCH_SCRIPTS = ROOT / "scripts"
for script_root in (WATCH_SCRIPTS, MAKE_SCRIPTS):
    if str(script_root) not in sys.path:
        sys.path.insert(0, str(script_root))
import validate_monitoring_contract as monitoring_contract  # noqa: E402


class RecoveryValidationError(ValueError):
    """The recovery policy is incomplete or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryValidationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "recovery contract is missing")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryValidationError("recovery contract is not valid JSON") from error
    require(isinstance(value, dict), "recovery contract must be an object")
    return cast(dict[str, Any], value)


def validate_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    document = read_json(path)
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "execution_owner",
            "proof_status",
            "environment",
            "cluster",
            "approval",
            "target",
            "alert",
            "stability",
            "limits",
        },
        "recovery contract shape changed",
    )
    require(document["schema_version"] == "1.0", "recovery schema changed")
    require(document["contract_version"] == "1.0.0", "recovery version changed")
    require(document["contract_id"] == "grafana-recovery-drill", "recovery ID changed")
    require(document["policy_owner"] == "watch", "WATCH must own recovery policy")
    require(document["execution_owner"] == "make", "MAKE must own deferred execution")
    require(document["proof_status"] == "source-only", "recovery proof status changed")
    require(document["environment"] == "environment-gcp", "recovery environment changed")
    require(document["approval"] == "environment-gcp/watch/grafana-unavailable", "recovery approval changed")
    require(
        document["cluster"]
        == {"name": "gcp", "nodes": ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"]},
        "recovery cluster boundary changed",
    )
    require(
        document["target"]
        == {
            "kind": "Deployment",
            "namespace": "monitoring",
            "name": "shell-watch-grafana",
            "healthy_replicas": 1,
            "annotation": "shell.internal/recovery-drill",
        },
        "recovery target boundary changed",
    )
    alert = document["alert"]
    require(
        alert
        == {
            "name": "ShellWatchGrafanaUnavailable",
            "query": 'kube_deployment_status_replicas_available{namespace="monitoring",deployment="shell-watch-grafana"} < 1',
            "hold_seconds": 60,
            "labels": {
                "owner": "watch",
                "drill": "grafana-unavailability",
                "severity": "warning",
            },
        },
        "recovery alert boundary changed",
    )
    require(
        document["stability"] == {"samples": 20, "interval_seconds": 30},
        "recovery stability boundary changed",
    )
    require(document["limits"] == {"max_outage_seconds": 300}, "recovery limits changed")
    current = monitoring_contract.validate_contract()
    require(
        current["cluster"]["name"] == document["cluster"]["name"]
        and current["cluster"]["nodes"] == document["cluster"]["nodes"]
        and current["deployment"]["namespace"] == document["target"]["namespace"]
        and current["deployment"]["release"] + "-grafana" == document["target"]["name"],
        "recovery and monitoring contracts differ",
    )
    return document


def validate_rule(path: Path = RULE_PATH) -> None:
    require(path.is_file() and not path.is_symlink(), "recovery rule is missing")
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RecoveryValidationError("recovery rule cannot be read") from error
    contract = validate_contract()
    for fragment in (
        "apiVersion: monitoring.coreos.com/v1",
        "kind: PrometheusRule",
        "name: shell-watch-grafana-recovery",
        "namespace: monitoring",
        "release: shell-watch",
        "alert: ShellWatchGrafanaUnavailable",
        'namespace="monitoring"',
        'deployment="shell-watch-grafana"',
        "for: 60s",
    ):
        require(fragment in source, f"recovery rule is missing: {fragment}")
    require(source.count("alert: ShellWatchGrafanaUnavailable") == 1, "recovery alert is duplicated")
    require("alert: Watchdog" not in source, "recovery rule must not define Watchdog")
    require(
        re.sub(r"\s+", "", contract["alert"]["query"]) in re.sub(r"\s+", "", source),
        "recovery rule query differs from the contract",
    )
    for forbidden in ("password", "token", "shellprod", "LokiRecovery"):
        require(forbidden.lower() not in source.lower(), f"recovery rule contains forbidden scope: {forbidden}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", type=Path, default=RULE_PATH)
    args = parser.parse_args()
    try:
        validate_contract()
        validate_rule(args.rule)
    except (RecoveryValidationError, OSError, ValueError) as error:
        print(f"recovery validation failed: {error}", file=sys.stderr)
        return 2
    print("validated source-only Grafana recovery policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
