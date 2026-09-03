#!/usr/bin/env python3
"""Build and validate the WATCH k6 load check without applying resources."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "watch/contracts/k6-load-requirements.json"
SCRIPT_PATH = ROOT / "watch/load/release-feed.js"
ROOT_CA = ROOT / "sudo/pki/shell-offline-root.crt.pem"
TAR_SCRIPTS = ROOT / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import validate_security_tooling as security_supply  # noqa: E402


RUN_ID = re.compile(r"^[0-9]{14}$")


class K6Error(RuntimeError):
    """The k6 load contract failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise K6Error(message)


def _read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "k6 contract is missing")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise K6Error("k6 contract is invalid JSON") from error
    require(isinstance(value, dict), "k6 contract is not an object")
    return cast(dict[str, Any], value)


def contract() -> dict[str, Any]:
    document = _read_json(CONTRACT_PATH)
    require(
        set(document)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "execution_owner",
            "consumer_owners",
            "proof_status",
            "environment",
            "namespace",
            "approval",
            "image",
            "target_url",
            "tls_verification",
            "rate_per_second",
            "duration_seconds",
            "expected_requests",
            "thresholds",
            "resources",
            "excluded_fields",
        },
        "k6 contract shape changed",
    )
    require(
        document["schema_version"] == "1.0"
        and document["contract_version"] == "1.0.0"
        and document["contract_id"] == "k6-load-requirements",
        "k6 contract identity changed",
    )
    require(
        document["policy_owner"] == "watch"
        and document["execution_owner"] == "make"
        and document["consumer_owners"] == ["make", "watch"]
        and document["proof_status"] == "source-only"
        and document["environment"] == "environment-gcp",
        "k6 ownership changed",
    )
    require(
        document["namespace"] == "monitoring"
        and document["approval"] == "environment-gcp/make/k6"
        and document["target_url"]
        == "https://release-feed.release-feed.svc.cluster.local/healthz"
        and document["tls_verification"] == "enabled_with_sudo_root"
        and document["rate_per_second"] * document["duration_seconds"]
        == document["expected_requests"]
        == 600,
        "k6 budget or target changed",
    )
    require(
        document["thresholds"]
        == {"http_failure_rate_lt": 0.01, "checks_rate_gte": 0.99, "p95_ms_lt": 500},
        "k6 thresholds changed",
    )
    require(SCRIPT_PATH.is_file() and not SCRIPT_PATH.is_symlink(), "k6 script is missing")
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    require(
        "constant-arrival-rate" in source
        and "rate: 5" in source
        and 'duration: "2m"' in source
        and "insecureSkipTLSVerify" not in source,
        "k6 script budget or TLS boundary changed",
    )
    require(ROOT_CA.is_file() and not ROOT_CA.is_symlink(), "SUDO root CA is missing")
    lock = security_supply.validate()
    image = lock["images"]["docker.io/grafana/k6:2.1.0"]
    require(
        document["image"] == f"docker.io/grafana/k6:2.1.0@{image['digest']}",
        "k6 image pin changed",
    )
    return document


def resources(run_id: str, target: str | None = None) -> list[dict[str, Any]]:
    document = contract()
    require(RUN_ID.fullmatch(run_id) is not None, "k6 run ID is malformed")
    target = target or document["target_url"]
    require(target == document["target_url"], "k6 target must remain the contract target")
    labels = {"app.kubernetes.io/name": "shell-k6", "shell.platform/run-id": run_id}
    namespace = document["namespace"]
    script_name = f"shell-k6-script-{run_id}"
    ca_name = f"shell-k6-ca-{run_id}"
    job_name = f"shell-k6-{run_id}"
    return [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": f"shell-k6-{run_id}", "namespace": namespace, "labels": labels},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": script_name, "namespace": namespace, "labels": labels},
            "data": {"release-feed.js": SCRIPT_PATH.read_text(encoding="utf-8")},
        },
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": ca_name, "namespace": namespace, "labels": labels},
            "data": {"ca.crt": ROOT_CA.read_text(encoding="ascii")},
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"shell-k6-egress-{run_id}", "namespace": namespace, "labels": labels},
            "spec": {
                "podSelector": {"matchLabels": labels},
                "policyTypes": ["Ingress", "Egress"],
                "egress": [
                    {
                        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
                    },
                    {
                        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "release-feed"}}}],
                        "ports": [{"protocol": "TCP", "port": 443}],
                    },
                ],
            },
        },
        {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": job_name, "namespace": namespace, "labels": labels},
            "spec": {
                "backoffLimit": 0,
                "activeDeadlineSeconds": 180,
                "ttlSecondsAfterFinished": 300,
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "serviceAccountName": f"shell-k6-{run_id}",
                        "automountServiceAccountToken": False,
                        "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [
                            {
                                "name": "k6",
                                "image": document["image"],
                                "command": ["sh", "-ec"],
                                "args": [
                                    "k6 run --quiet --summary-export=/tmp/k6-summary.json /scripts/release-feed.js; "
                                    "status=$?; cat /tmp/k6-summary.json; exit $status"
                                ],
                                "env": [
                                    {"name": "TARGET_URL", "value": target},
                                    {"name": "SSL_CERT_FILE", "value": "/etc/shell-ca/ca.crt"},
                                ],
                                "resources": document["resources"],
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True,
                                },
                                "volumeMounts": [
                                    {"name": "script", "mountPath": "/scripts", "readOnly": True},
                                    {"name": "ca", "mountPath": "/etc/shell-ca", "readOnly": True},
                                    {"name": "tmp", "mountPath": "/tmp"},
                                ],
                            }
                        ],
                        "volumes": [
                            {"name": "script", "configMap": {"name": script_name, "defaultMode": 0o444}},
                            {"name": "ca", "configMap": {"name": ca_name, "items": [{"key": "ca.crt", "path": "ca.crt"}], "defaultMode": 0o444}},
                            {"name": "tmp", "emptyDir": {"sizeLimit": "128Mi"}},
                        ],
                    },
                },
            },
        },
    ]


def validate_summary(summary: dict[str, Any], document: dict[str, Any] | None = None) -> dict[str, float | int]:
    document = document or contract()
    metrics_value = summary.get("metrics")
    require(isinstance(metrics_value, dict), "k6 summary metrics are missing")
    metrics = cast(dict[str, Any], metrics_value)

    def value(metric: str, field: str) -> float:
        metric_data_value = metrics.get(metric)
        require(isinstance(metric_data_value, dict), f"k6 metric is missing: {metric}")
        metric_data = cast(dict[str, Any], metric_data_value)
        values = metric_data.get("values")
        require(isinstance(values, dict) and isinstance(values.get(field), (int, float)), f"k6 metric is missing: {metric}.{field}")
        values = cast(dict[str, Any], values)
        return float(values[field])

    requests = int(value("http_reqs", "count"))
    dropped = int(value("dropped_iterations", "count"))
    failures = value("http_req_failed", "rate")
    checks = value("checks", "rate")
    p95 = value("http_req_duration", "p(95)")
    result: dict[str, float | int] = {
        "requests": requests,
        "dropped_iterations": dropped,
        "http_failure_rate": failures,
        "checks_rate": checks,
        "p95_ms": p95,
    }
    require(requests == document["expected_requests"], "k6 request count gate failed")
    require(dropped == 0, "k6 dropped-iteration gate failed")
    require(failures < document["thresholds"]["http_failure_rate_lt"], "k6 HTTP failure gate failed")
    require(checks >= document["thresholds"]["checks_rate_gte"], "k6 check gate failed")
    require(p95 < document["thresholds"]["p95_ms_lt"], "k6 p95 gate failed")
    return result


def summary_from_logs(logs: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, character in enumerate(logs):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(logs[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "metrics" in value:
            return value
    raise K6Error("k6 summary was not present in Job logs")


def write_evidence(path: Path, document: dict[str, Any]) -> None:
    require(not path.exists() and not path.is_symlink(), "refusing to overwrite k6 evidence")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not path.parent.is_symlink(), "k6 evidence directory is unsafe")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def main() -> int:
    try:
        contract()
        resources("20990101000000")
        print("validated k6 release-feed load contract (600 requests, 2 minutes)")
        return 0
    except (K6Error, OSError, ValueError) as error:
        print(f"WATCH k6 validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
