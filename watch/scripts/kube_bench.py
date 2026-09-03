#!/usr/bin/env python3
"""Build and parse the WATCH kube-bench audit without applying resources."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "watch/contracts/kube-bench-requirements.json"
TAR_SCRIPTS = ROOT / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import validate_security_tooling as security_supply  # noqa: E402


RUN_ID = re.compile(r"^[0-9]{14}$")
EXPECTED_HOST_PATHS = {
    "/var/lib/cni",
    "/var/lib/kubelet",
    "/var/lib/rancher",
    "/etc/systemd",
    "/lib/systemd",
    "/usr/bin",
    "/etc/cni/net.d",
    "/opt/cni/bin",
}


class KubeBenchError(RuntimeError):
    """The kube-bench audit contract failed closed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KubeBenchError(message)


def _read_json(path: Path) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), "kube-bench contract is missing")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise KubeBenchError("kube-bench contract is invalid JSON") from error
    require(isinstance(value, dict), "kube-bench contract is not an object")
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
            "benchmark",
            "image",
            "host_pid",
            "privileged",
            "host_paths",
            "resources",
            "gate",
            "excluded_fields",
        },
        "kube-bench contract shape changed",
    )
    require(
        document["schema_version"] == "1.0"
        and document["contract_version"] == "1.0.0"
        and document["contract_id"] == "kube-bench-requirements",
        "kube-bench contract identity changed",
    )
    require(
        document["policy_owner"] == "watch"
        and document["execution_owner"] == "make"
        and document["consumer_owners"] == ["make", "watch"]
        and document["proof_status"] == "source-only"
        and document["environment"] == "environment-gcp",
        "kube-bench ownership changed",
    )
    require(
        document["namespace"] == "shell-security"
        and document["approval"] == "environment-gcp/make/kube-bench"
        and document["benchmark"] == "k3s-cis-1.9"
        and document["host_pid"] is True
        and document["privileged"] is False
        and set(document["host_paths"]) == EXPECTED_HOST_PATHS,
        "kube-bench audit boundary changed",
    )
    require(document["gate"] == {"max_fail": 0, "max_warn": 0}, "kube-bench gate changed")
    lock = security_supply.validate()
    image = lock["images"]["docker.io/aquasec/kube-bench:v0.16.0"]
    expected_image = f"docker.io/aquasec/kube-bench:v0.16.0@{image['digest']}"
    require(document["image"] == expected_image, "kube-bench image pin changed")
    return document


def resources(run_id: str) -> list[dict[str, Any]]:
    document = contract()
    require(RUN_ID.fullmatch(run_id) is not None, "kube-bench run ID is malformed")
    namespace = document["namespace"]
    labels = {"app.kubernetes.io/name": "kube-bench", "shell.platform/run-id": run_id}
    mounts = [
        ("var-lib-cni", "/var/lib/cni", "/var/lib/cni"),
        ("var-lib-kubelet", "/var/lib/kubelet", "/var/lib/kubelet"),
        ("var-lib-rancher", "/var/lib/rancher", "/var/lib/rancher"),
        ("etc-systemd", "/etc/systemd", "/etc/systemd"),
        ("lib-systemd", "/lib/systemd", "/lib/systemd"),
        ("usr-bin", "/usr/bin", "/usr/local/mount-from-host/bin"),
        ("etc-cni-netd", "/etc/cni/net.d", "/etc/cni/net.d"),
        ("opt-cni-bin", "/opt/cni/bin", "/opt/cni/bin"),
    ]
    return [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": namespace,
                "labels": {
                    "app.kubernetes.io/part-of": "shell-platform",
                    "shell.platform/owner": "watch",
                    "shell.platform/security-exception": "host-inspection",
                    "pod-security.kubernetes.io/enforce": "privileged",
                    "pod-security.kubernetes.io/audit": "privileged",
                    "pod-security.kubernetes.io/warn": "privileged",
                },
            },
        },
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "shell-kube-bench", "namespace": namespace, "labels": labels},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": f"shell-kube-bench-default-deny-{run_id}", "namespace": namespace, "labels": labels},
            "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"]},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": f"shell-kube-bench-{run_id}", "namespace": namespace, "labels": labels},
            "spec": {
                "selector": {"matchLabels": labels},
                "updateStrategy": {"type": "OnDelete"},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "serviceAccountName": "shell-kube-bench",
                        "automountServiceAccountToken": False,
                        "hostPID": True,
                        "restartPolicy": "Always",
                        "nodeSelector": {"kubernetes.io/os": "linux"},
                        "tolerations": [{"operator": "Exists"}],
                        "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [
                            {
                                "name": "kube-bench",
                                "image": document["image"],
                                "command": ["/bin/sh", "-ec"],
                                "args": [
                                    f"kube-bench run --benchmark {document['benchmark']} --json; "
                                    "status=$?; printf '__SHELL_KUBE_BENCH_DONE__\\n'; "
                                    "sleep 86400; exit $status"
                                ],
                                "resources": document["resources"],
                                "securityContext": {
                                    "runAsUser": 0,
                                    "runAsGroup": 0,
                                    "runAsNonRoot": False,
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                    "readOnlyRootFilesystem": True,
                                },
                                "volumeMounts": [
                                    {"name": name, "mountPath": mount_path, "readOnly": True}
                                    for name, _, mount_path in mounts
                                ]
                                + [{"name": "tmp", "mountPath": "/tmp"}],
                            }
                        ],
                        "volumes": [
                            {"name": name, "hostPath": {"path": host_path, "type": "Directory"}}
                            for name, host_path, _ in mounts
                        ]
                        + [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
                    },
                },
            },
        },
    ]


def parse_report(text: str) -> dict[str, int]:
    decoder = json.JSONDecoder()
    report: dict[str, Any] | None = None
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            candidate, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and ("Controls" in candidate or "controls" in candidate):
            report = candidate
            break
    require(report is not None, "kube-bench did not emit JSON")
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "INFO": 0, "NOT_APPLICABLE": 0, "MANUAL": 0}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            status = value.get("status")
            if isinstance(status, str) and status.upper() in counts:
                counts[status.upper()] += 1
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(report)
    require(sum(counts.values()) > 0, "kube-bench JSON contained no check results")
    return counts


def write_evidence(path: Path, document: dict[str, Any]) -> None:
    require(not path.exists() and not path.is_symlink(), "refusing to overwrite kube-bench evidence")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not path.parent.is_symlink(), "kube-bench evidence directory is unsafe")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def main() -> int:
    try:
        contract()
        resources("20990101000000")
        print("validated kube-bench K3s audit contract")
        return 0
    except (KubeBenchError, OSError, ValueError) as error:
        print(f"WATCH kube-bench validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
