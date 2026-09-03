#!/usr/bin/env python3
"""Apply or verify the SUDO-owned Cosign public trust Secret."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from pathlib import Path

import sops_helpers
import validate_cosign_admission


ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / ".local/sudo/kubernetes/cosign/cosign-public.sops.json"
AGE_KEY = ROOT / ".local/sudo/kubernetes/cosign/age-key.txt"
KUBECONFIG = ROOT / ".local/ansible/kubeconfig/gcp.yaml"
NAMESPACE = "shell-trust"
SECRET_NAME = "cosign-public-keys"
SECRET_KEY = "cosign.pub"
APPROVAL = "environment-gcp/make/cosign-trust"
PUBLIC_KEY = re.compile(
    r"\A-----BEGIN PUBLIC KEY-----\r?\n.+?\r?\n-----END PUBLIC KEY-----\r?\n?\Z",
    re.DOTALL,
)


class CosignTrustError(RuntimeError):
    """The Cosign public trust handoff cannot be applied safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CosignTrustError(message)


def fixed_path(path: Path, expected: Path, label: str) -> Path:
    value = Path(os.path.abspath(path))
    target = Path(os.path.abspath(expected))
    require(value == target, f"{label} path changed")
    return target


def public_key(path: Path = INPUT, age_key: Path = AGE_KEY) -> str:
    document = sops_helpers.decrypt_json(path, age_key)
    require(set(document) == {"public_key"}, "Cosign public handoff shape changed")
    value = document["public_key"]
    require(isinstance(value, str) and PUBLIC_KEY.fullmatch(value) is not None, "Cosign public key is invalid")
    return value


def secret_manifest(value: str) -> str:
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": SECRET_NAME,
                "namespace": NAMESPACE,
                "labels": {
                    "app.kubernetes.io/part-of": "shell-platform",
                    "shell.platform/owner": "sudo",
                },
            },
            "type": "Opaque",
            "stringData": {SECRET_KEY: value},
        }
    ) + "\n"


def decode_existing(raw: str, expected: str) -> None:
    try:
        document = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise CosignTrustError("existing Cosign Secret is not JSON") from error
    require(isinstance(document, dict), "existing Cosign Secret is not an object")
    metadata = document.get("metadata")
    require(
        isinstance(metadata, dict)
        and metadata.get("name") == SECRET_NAME
        and metadata.get("namespace") == NAMESPACE,
        "existing Cosign Secret identity changed",
    )
    require(document.get("type") == "Opaque", "existing Cosign Secret type changed")
    data = document.get("data")
    require(isinstance(data, dict) and set(data) == {SECRET_KEY}, "existing Cosign Secret keys changed")
    encoded = data[SECRET_KEY]
    require(isinstance(encoded, str), "existing Cosign public key is invalid")
    try:
        observed = base64.b64decode(encoded, validate=True).decode("ascii")
    except (binascii.Error, UnicodeError) as error:
        raise CosignTrustError("existing Cosign public key is not base64 PEM") from error
    require(observed == expected, "existing Cosign public key differs; rotate explicitly")


def kubectl(kubeconfig: Path, *arguments: str) -> list[str]:
    return ["kubectl", "--kubeconfig", str(kubeconfig), *arguments]


def read_existing(kubeconfig: Path) -> str | None:
    output = sops_helpers.run(
        kubectl(
            kubeconfig,
            "get",
            "secret",
            SECRET_NAME,
            "--namespace",
            NAMESPACE,
            "--output",
            "json",
            "--ignore-not-found",
        ),
        label="Cosign trust Secret readback",
        environment=os.environ.copy(),
    )
    return output if output.strip() else None


def require_namespace(kubeconfig: Path) -> None:
    sops_helpers.run(
        kubectl(kubeconfig, "get", "namespace", NAMESPACE, "--output", "name"),
        label="Cosign trust namespace readback",
        environment=os.environ.copy(),
    )


def apply(kubeconfig: Path, value: str) -> None:
    require_namespace(kubeconfig)
    output = read_existing(kubeconfig)
    if output is not None:
        decode_existing(output, value)
    sops_helpers.run(
        kubectl(
            kubeconfig,
            "apply",
            "--server-side",
            "--field-manager=make-cosign-trust",
            "--filename",
            "-",
        ),
        label="Cosign trust Secret apply",
        environment=os.environ.copy(),
        input_text=secret_manifest(value),
    )
    readback = read_existing(kubeconfig)
    if readback is None:
        raise CosignTrustError("Cosign trust Secret was not returned after apply")
    decode_existing(readback, value)


def verify(kubeconfig: Path, value: str) -> None:
    require_namespace(kubeconfig)
    output = read_existing(kubeconfig)
    if output is None:
        raise CosignTrustError("Cosign trust Secret is missing")
    decode_existing(output, value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "apply", "verify"))
    parser.add_argument("--approval", default="")
    parser.add_argument("--input", type=Path, default=INPUT)
    parser.add_argument("--age-key", type=Path, default=AGE_KEY)
    parser.add_argument("--kubeconfig", type=Path, default=KUBECONFIG)
    args = parser.parse_args(argv)
    try:
        if args.action == "check":
            validate_cosign_admission.validate()
            print("validated Cosign trust source")
            return 0
        validate_cosign_admission.validate()
        if args.action == "apply":
            require(args.approval == APPROVAL, f"approval must be {APPROVAL}")
        input_path = fixed_path(args.input, INPUT, "Cosign public handoff")
        age_key = fixed_path(args.age_key, AGE_KEY, "Cosign age key")
        kubeconfig = fixed_path(args.kubeconfig, KUBECONFIG, "GCP kubeconfig")
        value = public_key(input_path, age_key)
        sops_helpers.private_file(kubeconfig, "GCP kubeconfig")
        if args.action == "apply":
            apply(kubeconfig, value)
            print("applied Cosign public trust Secret")
        else:
            verify(kubeconfig, value)
            print("verified Cosign public trust Secret")
        return 0
    except (
        OSError,
        CosignTrustError,
        sops_helpers.SopsError,
        validate_cosign_admission.CosignAdmissionError,
        validate_cosign_admission.access.AccessContractError,
        validate_cosign_admission.supply.SupplyError,
        validate_cosign_admission.validate_harbor_robots.HarborRobotError,
    ) as error:
        print(f"MAKE Cosign trust operation refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
