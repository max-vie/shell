#!/usr/bin/env python3
"""Validate the public TAR supply for the Kubernetes ecosystem slices."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = REPOSITORY_ROOT / "tar/manifests/kubernetes-ecosystem-supply.json"
DEFAULT_LOCAL_ROOT = REPOSITORY_ROOT / ".local/tar/kubernetes"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
EXPECTED_CHARTS = {
    "cert-manager": {
        "repository": "https://charts.jetstack.io",
        "name": "cert-manager",
        "version": "v1.21.0",
        "source": "https://charts.jetstack.io/charts/cert-manager-v1.21.0.tgz",
        "sha256": "9c2c6fabf3cf8fe14dacb016f37c819b66bc2c79e8b7acde4573d45ec141fb97",
        "size": 153302,
        "max_bytes": 16777216,
        "redirect_hosts": [],
    },
    "kyverno": {
        "repository": "https://kyverno.github.io/kyverno/",
        "name": "kyverno",
        "version": "3.8.2",
        "source": "https://kyverno.github.io/kyverno/kyverno-3.8.2.tgz",
        "sha256": "f4fc787cf1d6781eefb9e9b45837edcddcfae984c872888289914e97207cc5de",
        "size": 719383,
        "max_bytes": 16777216,
        "redirect_hosts": [],
    },
    "velero": {
        "repository": "https://vmware-tanzu.github.io/helm-charts",
        "name": "velero",
        "version": "12.1.0",
        "source": "https://github.com/vmware-tanzu/helm-charts/releases/download/velero-12.1.0/velero-12.1.0.tgz",
        "sha256": "cd23589ad1b2d25cdd3220f6866b3f6f4c5683c4c09494e76a14700b33f81f83",
        "size": 42489,
        "max_bytes": 16777216,
        "redirect_hosts": ["github.com", "release-assets.githubusercontent.com"],
    },
    "tempo": {
        "repository": "https://grafana.github.io/helm-charts",
        "name": "tempo",
        "version": "1.24.4",
        "source": "https://github.com/grafana/helm-charts/releases/download/tempo-1.24.4/tempo-1.24.4.tgz",
        "sha256": "f1f6e318d5bca3b5097cb676077796cdf8135beb2c1f71c4d14614ccf9b0081b",
        "size": 13508,
        "max_bytes": 16777216,
        "redirect_hosts": ["github.com", "release-assets.githubusercontent.com"],
    },
    "opentelemetry-collector": {
        "repository": "https://open-telemetry.github.io/opentelemetry-helm-charts",
        "name": "opentelemetry-collector",
        "version": "0.165.0",
        "source": "https://github.com/open-telemetry/opentelemetry-helm-charts/releases/download/opentelemetry-collector-0.165.0/opentelemetry-collector-0.165.0.tgz",
        "sha256": "b592ea064d9b906930cac2d22b88eeb1bc82f12d5ed07fd20792de2c051ca3c5",
        "size": 39531,
        "max_bytes": 16777216,
        "redirect_hosts": ["github.com", "release-assets.githubusercontent.com"],
    },
}
EXPECTED_IMAGES = {
    "quay.io/jetstack/cert-manager-controller:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-controller",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:e370f7800a53078e9d74324287a7d52b553864e55f5b4e521f911c3f6c7da203",
    },
    "quay.io/jetstack/cert-manager-webhook:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-webhook",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:c33cca307541e2d58861a55b1af5f390b7e19c8741e48b433693b73a7cce88b3",
    },
    "quay.io/jetstack/cert-manager-cainjector:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-cainjector",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:ad1dcc5b2fccc420f9b3fbee7ce8a869450c540fd4f2f41de2d95b1ca0c4d701",
    },
    "quay.io/jetstack/cert-manager-startupapicheck:v1.21.0": {
        "repository": "quay.io/jetstack/cert-manager-startupapicheck",
        "tag": "v1.21.0",
        "platform": "linux/amd64",
        "digest": "sha256:68b3c5029dc63e64a6b6435337d7dc0eb169f889a48a02d999d1f22f31865b33",
    },
    "reg.kyverno.io/kyverno/kyverno:v1.18.2": {
        "repository": "reg.kyverno.io/kyverno/kyverno",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:0a540e2ddf74d0d2d3d45f9ef248d7dbc96576accdbcc6a2dd7eaff9fea56504",
    },
    "reg.kyverno.io/kyverno/kyvernopre:v1.18.2": {
        "repository": "reg.kyverno.io/kyverno/kyvernopre",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:cd8cb4a31d25b3992734fb8f24a90ef691c90ce49338c89bea96792160eacb98",
    },
    "reg.kyverno.io/kyverno/background-controller:v1.18.2": {
        "repository": "reg.kyverno.io/kyverno/background-controller",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:d62566ce41bd0d4a32bf2cf44b9ebfc02c36374f821f83070890287f62f68671",
    },
    "reg.kyverno.io/kyverno/cleanup-controller:v1.18.2": {
        "repository": "reg.kyverno.io/kyverno/cleanup-controller",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:b0395d29ae332276e6910eb40418be9bc127c068d659f90aa1bcddd6be99ccb4",
    },
    "reg.kyverno.io/kyverno/reports-controller:v1.18.2": {
        "repository": "reg.kyverno.io/kyverno/reports-controller",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:f09cf305170014e191b94e1c54f5be73163d8824eefad49349675c4efe43159a",
    },
    "ghcr.io/kyverno/readiness-checker:v1.18.2": {
        "repository": "ghcr.io/kyverno/readiness-checker",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:4fb1870b1a4adfed0fa7a32b7c3bcaf736fb889c7e1947ee8b20710bc2f5a5ce",
    },
    "docker.io/velero/velero:v1.18.2": {
        "repository": "docker.io/velero/velero",
        "tag": "v1.18.2",
        "platform": "linux/amd64",
        "digest": "sha256:37396519f399536e5f01427d723565ae69294ec3fb5625cf1c87c09eaa9de16b",
    },
    "docker.io/velero/velero-plugin-for-gcp:v1.14.2": {
        "repository": "docker.io/velero/velero-plugin-for-gcp",
        "tag": "v1.14.2",
        "platform": "linux/amd64",
        "digest": "sha256:f4c0b7d1e69f7dbc721e2dc7eca20a9720d06f7c5e021ccc3cd57df6bb505f7b",
    },
    "registry.k8s.io/sig-storage/snapshot-controller:v8.6.0": {
        "repository": "registry.k8s.io/sig-storage/snapshot-controller",
        "tag": "v8.6.0",
        "platform": "linux/amd64",
        "digest": "sha256:81e79f205083f105e573ba2ebfe5964ede7f69a154e8627f53ebbbccd3ed9f70",
    },
    "docker.io/grafana/tempo:2.9.0": {
        "repository": "docker.io/grafana/tempo",
        "tag": "2.9.0",
        "platform": "linux/amd64",
        "digest": "sha256:65a5789759435f1ef696f1953258b9bbdb18eb571d5ce711ff812d2e128288a4",
    },
    "otel/opentelemetry-collector-contrib:0.159.0": {
        "repository": "otel/opentelemetry-collector-contrib",
        "tag": "0.159.0",
        "platform": "linux/amd64",
        "digest": "sha256:1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc",
    },
    "docker.io/aquasec/trivy:0.73.0": {
        "repository": "docker.io/aquasec/trivy",
        "tag": "0.73.0",
        "platform": "linux/amd64",
        "digest": "sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c",
    },
    "docker.io/aquasec/kube-bench:v0.16.0": {
        "repository": "docker.io/aquasec/kube-bench",
        "tag": "v0.16.0",
        "platform": "linux/amd64",
        "digest": "sha256:75506f222d1eb6ce2a751a5533bdc0a3b54c898e2e49e7751d0ee22cfb862679",
    },
    "docker.io/grafana/k6:2.1.0": {
        "repository": "docker.io/grafana/k6",
        "tag": "2.1.0",
        "platform": "linux/amd64",
        "digest": "sha256:65c920dc067d5e2e00befbf982af6ad6ad0117034e8b1c65817c7975c52d4669",
    },
}
EXPECTED_TOOLS = {
    "cosign": {
        "version": "2.6.4",
        "platform": "linux/amd64",
        "source": "https://github.com/sigstore/cosign/releases/download/v2.6.4/cosign-linux-amd64",
        "source_sha256": "309779b0c4e409186b0a80daba99041fe2cf65a920ce645013901df6211895a9",
        "size": 137225408,
        "max_bytes": 268435456,
        "file_name": "cosign",
        "mode": "0700",
        "redirect_hosts": ["github.com", "release-assets.githubusercontent.com"],
    },
    "trivy": {"version": "0.73.0", "image": "docker.io/aquasec/trivy:0.73.0"},
    "kube-bench": {
        "version": "0.16.0",
        "image": "docker.io/aquasec/kube-bench:v0.16.0",
    },
    "k6": {"version": "2.1.0", "image": "docker.io/grafana/k6:2.1.0"},
    "skopeo": {
        "version": "1.22.2",
        "binary": "skopeo",
        "execution_host": "delivery-01",
        "authfile_mode": "0600",
        "preserve_digests": True,
    },
}


class SupplyError(ValueError):
    """The public Kubernetes supply contract is invalid or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupplyError(message)


def _check_no_symlink_components(path: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        require(not current.is_symlink(), f"unsafe symlinked {label}: {current}")
    return path


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path, label: str) -> dict[str, Any]:
    path = _check_no_symlink_components(path, label)
    require(path.is_file() and not path.is_symlink(), f"missing regular {label}: {path}")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SupplyError(f"invalid JSON for {label}: {path}") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def validate_public(path: Path = LOCK_PATH) -> dict[str, Any]:
    lock = read_json(path, "Kubernetes supply lock")
    require(
        set(lock)
        == {
            "schema_version",
            "contract_version",
            "contract_id",
            "description",
            "policy_owner",
            "execution_owner",
            "proof_status",
            "staging",
            "charts",
            "images",
            "tools",
        },
        "Kubernetes supply lock shape changed",
    )
    require(lock["schema_version"] == "1.0", "Kubernetes supply schema changed")
    require(lock["contract_version"] == "1.0.0", "Kubernetes supply version changed")
    require(lock["contract_id"] == "kubernetes-ecosystem-supply", "Kubernetes supply ID changed")
    require(lock["policy_owner"] == "tar", "TAR must own Kubernetes supply")
    require(lock["execution_owner"] == "make", "MAKE must consume Kubernetes supply")
    require(lock["proof_status"] == "source-reference-only", "Kubernetes supply proof changed")
    require(
        lock["staging"]
        == {
            "mode": "local-verified-artifacts",
            "network_acquisition_owner": "tar",
            "consumer_network_acquisition": False,
            "artifact_directory": "kubernetes",
            "chart_cache_layout": "charts/{name}-{version}.tgz",
        },
        "Kubernetes staging policy changed",
    )
    charts = lock["charts"]
    require(isinstance(charts, dict) and charts == EXPECTED_CHARTS, "Kubernetes chart pins changed")
    for name, chart in charts.items():
        source = urlsplit(chart["source"])
        repository = urlsplit(chart["repository"])
        require(
            source.scheme == "https"
            and repository.scheme == "https"
            and source.netloc in {repository.netloc, *chart["redirect_hosts"]}
            and source.path.endswith(f"/{chart['name']}-{chart['version']}.tgz"),
            f"{name} source must remain the official HTTPS archive",
        )
        require(SHA256_PATTERN.fullmatch(chart["sha256"]) is not None, f"{name} chart checksum is invalid")
        require(
            isinstance(chart["size"], int)
            and isinstance(chart["max_bytes"], int)
            and chart["size"] > 0
            and chart["size"] <= chart["max_bytes"] <= 64 * 1024 * 1024
            and isinstance(chart["redirect_hosts"], list)
            and all(isinstance(host, str) and host for host in chart["redirect_hosts"]),
            f"{name} chart size policy changed",
        )
    images = lock["images"]
    require(images == EXPECTED_IMAGES, "Kubernetes image pins changed")
    for image, details in images.items():
        require(
            isinstance(details, dict)
            and set(details) == {"repository", "tag", "platform", "digest"},
            f"Kubernetes image shape changed: {image}",
        )
        require(details["platform"] == "linux/amd64", f"Kubernetes image platform changed: {image}")
        require(
            IMAGE_DIGEST_PATTERN.fullmatch(details["digest"]) is not None,
            f"Kubernetes image digest is invalid: {image}",
        )
    require(lock["tools"] == EXPECTED_TOOLS, "Kubernetes tool pins changed")
    tool = lock["tools"]["cosign"]
    source = urlsplit(tool["source"])
    require(
        source.scheme == "https"
        and source.netloc == "github.com"
        and source.path.endswith("/sigstore/cosign/releases/download/v2.6.4/cosign-linux-amd64"),
        "Cosign source must remain the official HTTPS release",
    )
    require(SHA256_PATTERN.fullmatch(tool["source_sha256"]) is not None, "Cosign checksum is invalid")
    require(tool["redirect_hosts"] == ["github.com", "release-assets.githubusercontent.com"], "Cosign redirect policy changed")
    return lock


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_staged(local_root: Path = DEFAULT_LOCAL_ROOT) -> Path:
    lock = validate_public()
    local_root = _check_no_symlink_components(local_root, "Kubernetes local root")
    require(local_root.is_dir() and not local_root.is_symlink(), "Kubernetes local root must be a directory")
    require(local_root.stat().st_mode & 0o077 == 0, "Kubernetes local root must be private")
    chart_root = _check_no_symlink_components(local_root / "charts", "Kubernetes chart directory")
    require(chart_root.is_dir() and not chart_root.is_symlink(), "Kubernetes chart directory is missing")
    require(
        stat.S_IMODE(chart_root.stat().st_mode) == 0o700,
        "Kubernetes chart directory must be mode 0700",
    )
    staged: Path | None = None
    for name, chart in lock["charts"].items():
        path = _check_no_symlink_components(
            chart_root / f"{chart['name']}-{chart['version']}.tgz",
            f"staged {name} chart",
        )
        require(path.is_file() and not path.is_symlink(), f"staged {name} chart is missing")
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, f"staged {name} chart must be mode 0600")
        require(path.stat().st_size == chart["size"], f"staged {name} chart size changed")
        require(sha256_file(path) == chart["sha256"], f"staged {name} chart checksum changed")
        if name == "cert-manager":
            staged = path
    tool = lock["tools"]["cosign"]
    cosign = _check_no_symlink_components(local_root / "tools" / tool["file_name"], "staged Cosign binary")
    require(cosign.is_file() and not cosign.is_symlink(), "staged Cosign binary is missing")
    require(stat.S_IMODE(cosign.stat().st_mode) == int(tool["mode"], 8), "staged Cosign binary mode changed")
    require(cosign.stat().st_size == tool["size"], "staged Cosign binary size changed")
    require(sha256_file(cosign) == tool["source_sha256"], "staged Cosign binary checksum changed")
    require(staged is not None, "Kubernetes charts are missing")
    return cast(Path, staged)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-root", type=Path)
    args = parser.parse_args(argv)
    try:
        validate_public()
        if args.staged_root is not None:
            validate_staged(args.staged_root)
    except (OSError, SupplyError) as error:
        print(f"Kubernetes supply validation failed: {error}", file=sys.stderr)
        return 2
    print("validated Kubernetes and admission supply contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
