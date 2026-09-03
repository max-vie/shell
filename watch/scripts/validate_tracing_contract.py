#!/usr/bin/env python3
"""Validate WATCH's source-only Tempo and OpenTelemetry contract."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, cast

import yaml


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "watch/contracts/tracing-requirements.json"
TAR_SCRIPTS = ROOT / "tar/scripts"
if str(TAR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(TAR_SCRIPTS))
import validate_kubernetes_supply as supply  # noqa: E402


class TracingContractError(ValueError):
    """WATCH tracing source validation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TracingContractError(message)


def read_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"missing {label}")

    def reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TracingContractError(f"invalid {label}") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(dict[str, Any], value)


def read_yaml(path: Path, label: str) -> Any:
    require(path.is_file() and not path.is_symlink(), f"missing {label}")
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise TracingContractError(f"invalid {label}") from error


def validate_application(
    path: Path,
    name: str,
    chart: str,
    chart_version: str,
    value_file: str,
    platform_path: str | None = None,
) -> None:
    application = read_yaml(path, f"{name} Application")
    require(isinstance(application, dict), f"{name} Application is not a mapping")
    require(application.get("kind") == "Application", f"{name} kind changed")
    metadata = application.get("metadata", {})
    spec = application.get("spec", {})
    require(metadata.get("name") == name, f"{name} Application name changed")
    require(spec.get("project") == "shell-platform-services", f"{name} project changed")
    sources = spec.get("sources")
    require(isinstance(sources, list), f"{name} sources are missing")
    chart_source = next(
        (
            item
            for item in sources
            if isinstance(item, dict) and item.get("chart") == chart
        ),
        None,
    )
    require(isinstance(chart_source, dict), f"{name} chart source is missing")
    chart_source = cast(dict[str, Any], chart_source)
    require(
        chart_source.get("repoURL") == "registry.shell.internal/shell/charts"
        and chart_source.get("targetRevision") == chart_version,
        f"{name} chart source changed",
    )
    helm = chart_source.get("helm", {})
    require(
        isinstance(helm, dict)
        and helm.get("valueFiles") == [f"$values/{value_file}"],
        f"{name} value handoff changed",
    )
    require(
        any(
            isinstance(item, dict)
            and item.get("repoURL") == "https://forgejo.shell.internal/shell/make.git"
            and item.get("ref") == "values"
            for item in sources
        ),
        f"{name} values source is missing",
    )
    if platform_path is not None:
        require(
            any(
                isinstance(item, dict)
                and item.get("repoURL")
                == "https://forgejo.shell.internal/shell/make.git"
                and item.get("path") == platform_path
                for item in sources
            ),
            f"{name} platform source is missing",
        )
    destination = spec.get("destination", {})
    require(
        destination == {
            "server": "https://kubernetes.default.svc",
            "namespace": "monitoring",
        },
        f"{name} destination changed",
    )
    sync_policy = spec.get("syncPolicy", {})
    require(
        sync_policy.get("automated") == {"prune": False, "selfHeal": True},
        f"{name} automation changed",
    )
    require(
        sync_policy.get("syncOptions") == ["ServerSideApply=true", "CreateNamespace=true"],
        f"{name} sync options changed",
    )


def validate_values(lock: dict[str, Any], document: dict[str, Any]) -> None:
    tempo = document["tempo"]
    tempo_values = read_yaml(ROOT / "make/gitops/values/tempo.yaml", "Tempo values")
    require(isinstance(tempo_values, dict), "Tempo values must be a mapping")
    require(
        tempo_values.get("fullnameOverride") == "tempo"
        and tempo_values.get("replicas") == 1
        and tempo_values["tempo"]["tag"]
        == "2.9.0@" + lock["images"]["docker.io/grafana/tempo:2.9.0"]["digest"],
        "Tempo identity or image pin changed",
    )
    tempo_config = yaml.safe_load(tempo_values["config"])
    require(
        isinstance(tempo_config, dict)
        and set(tempo_config["distributor"]["receivers"]) == {"otlp"}
        and tempo_config["storage"]["trace"]
        == {
            "backend": "local",
            "local": {"path": "/var/tempo/traces"},
            "wal": {"path": "/var/tempo/wal"},
        },
        "Tempo receiver or storage configuration changed",
    )
    require(
        tempo_values["tempo"]["retention"] == tempo["retention"]
        and tempo_values["persistence"]
        == {
            "enabled": True,
            "storageClassName": "longhorn",
            "accessModes": ["ReadWriteOnce"],
            "size": "2Gi",
        }
        and tempo_values["tempoQuery"]["enabled"] is False
        and tempo_values["service"]["type"] == "ClusterIP"
        and tempo_values["serviceAccount"]["automountServiceAccountToken"] is False
        and tempo_values["networkPolicy"]["enabled"] is False,
        "Tempo storage or access boundary changed",
    )

    collector = document["collector"]
    otel_values = read_yaml(
        ROOT / "make/gitops/values/otel.yaml", "OpenTelemetry values"
    )
    require(isinstance(otel_values, dict), "OpenTelemetry values must be a mapping")
    image = otel_values["image"]
    require(
        otel_values.get("fullnameOverride") == "shell-otel"
        and otel_values.get("mode") == "deployment"
        and otel_values.get("replicaCount") == 1
        and image
        == {
            "repository": "otel/opentelemetry-collector-contrib",
            "tag": "0.159.0",
            "digest": lock["images"]["otel/opentelemetry-collector-contrib:0.159.0"]["digest"],
            "pullPolicy": "IfNotPresent",
        },
        "OpenTelemetry identity or image pin changed",
    )
    config = otel_values["alternateConfig"]
    require(
        set(config["receivers"]) == {"otlp"}
        and set(config["service"]["pipelines"]) == {"traces", "metrics"}
        and config["exporters"]["otlphttp/tempo"]["endpoint"]
        == collector["trace_export_endpoint"]
        and config["exporters"]["prometheus"]["endpoint"] == "0.0.0.0:8889",
        "OpenTelemetry pipeline changed",
    )
    ports = otel_values["ports"]
    require(
        ports["otlp"]["servicePort"] == collector["otlp_ports"]["grpc"]
        and ports["otlp-http"]["servicePort"] == collector["otlp_ports"]["http"]
        and ports["metrics"]["servicePort"] == collector["metrics_port"]
        and all(not ports[name]["enabled"] for name in ("jaeger-compact", "jaeger-thrift", "jaeger-grpc", "zipkin"))
        and otel_values["service"]["type"] == "ClusterIP"
        and otel_values["ingress"]["enabled"] is False
        and otel_values["httproute"]["enabled"] is False
        and otel_values["serviceAccount"]["automountServiceAccountToken"] is False
        and otel_values["networkPolicy"]["enabled"] is True,
        "OpenTelemetry access boundary changed",
    )


def validate_platform_policy() -> None:
    source = read_yaml(ROOT / "make/gitops/platform/tempo/networkpolicy.yaml", "Tempo network policy")
    require(
        isinstance(source, dict)
        and source.get("kind") == "NetworkPolicy"
        and source.get("metadata", {}).get("name") == "tempo-default-deny"
        and source.get("spec", {}).get("policyTypes") == ["Ingress", "Egress"],
        "Tempo network policy identity changed",
    )
    spec = cast(dict[str, Any], source["spec"])
    ingress = cast(list[dict[str, Any]], spec["ingress"])
    require(len(ingress) == 2, "Tempo ingress rules changed")
    require({item.get("port") for item in ingress[0]["ports"]} == {4317, 4318}, "Tempo collector ingress ports changed")
    require({item.get("port") for item in ingress[1]["ports"]} == {3200}, "Tempo query ingress port changed")
    egress = cast(dict[str, Any], spec["egress"][0])
    require({item.get("port") for item in egress["ports"]} == {53}, "Tempo DNS egress changed")


def validate_contract(
    path: Path = CONTRACT, repository_root: Path = ROOT
) -> dict[str, Any]:
    document = read_json(path, "WATCH tracing contract")
    require(
        set(document)
        == {
            "description",
            "schema_version",
            "contract_version",
            "contract_id",
            "policy_owner",
            "producer_owners",
            "consumer_owners",
            "proof_status",
            "environment",
            "cluster",
            "source_contracts",
            "tempo",
            "collector",
            "evidence",
            "excluded_fields",
            "failure_policy",
        },
        "WATCH tracing contract shape changed",
    )
    require(
        document["schema_version"] == "1.0"
        and document["contract_version"] == "1.0.0"
        and document["contract_id"] == "tracing-requirements",
        "WATCH tracing identity changed",
    )
    require(
        document["policy_owner"] == "watch"
        and document["producer_owners"] == ["tar", "make"]
        and document["consumer_owners"] == ["make", "watch"]
        and document["proof_status"] == "source-only"
        and document["environment"] == "environment-gcp",
        "WATCH tracing ownership changed",
    )
    require(
        document["cluster"]
        == {
            "name": "gcp",
            "inventory_group": "gcp_k3s_servers",
            "first_server": "gcp-k3s-01",
            "first_server_address": "10.77.0.201",
            "nodes": ["gcp-k3s-01", "gcp-k3s-02", "gcp-k3s-03"],
        },
        "WATCH tracing cluster changed",
    )
    require(
        document["source_contracts"]
        == {
            "supply": "tar/manifests/kubernetes-ecosystem-supply.json",
            "tempo_application": "make/gitops/applications/children/tempo.yaml",
            "tempo_values": "make/gitops/values/tempo.yaml",
            "otel_application": "make/gitops/applications/children/otel.yaml",
            "otel_values": "make/gitops/values/otel.yaml",
        },
        "WATCH tracing source contracts changed",
    )
    require(
        document["tempo"]
        == {
            "application": "watch-tempo",
            "release": "tempo",
            "namespace": "monitoring",
            "chart": "tempo",
            "chart_version": "1.24.4",
            "statefulset": "tempo",
            "service": "tempo",
            "replicas": 1,
            "service_type": "ClusterIP",
            "query_port": 3200,
            "otlp_ports": {"grpc": 4317, "http": 4318},
            "image": "docker.io/grafana/tempo:2.9.0",
            "storage": {"class": "longhorn", "size": "2Gi", "backend": "local"},
            "retention": "24h",
            "public_route": False,
        },
        "WATCH Tempo policy changed",
    )
    require(
        document["collector"]
        == {
            "application": "watch-opentelemetry",
            "release": "shell-otel",
            "namespace": "monitoring",
            "chart": "opentelemetry-collector",
            "chart_version": "0.165.0",
            "deployment": "shell-otel",
            "service": "shell-otel",
            "replicas": 1,
            "service_type": "ClusterIP",
            "otlp_ports": {"grpc": 4317, "http": 4318},
            "metrics_port": 8889,
            "image": "otel/opentelemetry-collector-contrib:0.159.0",
            "trace_export_endpoint": "http://tempo.monitoring.svc.cluster.local:4318",
            "metrics_export": "prometheus:8889",
            "host_access": False,
            "cluster_rbac": False,
            "persistent_storage": False,
        },
        "WATCH OpenTelemetry policy changed",
    )
    require(
        document["evidence"]
        == [
            "Tempo StatefulSet has one ready replica and a bound Longhorn claim",
            "OpenTelemetry Deployment has one ready replica",
            "Tempo and the collector expose only cluster-local service paths",
            "Tempo readiness responds through an operator port-forward",
        ]
        and document["failure_policy"] == "read-only-diagnosis",
        "WATCH tracing evidence changed",
    )
    require(
        document["excluded_fields"]
        == [
            "instrumented_application_trace",
            "trace_search_result",
            "live_pod_logs",
            "credentials",
            "public_ingress",
        ],
        "WATCH tracing exclusions changed",
    )

    repository_root = repository_root.resolve()
    lock = supply.validate_public(repository_root / "tar/manifests/kubernetes-ecosystem-supply.json")
    require(lock["charts"]["tempo"]["version"] == document["tempo"]["chart_version"], "Tempo chart pin changed")
    require(lock["charts"]["opentelemetry-collector"]["version"] == document["collector"]["chart_version"], "OpenTelemetry chart pin changed")
    require("docker.io/grafana/tempo:2.9.0" in lock["images"], "Tempo image pin is missing")
    require("otel/opentelemetry-collector-contrib:0.159.0" in lock["images"], "OpenTelemetry image pin is missing")
    validate_application(
        repository_root / "make/gitops/applications/children/tempo.yaml",
        "watch-tempo",
        "tempo",
        "1.24.4",
        "gitops/values/tempo.yaml",
        "gitops/platform/tempo",
    )
    validate_application(
        repository_root / "make/gitops/applications/children/otel.yaml",
        "watch-opentelemetry",
        "opentelemetry-collector",
        "0.165.0",
        "gitops/values/otel.yaml",
    )
    validate_values(lock, document)
    validate_platform_policy()
    return document


def main() -> int:
    try:
        validate_contract()
        print("validated WATCH tracing contract")
        return 0
    except (OSError, TracingContractError, supply.SupplyError) as error:
        print(f"WATCH tracing validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
