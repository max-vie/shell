# TAR owns verified charts, images, staging policy, and publication handoffs.
PYTHON ?= python3
WATCH_VALIDATOR := scripts/validate_watch.py
WATCH_LOGS_VALIDATOR := scripts/validate_watch_logs.py
WATCH_LOGS_STAGER := scripts/stage_watch_logs.py
WATCH_LOGS_LOCAL_ROOT ?= ../.local/tar/watch
PLATFORM_VALIDATOR := scripts/validate_platform_supply.py
RELEASE_FEED_VALIDATOR := scripts/validate_release_feed.py
PLATFORM_STAGER := scripts/stage_platform.py
INIT_NETWORK_VALIDATOR := scripts/validate_init_k3s_network_supply.py
INIT_NETWORK_STAGER := scripts/stage_init_k3s_network_supply.py
FREEIPA_VALIDATOR := scripts/validate_freeipa_supply.py
KEYCLOAK_VALIDATOR := scripts/validate_keycloak_supply.py
KUBERNETES_VALIDATOR := scripts/validate_kubernetes_supply.py
KUBERNETES_STAGER := scripts/stage_kubernetes_supply.py
KUBERNETES_LOCAL_ROOT ?= ../.local/tar/kubernetes
SECURITY_VALIDATOR := scripts/validate_security_tooling.py
TRIVY_SCRIPT := scripts/run_trivy_scan.py
SKOPEO_SCRIPT := scripts/publish_kubernetes_images.py
TRIVY ?= trivy
TRIVY_IMAGE ?=
TRIVY_REPORT ?=
TRIVY_CACHE ?=
SKOPEO_SOURCE ?=
SKOPEO_DESTINATION ?=
SKOPEO_APPROVAL := environment-gcp/tar/skopeo-transfer
PLATFORM_CHART_PUBLISHER := scripts/publish_platform_charts.py
PLATFORM_IMAGE_PUBLISHER := scripts/publish_platform_images.py
PLATFORM_LOCAL_ROOT ?= ../.local/tar/platform-addons
INIT_HELM_BINARY ?=
INIT_CILIUM_CHART ?=
INVENTORY ?= ../.local/ansible/inventory.json
CONNECTION_INVENTORY ?= ../.local/ansible/connection-inventory.yml

.PHONY: check test check-watch-supply check-watch-logs-supply check-platform-supply check-init-network-supply check-freeipa-supply check-keycloak-supply check-kubernetes-supply check-security-tooling check-release-feed-supply stage-watch-logs stage-platform stage-platform-addons stage-init-k3s-network stage-kubernetes trivy-scan skopeo-check skopeo-preview skopeo-transfer publish-platform-charts publish-platform-images publish-release-feed

check: test check-platform-supply check-init-network-supply check-freeipa-supply check-keycloak-supply check-kubernetes-supply check-security-tooling check-release-feed-supply

test: check-watch-supply check-watch-logs-supply
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

check-watch-supply:
	$(PYTHON) $(WATCH_VALIDATOR)

check-watch-logs-supply:
	$(PYTHON) $(WATCH_LOGS_VALIDATOR)

check-platform-supply:
	$(PYTHON) $(PLATFORM_VALIDATOR)
	$(PYTHON) scripts/validate_harbor.py

check-release-feed-supply:
	$(PYTHON) $(RELEASE_FEED_VALIDATOR)

stage-watch-logs: check-watch-logs-supply
	$(PYTHON) $(WATCH_LOGS_STAGER) --local-root "$(WATCH_LOGS_LOCAL_ROOT)"

stage-platform-addons: check-platform-supply
	$(PYTHON) $(PLATFORM_STAGER) --local-root "$(PLATFORM_LOCAL_ROOT)"

stage-platform: stage-platform-addons

check-init-network-supply:
	$(PYTHON) $(INIT_NETWORK_VALIDATOR)

check-freeipa-supply:
	$(PYTHON) $(FREEIPA_VALIDATOR)

check-keycloak-supply:
	$(PYTHON) $(KEYCLOAK_VALIDATOR)

check-kubernetes-supply:
	$(PYTHON) $(KUBERNETES_VALIDATOR)

check-security-tooling:
	$(PYTHON) $(SECURITY_VALIDATOR)
	$(PYTHON) -m unittest tests/test_security_tooling.py tests/test_skopeo_transfer.py

stage-init-k3s-network: check-init-network-supply
	$(PYTHON) $(INIT_NETWORK_STAGER) --helm-binary "$(INIT_HELM_BINARY)" --cilium-chart "$(INIT_CILIUM_CHART)"

stage-kubernetes: check-kubernetes-supply
	$(PYTHON) $(KUBERNETES_STAGER) --local-root "$(KUBERNETES_LOCAL_ROOT)"

trivy-scan: check-security-tooling
	@test -n "$(TRIVY_IMAGE)" || { printf '%s\n' 'TRIVY_IMAGE is required' >&2; exit 2; }
	@test -n "$(TRIVY_REPORT)" || { printf '%s\n' 'TRIVY_REPORT is required' >&2; exit 2; }
	@test -n "$(TRIVY_CACHE)" || { printf '%s\n' 'TRIVY_CACHE is required' >&2; exit 2; }
	$(PYTHON) $(TRIVY_SCRIPT) --image "$(TRIVY_IMAGE)" --report "$(TRIVY_REPORT)" --cache-dir "$(TRIVY_CACHE)" --trivy "$(TRIVY)"

skopeo-check: check-security-tooling
	$(PYTHON) -m unittest tests/test_skopeo_transfer.py

skopeo-preview: skopeo-check
	$(PYTHON) $(SKOPEO_SCRIPT) preview

skopeo-transfer: skopeo-check
	@test "$(APPROVAL)" = "$(SKOPEO_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/tar/skopeo-transfer' >&2; exit 2; }
	@test -n "$(SKOPEO_SOURCE)" || { printf '%s\n' 'SKOPEO_SOURCE is required' >&2; exit 2; }
	@test -n "$(SKOPEO_DESTINATION)" || { printf '%s\n' 'SKOPEO_DESTINATION is required' >&2; exit 2; }
	$(PYTHON) $(SKOPEO_SCRIPT) publish --source "$(SKOPEO_SOURCE)" --destination "$(SKOPEO_DESTINATION)" --approval "$(APPROVAL)" --inventory "$(INVENTORY)" --inventory "$(CONNECTION_INVENTORY)"

publish-platform-charts:
	@printf '%s\n' 'platform chart publication is blocked until Helm provenance, isolated credentials, and Argo image pins exist' >&2
	@exit 2

publish-platform-images:
	@printf '%s\n' 'platform image publication is blocked until Harbor routing and robot custody exist' >&2
	@exit 2

publish-release-feed:
	@printf '%s\n' 'release-feed publication is blocked until immutable tags and a promotion handoff exist' >&2
	@exit 2
