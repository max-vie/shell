# MAKE owns Kubernetes trust and delivery resources. Live targets require an
# explicit approval and use only the fixed scripts below.
MAKE_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPOSITORY_ROOT := $(abspath $(MAKE_ROOT)/..)
PYTHON ?= python3
CLUSTER ?= gcp
APPROVAL ?=
ANSIBLE_PLAYBOOK ?= ansible-playbook
TAR_LOCAL_ROOT ?= $(REPOSITORY_ROOT)/.local/tar/kubernetes
STAGED_ROOT := $(abspath $(TAR_LOCAL_ROOT))
CHART := $(STAGED_ROOT)/charts/cert-manager-v1.21.0.tgz

DELIVERY_HANDOFF_SCRIPT := $(MAKE_ROOT)/scripts/render_delivery_handoff.py
MAKE_DELIVERY_HANDOFF := $(REPOSITORY_ROOT)/.local/make/delivery-ansible-vars.json
MAKE_DELIVERY_HANDOFF_ABS := $(abspath $(MAKE_DELIVERY_HANDOFF))
INIT_DELIVERY_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
INIT_CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml
DELIVERY_INVENTORY_ARGS := -i "$(INIT_DELIVERY_INVENTORY)" -i "$(INIT_CONNECTION_INVENTORY)"
SYNTAX_INVENTORY := $(REPOSITORY_ROOT)/init/ansible/inventory/hosts.example.yml
DELIVERY_APPROVAL := environment-gcp/make/forgejo-delivery
DELIVERY_DEPLOY_PLAYBOOK := $(MAKE_ROOT)/forgejo/deploy-forgejo.yml
DELIVERY_VERIFY_PLAYBOOK := $(MAKE_ROOT)/forgejo/verify-forgejo.yml
DELIVERY_SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_delivery_supply.py
RUNNER_REGISTER_SCRIPT := $(MAKE_ROOT)/scripts/register_forgejo_runner.py
RUNNER_HANDOFF := $(REPOSITORY_ROOT)/.local/sudo/delivery/forgejo-runner.sops.json
REPOSITORY_REGISTER_SCRIPT := $(MAKE_ROOT)/scripts/register_forgejo_repository.py
REPOSITORY_HANDOFF := $(REPOSITORY_ROOT)/.local/sudo/delivery/forgejo-repository.sops.json
REPOSITORY_APPROVAL := environment-gcp/make/forgejo-repository
MONITORING_DEPLOY_SCRIPT := $(MAKE_ROOT)/scripts/deploy_monitoring.py
MONITORING_APPROVAL := environment-gcp/make/monitoring
MONITORING_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
MONITORING_CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml
LOGS_DEPLOY_SCRIPT := $(MAKE_ROOT)/scripts/deploy_logs.py
LOGS_APPROVAL := environment-gcp/make/logs
PLATFORM_SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_platform_supply.py
HARBOR_SCRIPT := $(MAKE_ROOT)/scripts/deploy_harbor.py
HARBOR_ROBOTS_SCRIPT := $(MAKE_ROOT)/scripts/register_harbor_robots.py
HARBOR_APPROVAL := environment-gcp/make/harbor
HARBOR_ROBOTS_APPROVAL := environment-gcp/make/harbor-robots
HARBOR_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
HARBOR_CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml
ARGOCD_SCRIPT := $(MAKE_ROOT)/scripts/deploy_argocd.py
ARGOCD_APPROVAL := environment-gcp/make/argocd
ARGOCD_ROOT_APPROVAL := environment-gcp/make/argocd-root
ARGOCD_REPOSITORY_SCRIPT := $(MAKE_ROOT)/scripts/register_argocd_repository.py
ARGOCD_REPOSITORY_APPROVAL := environment-gcp/make/argocd-repository
OPENBAO_VALIDATOR := $(MAKE_ROOT)/scripts/validate_openbao.py
OPENBAO_BOOTSTRAP_SCRIPT := $(MAKE_ROOT)/scripts/bootstrap_openbao.py
OPENBAO_CA_FILE ?= $(REPOSITORY_ROOT)/sudo/pki/shell-offline-root.crt.pem
RELEASE_FEED_SCRIPT := $(MAKE_ROOT)/scripts/deploy_release_feed.py
RELEASE_FEED_APPROVAL := environment-gcp/make/release-feed
RELEASE_FEED_TAR_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_release_feed.py
WATCH_RECOVERY_SCRIPT := $(MAKE_ROOT)/scripts/watch_recovery.py
WATCH_RECOVERY_APPROVAL := environment-gcp/watch/grafana-unavailable
WATCH_RECOVERY_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
WATCH_RECOVERY_CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml
PLATFORM_ADDONS_SCRIPT := $(MAKE_ROOT)/scripts/deploy_platform_addons.py
PLATFORM_ADDONS_APPROVAL := environment-gcp/make/platform-addons
PLATFORM_ADDONS_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
PLATFORM_ADDONS_CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml
KEYCLOAK_VALIDATOR := $(MAKE_ROOT)/scripts/validate_keycloak.py
KEYCLOAK_SECRETS_SCRIPT := $(MAKE_ROOT)/scripts/apply_keycloak_secrets.py
KEYCLOAK_KUBECONFIG := $(REPOSITORY_ROOT)/.local/ansible/kubeconfig/gcp.yaml
KEYCLOAK_INPUT := $(REPOSITORY_ROOT)/.local/sudo/keycloak/keycloak.sops.json
KEYCLOAK_AGE_KEY := $(REPOSITORY_ROOT)/.local/sudo/keycloak/age-key.txt
KEYCLOAK_FREEIPA_CA := $(REPOSITORY_ROOT)/.local/sudo/keycloak/freeipa-ca.crt
KEYCLOAK_SECRETS_APPROVAL := environment-gcp/make/keycloak-secrets
COSIGN_ADMISSION_VALIDATOR := $(MAKE_ROOT)/scripts/validate_cosign_admission.py
COSIGN_TRUST_SCRIPT := $(MAKE_ROOT)/scripts/apply_cosign_trust.py
COSIGN_TRUST_APPROVAL := environment-gcp/make/cosign-trust
COSIGN_TRUST_INPUT := $(REPOSITORY_ROOT)/.local/sudo/kubernetes/cosign/cosign-public.sops.json
COSIGN_TRUST_AGE_KEY := $(REPOSITORY_ROOT)/.local/sudo/kubernetes/cosign/age-key.txt
COSIGN_TRUST_KUBECONFIG := $(REPOSITORY_ROOT)/.local/ansible/kubeconfig/gcp.yaml
VELERO_VALIDATOR := $(MAKE_ROOT)/scripts/validate_velero.py
VELERO_CREDENTIAL_SCRIPT := $(MAKE_ROOT)/scripts/apply_velero_credentials.py
VELERO_CREDENTIALS := $(REPOSITORY_ROOT)/.local/init/gcs-backup/credentials.json
VELERO_CREDENTIAL_KUBECONFIG := $(REPOSITORY_ROOT)/.local/ansible/kubeconfig/gcp.yaml
VELERO_CREDENTIAL_APPROVAL := environment-gcp/make/velero-credentials
KUBE_BENCH_RUNNER := $(MAKE_ROOT)/scripts/run_kube_bench.py
KUBE_BENCH_KUBECONFIG := $(REPOSITORY_ROOT)/.local/ansible/kubeconfig/gcp.yaml
KUBE_BENCH_APPROVAL := environment-gcp/make/kube-bench
K6_RUNNER := $(MAKE_ROOT)/scripts/run_k6_load.py
K6_KUBECONFIG := $(REPOSITORY_ROOT)/.local/ansible/kubeconfig/gcp.yaml
K6_APPROVAL := environment-gcp/make/k6

TRUST_VALIDATOR := $(MAKE_ROOT)/scripts/validate_cluster_trust.py
INTERMEDIATE_SCRIPT := $(MAKE_ROOT)/scripts/apply_cluster_intermediate.py
CERTIFICATE_SCRIPT := $(MAKE_ROOT)/scripts/apply_consumer_certificate.py
SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_kubernetes_supply.py
TRUST_VALUES := $(MAKE_ROOT)/cert-manager/values.yaml

.PHONY: check test trust-preview trust-template trust-apply trust-verify certificate-check certificate-apply certificate-verify delivery-handoff-check delivery-handoff delivery-handoff-validate forgejo-check forgejo-preview forgejo-apply forgejo-verify runner-check runner-register runner-apply runner-verify repository-check repository-register repository-rotate repository-verify monitoring-check monitoring-preview monitoring-apply logs-check logs-preview logs-apply platform-check platform-addons-check platform-addons-preview platform-addons-apply platform-addons-verify harbor-check harbor-preview harbor-apply harbor-robots-check harbor-robots-apply argocd-check argocd-preview argocd-apply argocd-root-apply argocd-verify argocd-repository-check argocd-repository-apply openbao-check openbao-preview openbao-bootstrap keycloak-check keycloak-secrets-check keycloak-secrets-apply keycloak-secrets-verify cosign-admission-check cosign-trust-check cosign-trust-apply cosign-trust-verify kyverno-check velero-check velero-credential-check velero-credential-apply velero-credential-verify kube-bench-check kube-bench-preview kube-bench-run k6-check k6-preview k6-run release-feed-check release-feed-preview release-feed-apply release-feed-verify watch-recovery-check watch-recovery-rule-preview watch-recovery-rule-apply watch-recovery-drill watch-recovery-restore

check: test trust-preview repository-check monitoring-check logs-check platform-check platform-addons-check harbor-check argocd-check openbao-check keycloak-check keycloak-secrets-check cosign-admission-check cosign-trust-check kyverno-check velero-check velero-credential-check kube-bench-check k6-check release-feed-check

test:
	$(PYTHON) -m unittest discover -s $(MAKE_ROOT)/tests -p 'test_*.py'
	$(PYTHON) -m unittest discover -s $(MAKE_ROOT)/apps/release-feed/tests -p 'test_*.py'

# Contract validation is offline and checks both clusters.
trust-preview:
	$(PYTHON) $(TRUST_VALIDATOR)

# Render the staged chart locally without contacting a cluster.
trust-template:
	$(PYTHON) $(SUPPLY_VALIDATOR) --staged-root "$(STAGED_ROOT)"
	helm template cert-manager "$(CHART)" --namespace cert-manager --values "$(TRUST_VALUES)" --include-crds >/dev/null

trust-apply:
	$(PYTHON) $(INTERMEDIATE_SCRIPT) apply --cluster "$(CLUSTER)" --approval "$(APPROVAL)"

trust-verify:
	$(PYTHON) $(INTERMEDIATE_SCRIPT) verify --cluster "$(CLUSTER)"

certificate-check:
	$(PYTHON) $(TRUST_VALIDATOR)

certificate-apply:
	$(PYTHON) $(CERTIFICATE_SCRIPT) apply --cluster "$(CLUSTER)" --approval "$(APPROVAL)"

certificate-verify:
	$(PYTHON) $(CERTIFICATE_SCRIPT) verify --cluster "$(CLUSTER)"

# Validate all public delivery inputs without reading or creating private state.
delivery-handoff-check:
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --check-only

# Render the ignored path-only delivery handoff consumed by the delivery
# playbooks. The generator never decrypts or copies a private input.
delivery-handoff:
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --output "$(MAKE_DELIVERY_HANDOFF_ABS)"

# Validate the existing path-only handoff without creating or replacing it.
delivery-handoff-validate:
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --validate --output "$(MAKE_DELIVERY_HANDOFF_ABS)"

# Check the Forgejo and Caddy playbooks without selecting a host or contacting
# a guest. The private INIT inventory is used only by the explicit preview,
# deployment, and verification targets below.
forgejo-check: delivery-handoff-check
	$(PYTHON) $(DELIVERY_SUPPLY_VALIDATOR)
	$(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" "$(DELIVERY_DEPLOY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"
	$(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" "$(DELIVERY_VERIFY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"

# The playbook's check-mode gate stops before SOPS decryption and guest writes.
forgejo-preview: delivery-handoff-validate
	$(ANSIBLE_PLAYBOOK) --check $(DELIVERY_INVENTORY_ARGS) "$(DELIVERY_DEPLOY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"

# Explicit mutation target for the already-prepared delivery host.
forgejo-apply:
	@test "$(APPROVAL)" = "$(DELIVERY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/forgejo-delivery' >&2; exit 2; }
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --output "$(MAKE_DELIVERY_HANDOFF_ABS)"
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --validate --output "$(MAKE_DELIVERY_HANDOFF_ABS)"
	$(ANSIBLE_PLAYBOOK) $(DELIVERY_INVENTORY_ARGS) "$(DELIVERY_DEPLOY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"

# Read-only service and HTTPS verification target.
forgejo-verify: delivery-handoff-validate
	$(ANSIBLE_PLAYBOOK) $(DELIVERY_INVENTORY_ARGS) "$(DELIVERY_VERIFY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"

# Runner checks remain source-only and do not require a private handoff.
runner-check: forgejo-check
	$(PYTHON) -m unittest $(MAKE_ROOT)/tests/test_register_forgejo_runner.py

# Registration is the first target that may create external Forgejo state.
runner-register:
	@test "$(APPROVAL)" = "$(DELIVERY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/forgejo-delivery' >&2; exit 2; }
	$(PYTHON) "$(RUNNER_REGISTER_SCRIPT)" \
		--age-key "$(REPOSITORY_ROOT)/.local/sudo/delivery/age-key.txt" \
		--runner-sops "$(RUNNER_HANDOFF)" \
		--inventory "$(INIT_DELIVERY_INVENTORY)" \
		--inventory "$(INIT_CONNECTION_INVENTORY)" \
		--approval "$(APPROVAL)"

# Deploy the runner only after the encrypted registration handoff exists.
runner-apply:
	@test "$(APPROVAL)" = "$(DELIVERY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/forgejo-delivery' >&2; exit 2; }
	$(PYTHON) "$(RUNNER_REGISTER_SCRIPT)" --validate-only --runner-sops "$(RUNNER_HANDOFF)" --age-key "$(REPOSITORY_ROOT)/.local/sudo/delivery/age-key.txt"
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --output "$(MAKE_DELIVERY_HANDOFF_ABS)"
	$(PYTHON) $(DELIVERY_HANDOFF_SCRIPT) --validate --output "$(MAKE_DELIVERY_HANDOFF_ABS)"
	$(ANSIBLE_PLAYBOOK) $(DELIVERY_INVENTORY_ARGS) "$(DELIVERY_DEPLOY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"

# Runner verification is read-only and shares the delivery service verifier.
runner-verify: delivery-handoff-validate
	$(PYTHON) "$(RUNNER_REGISTER_SCRIPT)" --validate-only --runner-sops "$(RUNNER_HANDOFF)" --age-key "$(REPOSITORY_ROOT)/.local/sudo/delivery/age-key.txt"
	$(ANSIBLE_PLAYBOOK) $(DELIVERY_INVENTORY_ARGS) "$(DELIVERY_VERIFY_PLAYBOOK)" -e make_delivery_vars_path="$(MAKE_DELIVERY_HANDOFF_ABS)"

# Repository checks are source-only and keep the credential handoff optional.
repository-check: runner-check
	$(PYTHON) -m unittest $(MAKE_ROOT)/tests/test_register_forgejo_repository.py

# Repository creation and the seed push require a separate explicit approval.
repository-register:
	@test "$(APPROVAL)" = "$(REPOSITORY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/forgejo-repository' >&2; exit 2; }
	$(PYTHON) "$(REPOSITORY_REGISTER_SCRIPT)" \
		--bootstrap-sops "$(REPOSITORY_ROOT)/.local/sudo/delivery/bootstrap.sops.json" \
		--age-key "$(REPOSITORY_ROOT)/.local/sudo/delivery/age-key.txt" \
		--repository-sops "$(REPOSITORY_HANDOFF)" \
		--inventory "$(INIT_DELIVERY_INVENTORY)" \
		--inventory "$(INIT_CONNECTION_INVENTORY)" \
		--approval "$(APPROVAL)"

# Explicit rotation revokes the prior named token and replaces the handoff.
repository-rotate:
	@test "$(APPROVAL)" = "$(REPOSITORY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/forgejo-repository' >&2; exit 2; }
	$(PYTHON) "$(REPOSITORY_REGISTER_SCRIPT)" \
		--rotate \
		--bootstrap-sops "$(REPOSITORY_ROOT)/.local/sudo/delivery/bootstrap.sops.json" \
		--age-key "$(REPOSITORY_ROOT)/.local/sudo/delivery/age-key.txt" \
		--repository-sops "$(REPOSITORY_HANDOFF)" \
		--inventory "$(INIT_DELIVERY_INVENTORY)" \
		--inventory "$(INIT_CONNECTION_INVENTORY)" \
		--approval "$(APPROVAL)"

# Read-only repository verification uses the bot credential handoff.
repository-verify: delivery-handoff-validate
	$(PYTHON) "$(REPOSITORY_REGISTER_SCRIPT)" \
		--verify-only \
		--repository-sops "$(REPOSITORY_HANDOFF)" \
		--age-key "$(REPOSITORY_ROOT)/.local/sudo/delivery/age-key.txt" \
		--inventory "$(INIT_DELIVERY_INVENTORY)" \
		--inventory "$(INIT_CONNECTION_INVENTORY)"

# Monitoring source validation is offline and does not inspect private state.
monitoring-check:
	$(PYTHON) "$(MONITORING_DEPLOY_SCRIPT)" --check-only

monitoring-preview: monitoring-check
	$(PYTHON) "$(MONITORING_DEPLOY_SCRIPT)" --template-only

# MAKE is the only lifecycle allowed to mutate Kubernetes workloads.
monitoring-apply:
	@test "$(APPROVAL)" = "$(MONITORING_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/monitoring' >&2; exit 2; }
	$(PYTHON) "$(MONITORING_DEPLOY_SCRIPT)" \
		--inventory "$(MONITORING_INVENTORY)" \
		--inventory "$(MONITORING_CONNECTION_INVENTORY)" \
		--approval "$(APPROVAL)"

# Logs source validation remains offline; deployment is separate from metrics.
logs-check: monitoring-check
	$(PYTHON) "$(LOGS_DEPLOY_SCRIPT)" --check-only

logs-preview: logs-check
	$(PYTHON) "$(LOGS_DEPLOY_SCRIPT)" --template-only

logs-apply:
	@test "$(APPROVAL)" = "$(LOGS_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/logs' >&2; exit 2; }
	$(PYTHON) "$(LOGS_DEPLOY_SCRIPT)" \
		--inventory "$(MONITORING_INVENTORY)" \
		--inventory "$(MONITORING_CONNECTION_INVENTORY)" \
		--approval "$(APPROVAL)"

platform-check:
	$(PYTHON) "$(PLATFORM_SUPPLY_VALIDATOR)"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_harbor_robots.py"

platform-addons-check:
	$(PYTHON) "$(PLATFORM_ADDONS_SCRIPT)" check
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_platform_addons.py"

platform-addons-preview: platform-addons-check
	$(PYTHON) "$(PLATFORM_ADDONS_SCRIPT)" template

platform-addons-apply:
	@test "$(APPROVAL)" = "$(PLATFORM_ADDONS_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/platform-addons' >&2; exit 2; }
	$(PYTHON) "$(PLATFORM_ADDONS_SCRIPT)" apply \
		--approval "$(APPROVAL)" \
		--inventory "$(PLATFORM_ADDONS_INVENTORY)" \
		--inventory "$(PLATFORM_ADDONS_CONNECTION_INVENTORY)"

platform-addons-verify:
	$(PYTHON) "$(PLATFORM_ADDONS_SCRIPT)" verify \
		--inventory "$(PLATFORM_ADDONS_INVENTORY)" \
		--inventory "$(PLATFORM_ADDONS_CONNECTION_INVENTORY)"

harbor-check: platform-check
	$(PYTHON) "$(MAKE_ROOT)/scripts/validate_harbor_robots.py"
	$(PYTHON) "$(HARBOR_SCRIPT)" check

harbor-preview: harbor-check
	$(PYTHON) "$(HARBOR_SCRIPT)" check

harbor-apply:
	@printf '%s\n' 'Harbor apply is blocked: GCP service routing and SUDO signing-key custody are unresolved' >&2
	@exit 2

harbor-robots-check:
	$(PYTHON) "$(HARBOR_ROBOTS_SCRIPT)" --check-only --approval source-only

harbor-robots-apply:
	@printf '%s\n' 'Harbor robot registration is blocked: durable replacement and custody publication are unresolved' >&2
	@exit 2

argocd-check: argocd-repository-check
	$(PYTHON) "$(MAKE_ROOT)/scripts/validate_argocd.py"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_argocd_source.py"

argocd-preview: argocd-check
	$(PYTHON) "$(ARGOCD_SCRIPT)" check

argocd-apply:
	@printf '%s\n' 'Argo CD apply is blocked: runtime image pins and GitOps source publication are unresolved' >&2
	@exit 2

argocd-root-apply:
	@printf '%s\n' 'Argo CD root apply is blocked until the reviewed GitOps revision is published' >&2
	@exit 2

argocd-verify:
	$(PYTHON) "$(ARGOCD_SCRIPT)" verify \
		--inventory "$(HARBOR_INVENTORY)" \
		--inventory "$(HARBOR_CONNECTION_INVENTORY)"

argocd-repository-check:
	$(PYTHON) "$(ARGOCD_REPOSITORY_SCRIPT)" --check-only --approval source-only
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_argocd_repository.py"

argocd-repository-apply:
	@printf '%s\n' 'Argo CD repository apply is blocked until GitOps publication is implemented' >&2
	@exit 2

openbao-check:
	$(PYTHON) "$(OPENBAO_VALIDATOR)"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_openbao_source.py" "$(MAKE_ROOT)/tests/test_openbao_bootstrap.py"

openbao-preview: openbao-check
	$(PYTHON) "$(OPENBAO_BOOTSTRAP_SCRIPT)" \
		--check-only \
		--approval source-only \
		--url https://openbao-active.openbao.svc.cluster.local:8200 \
		--ca-file "$(REPOSITORY_ROOT)/sudo/pki/shell-offline-root.crt.pem"

openbao-bootstrap:
	@printf '%s\n' 'OpenBao bootstrap is blocked: K3s API trust, HA join, and split custody are unresolved' >&2
	@exit 2

keycloak-check:
	$(PYTHON) "$(KEYCLOAK_VALIDATOR)"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_keycloak.py"

keycloak-secrets-check:
	$(PYTHON) "$(KEYCLOAK_SECRETS_SCRIPT)" check
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_keycloak_secrets.py"

keycloak-secrets-apply:
	@test "$(APPROVAL)" = "$(KEYCLOAK_SECRETS_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/keycloak-secrets' >&2; exit 2; }
	$(PYTHON) "$(KEYCLOAK_SECRETS_SCRIPT)" apply \
		--approval "$(APPROVAL)" \
		--input "$(KEYCLOAK_INPUT)" \
		--age-key "$(KEYCLOAK_AGE_KEY)" \
		--freeipa-ca "$(KEYCLOAK_FREEIPA_CA)" \
		--kubeconfig "$(KEYCLOAK_KUBECONFIG)"

keycloak-secrets-verify:
	$(PYTHON) "$(KEYCLOAK_SECRETS_SCRIPT)" verify \
		--kubeconfig "$(KEYCLOAK_KUBECONFIG)"

cosign-admission-check:
	$(PYTHON) "$(COSIGN_ADMISSION_VALIDATOR)"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_cosign_admission.py"

cosign-trust-check:
	$(PYTHON) "$(COSIGN_TRUST_SCRIPT)" check
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_cosign_trust.py"

cosign-trust-apply:
	@test "$(APPROVAL)" = "$(COSIGN_TRUST_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/cosign-trust' >&2; exit 2; }
	$(PYTHON) "$(COSIGN_TRUST_SCRIPT)" apply \
		--approval "$(APPROVAL)" \
		--input "$(COSIGN_TRUST_INPUT)" \
		--age-key "$(COSIGN_TRUST_AGE_KEY)" \
		--kubeconfig "$(COSIGN_TRUST_KUBECONFIG)"

cosign-trust-verify:
	$(PYTHON) "$(COSIGN_TRUST_SCRIPT)" verify \
		--input "$(COSIGN_TRUST_INPUT)" \
		--age-key "$(COSIGN_TRUST_AGE_KEY)" \
		--kubeconfig "$(COSIGN_TRUST_KUBECONFIG)"

kyverno-check: cosign-admission-check

velero-check:
	$(PYTHON) "$(VELERO_VALIDATOR)"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_velero.py"

velero-credential-check:
	$(PYTHON) "$(VELERO_CREDENTIAL_SCRIPT)" check
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_velero_credentials.py"

velero-credential-apply:
	@test "$(APPROVAL)" = "$(VELERO_CREDENTIAL_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/velero-credentials' >&2; exit 2; }
	$(PYTHON) "$(VELERO_CREDENTIAL_SCRIPT)" apply \
		--approval "$(APPROVAL)" \
		--credentials "$(VELERO_CREDENTIALS)" \
		--kubeconfig "$(VELERO_CREDENTIAL_KUBECONFIG)"

velero-credential-verify:
	$(PYTHON) "$(VELERO_CREDENTIAL_SCRIPT)" verify \
		--kubeconfig "$(VELERO_CREDENTIAL_KUBECONFIG)"

kube-bench-check:
	$(PYTHON) "$(REPOSITORY_ROOT)/watch/scripts/kube_bench.py"
	$(PYTHON) -m unittest discover -s "$(REPOSITORY_ROOT)/watch/tests" -p 'test_security_audits.py'

kube-bench-preview: kube-bench-check
	$(PYTHON) "$(KUBE_BENCH_RUNNER)" preview

kube-bench-run:
	@test "$(APPROVAL)" = "$(KUBE_BENCH_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/kube-bench' >&2; exit 2; }
	@test -n "$(EVIDENCE)" || { printf '%s\n' 'EVIDENCE is required' >&2; exit 2; }
	$(PYTHON) "$(KUBE_BENCH_RUNNER)" run \
		--approval "$(APPROVAL)" \
		--kubeconfig "$(KUBE_BENCH_KUBECONFIG)" \
		--evidence "$(EVIDENCE)" \
		$(if $(RUN_ID),--run-id "$(RUN_ID)",)

k6-check:
	$(PYTHON) "$(REPOSITORY_ROOT)/watch/scripts/k6_load.py"
	$(PYTHON) -m unittest discover -s "$(REPOSITORY_ROOT)/watch/tests" -p 'test_security_audits.py'

k6-preview: k6-check
	$(PYTHON) "$(K6_RUNNER)" preview

k6-run:
	@test "$(APPROVAL)" = "$(K6_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/make/k6' >&2; exit 2; }
	@test -n "$(EVIDENCE)" || { printf '%s\n' 'EVIDENCE is required' >&2; exit 2; }
	$(PYTHON) "$(K6_RUNNER)" run \
		--approval "$(APPROVAL)" \
		--kubeconfig "$(K6_KUBECONFIG)" \
		--evidence "$(EVIDENCE)" \
		$(if $(RUN_ID),--run-id "$(RUN_ID)",)

release-feed-check:
	$(PYTHON) "$(RELEASE_FEED_TAR_VALIDATOR)"
	$(PYTHON) "$(RELEASE_FEED_SCRIPT)" check
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_release_feed_deploy.py"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/apps/release-feed/tests/test_app.py"

release-feed-preview: release-feed-check
	$(PYTHON) "$(RELEASE_FEED_SCRIPT)" check

release-feed-apply:
	@printf '%s\n' 'release-feed apply is blocked: GCP routing and TAR promotion are unresolved' >&2
	@exit 2

release-feed-verify:
	$(PYTHON) "$(REPOSITORY_ROOT)/watch/scripts/verify_release_feed.py" \
		--inventory "$(HARBOR_INVENTORY)" \
		--inventory "$(HARBOR_CONNECTION_INVENTORY)"

# Recovery policy is validated locally; live mutation remains MAKE-owned and
# requires its exact WATCH approval.
watch-recovery-check:
	$(PYTHON) "$(REPOSITORY_ROOT)/watch/scripts/validate_recovery.py"
	$(PYTHON) -m unittest "$(MAKE_ROOT)/tests/test_watch_recovery.py"

watch-recovery-rule-preview:
	$(PYTHON) "$(WATCH_RECOVERY_SCRIPT)" rule-preview \
		--inventory "$(WATCH_RECOVERY_INVENTORY)" \
		--inventory "$(WATCH_RECOVERY_CONNECTION_INVENTORY)"

watch-recovery-rule-apply:
	@test "$(APPROVAL)" = "$(WATCH_RECOVERY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/watch/grafana-unavailable' >&2; exit 2; }
	$(PYTHON) "$(WATCH_RECOVERY_SCRIPT)" rule-apply \
		--approval "$(APPROVAL)" \
		--inventory "$(WATCH_RECOVERY_INVENTORY)" \
		--inventory "$(WATCH_RECOVERY_CONNECTION_INVENTORY)"

watch-recovery-drill:
	@test "$(APPROVAL)" = "$(WATCH_RECOVERY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/watch/grafana-unavailable' >&2; exit 2; }
	$(PYTHON) "$(WATCH_RECOVERY_SCRIPT)" drill \
		--approval "$(APPROVAL)" \
		--inventory "$(WATCH_RECOVERY_INVENTORY)" \
		--inventory "$(WATCH_RECOVERY_CONNECTION_INVENTORY)" \
		$(if $(OUTPUT),--output "$(OUTPUT)",)

watch-recovery-restore:
	@test "$(APPROVAL)" = "$(WATCH_RECOVERY_APPROVAL)" || { printf '%s\n' 'APPROVAL must be environment-gcp/watch/grafana-unavailable' >&2; exit 2; }
	@test -n "$(OPERATION_ID)" || { printf '%s\n' 'OPERATION_ID is required' >&2; exit 2; }
	$(PYTHON) "$(WATCH_RECOVERY_SCRIPT)" restore \
		--approval "$(APPROVAL)" \
		--operation-id "$(OPERATION_ID)" \
		--inventory "$(WATCH_RECOVERY_INVENTORY)" \
		--inventory "$(WATCH_RECOVERY_CONNECTION_INVENTORY)"
