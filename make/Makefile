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

TRUST_VALIDATOR := $(MAKE_ROOT)/scripts/validate_cluster_trust.py
INTERMEDIATE_SCRIPT := $(MAKE_ROOT)/scripts/apply_cluster_intermediate.py
CERTIFICATE_SCRIPT := $(MAKE_ROOT)/scripts/apply_consumer_certificate.py
SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_kubernetes_supply.py
TRUST_VALUES := $(MAKE_ROOT)/cert-manager/values.yaml

.PHONY: check test trust-preview trust-template trust-apply trust-verify certificate-check certificate-apply certificate-verify delivery-handoff-check delivery-handoff delivery-handoff-validate forgejo-check forgejo-preview forgejo-apply forgejo-verify runner-check runner-register runner-apply runner-verify repository-check repository-register repository-rotate repository-verify monitoring-check monitoring-preview monitoring-apply logs-check logs-preview logs-apply

check: test trust-preview repository-check monitoring-check logs-check

test:
	$(PYTHON) -m unittest discover -s $(MAKE_ROOT)/tests -p 'test_*.py'

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
