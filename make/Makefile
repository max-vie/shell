# MAKE owns Kubernetes trust resources. Live targets require an explicit,
# cluster-specific approval and use only the fixed scripts below.
MAKE_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPOSITORY_ROOT := $(abspath $(MAKE_ROOT)/..)
PYTHON ?= python3
CLUSTER ?= gcp
APPROVAL ?=
TAR_LOCAL_ROOT ?= $(REPOSITORY_ROOT)/.local/tar/kubernetes
STAGED_ROOT := $(abspath $(TAR_LOCAL_ROOT))
CHART := $(STAGED_ROOT)/charts/cert-manager-v1.21.0.tgz

TRUST_VALIDATOR := $(MAKE_ROOT)/scripts/validate_cluster_trust.py
INTERMEDIATE_SCRIPT := $(MAKE_ROOT)/scripts/apply_cluster_intermediate.py
CERTIFICATE_SCRIPT := $(MAKE_ROOT)/scripts/apply_consumer_certificate.py
SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_kubernetes_supply.py
TRUST_VALUES := $(MAKE_ROOT)/cert-manager/values.yaml

.PHONY: check test trust-preview trust-template trust-apply trust-verify certificate-check certificate-apply certificate-verify

check: test trust-preview

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
