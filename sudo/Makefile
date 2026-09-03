# SUDO owns value-free access and private-input contract validation.
PYTHON ?= python3
SUDO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
FREEIPA_INPUT_GENERATOR := $(SUDO_ROOT)/scripts/generate_freeipa_inputs.py
KEYCLOAK_INPUT_GENERATOR := $(SUDO_ROOT)/scripts/generate_keycloak_inputs.py
COSIGN_INPUT_GENERATOR := $(SUDO_ROOT)/scripts/generate_cosign_trust_inputs.py
COSIGN_BINARY ?= $(SUDO_ROOT)/../.local/tar/kubernetes/tools/cosign

.PHONY: check test access-check stateful-check input-check freeipa-check keycloak-check cosign-check cosign-generate

check: test access-check input-check freeipa-check keycloak-check cosign-check

test:
	$(PYTHON) -m unittest discover -s $(SUDO_ROOT)/tests -p 'test_*.py'

access-check:
	$(PYTHON) $(SUDO_ROOT)/scripts/validate_access_contracts.py

stateful-check:
	$(PYTHON) $(SUDO_ROOT)/scripts/validate_stateful_inputs.py

input-check:
	$(PYTHON) $(SUDO_ROOT)/scripts/generate_release_feed_inputs.py \
		--check-only --approval source-only

freeipa-check:
	$(PYTHON) $(FREEIPA_INPUT_GENERATOR) \
		--check-only --approval source-only

keycloak-check:
	$(PYTHON) $(KEYCLOAK_INPUT_GENERATOR) \
		--check-only --approval source-only

cosign-check:
	$(PYTHON) $(COSIGN_INPUT_GENERATOR) \
		--check-only --approval source-only

cosign-generate:
	$(PYTHON) $(COSIGN_INPUT_GENERATOR) \
		--approval "$(APPROVAL)" --cosign "$(COSIGN_BINARY)"
