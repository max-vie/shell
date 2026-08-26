# WATCH owns monitoring policy, alerting, and recovery evidence for the GCP
# K3s cluster. Its targets are source-only or read-only.
PYTHON ?= python3
WATCH_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPOSITORY_ROOT := $(abspath $(WATCH_ROOT)/..)
CONTRACT_VALIDATOR := $(WATCH_ROOT)/scripts/validate_monitoring_contract.py
SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_watch.py
VERIFY_SCRIPT := $(WATCH_ROOT)/scripts/verify_monitoring.py
INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml

.PHONY: check test verify

check: test

test:
	$(PYTHON) $(CONTRACT_VALIDATOR)
	$(PYTHON) $(SUPPLY_VALIDATOR)
	$(PYTHON) -m unittest discover -s $(WATCH_ROOT)/tests -p 'test_*.py'

# Read-only live verification through the fixed first GCP K3s server.
verify:
	$(PYTHON) $(VERIFY_SCRIPT) \
		--inventory "$(INVENTORY)" \
		--inventory "$(CONNECTION_INVENTORY)"
