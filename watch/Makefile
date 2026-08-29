# WATCH owns monitoring policy, alerting, and recovery evidence for the GCP
# K3s cluster. Its targets are source-only or read-only.
PYTHON ?= python3
WATCH_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPOSITORY_ROOT := $(abspath $(WATCH_ROOT)/..)
CONTRACT_VALIDATOR := $(WATCH_ROOT)/scripts/validate_monitoring_contract.py
SUPPLY_VALIDATOR := $(REPOSITORY_ROOT)/tar/scripts/validate_watch.py
VERIFY_SCRIPT := $(WATCH_ROOT)/scripts/verify_monitoring.py
RECOVERY_SCRIPT := $(REPOSITORY_ROOT)/make/scripts/watch_recovery.py
INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/inventory.json
CONNECTION_INVENTORY := $(REPOSITORY_ROOT)/.local/ansible/connection-inventory.yml

.PHONY: check test check-logs check-recovery verify verify-logs recovery-status recovery-preflight stability-soak

check: test

test:
	$(PYTHON) $(CONTRACT_VALIDATOR)
	$(PYTHON) $(SUPPLY_VALIDATOR)
	$(PYTHON) -m unittest discover -s $(WATCH_ROOT)/tests -p 'test_*.py'

check-logs:
	$(PYTHON) $(CONTRACT_VALIDATOR)
	$(PYTHON) $(REPOSITORY_ROOT)/tar/scripts/validate_watch_logs.py
	$(PYTHON) -m unittest $(WATCH_ROOT)/tests/test_logs.py

check-recovery:
	$(PYTHON) $(WATCH_ROOT)/scripts/validate_recovery.py
	$(PYTHON) -m unittest $(WATCH_ROOT)/tests/test_recovery_drill.py

# Read-only live verification for metrics and Grafana through the fixed first
# GCP K3s server.
verify:
	$(PYTHON) $(VERIFY_SCRIPT) \
		--inventory "$(INVENTORY)" \
		--inventory "$(CONNECTION_INVENTORY)"

verify-logs:
	$(PYTHON) $(WATCH_ROOT)/scripts/verify_logs.py \
		--inventory "$(INVENTORY)" \
		--inventory "$(CONNECTION_INVENTORY)"

# These targets are read-only. MAKE owns the rule application and fault
# mutation invoked by its separate recovery targets.
recovery-status:
	$(PYTHON) $(RECOVERY_SCRIPT) status \
		--inventory "$(INVENTORY)" \
		--inventory "$(CONNECTION_INVENTORY)"

recovery-preflight:
	$(PYTHON) $(RECOVERY_SCRIPT) preflight \
		--inventory "$(INVENTORY)" \
		--inventory "$(CONNECTION_INVENTORY)"

stability-soak:
	$(PYTHON) $(RECOVERY_SCRIPT) stability-soak \
		--inventory "$(INVENTORY)" \
		--inventory "$(CONNECTION_INVENTORY)"
