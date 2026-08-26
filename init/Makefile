# INIT owns the source checks and fixed K3s controller entrypoint.
# Targets never select arbitrary Ansible hosts or playbooks.
PYTHON ?= python3
LAUNCHER := scripts/run_k3s_runtime.py
CLUSTER ?= gcp

.PHONY: check test k3s-preview k3s-verify

# Keep the default check offline and independent of provider or guest state.
check: test

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

# CLUSTER is validated again by the launcher. The launcher derives the exact
# inventory group and playbook for the selected cluster.
k3s-preview:
	$(PYTHON) $(LAUNCHER) configure --cluster "$(CLUSTER)" --check

k3s-verify:
	$(PYTHON) $(LAUNCHER) verify --cluster "$(CLUSTER)"
