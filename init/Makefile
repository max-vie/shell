# INIT owns the source checks and fixed K3s controller entrypoint.
# Targets never select arbitrary Ansible hosts or playbooks.
PYTHON ?= python3
ANSIBLE_PLAYBOOK ?= ansible-playbook
LAUNCHER := scripts/run_k3s_runtime.py
CLUSTER ?= gcp
PLATFORM_LAUNCHER := scripts/run_platform_addons.py
SYNTAX_INVENTORY := ansible/inventory/hosts.example.yml
override ANSIBLE_COLLECTIONS_PATH := $(shell $(PYTHON) -c 'import site; print(site.getusersitepackages() + "/ansible_collections")')

.PHONY: check test k3s-preview k3s-verify platform-check platform-preview platform-apply platform-verify registry-trust-preview registry-trust-apply registry-trust-verify

# Keep the default check offline and independent of provider or guest state.
check: test platform-check

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

# CLUSTER is validated again by the launcher. The launcher derives the exact
# inventory group and playbook for the selected cluster.
k3s-preview:
	$(PYTHON) $(LAUNCHER) configure --cluster "$(CLUSTER)" --check

k3s-verify:
	$(PYTHON) $(LAUNCHER) verify --cluster "$(CLUSTER)"

platform-check:
	$(PYTHON) -m unittest $(CURDIR)/tests/test_platform_addons.py
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" ansible/playbooks/configure-platform-addons.yml
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" ansible/playbooks/verify-platform-addons.yml
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" ansible/playbooks/configure-platform-registry-trust.yml
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" ansible/playbooks/verify-platform-registry-trust.yml

platform-preview: platform-check
	$(PYTHON) $(PLATFORM_LAUNCHER) configure --check

platform-apply:
	$(PYTHON) $(PLATFORM_LAUNCHER) configure \
		--approval "$(APPROVAL)" \
		$(if $(filter true,$(FORMAT_DATA_DISK)),--format-data-disk,)

platform-verify:
	$(PYTHON) $(PLATFORM_LAUNCHER) verify

registry-trust-preview:
	$(PYTHON) $(PLATFORM_LAUNCHER) registry-trust --check

registry-trust-apply:
	$(PYTHON) $(PLATFORM_LAUNCHER) registry-trust --approval "$(APPROVAL)"

registry-trust-verify:
	$(PYTHON) $(PLATFORM_LAUNCHER) registry-trust-verify
