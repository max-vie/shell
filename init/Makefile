# INIT owns the source checks and fixed K3s controller entrypoint.
# Targets never select arbitrary Ansible hosts or playbooks.
PYTHON ?= python3
ANSIBLE_PLAYBOOK ?= ansible-playbook
LAUNCHER := scripts/run_k3s_runtime.py
CLUSTER ?= gcp
PLATFORM_LAUNCHER := scripts/run_platform_addons.py
SYNTAX_INVENTORY := ansible/inventory/hosts.example.yml
K3S_CONFIGURE_PLAYBOOK := ansible/playbooks/configure-k3s-runtime.yml
K3S_VERIFY_PLAYBOOK := ansible/playbooks/verify-k3s-runtime.yml
IDENTITY_LAUNCHER := scripts/run_identity_service.py
IDENTITY_CONFIGURE_PLAYBOOK := ansible/playbooks/configure-identity-service.yml
IDENTITY_VERIFY_PLAYBOOK := ansible/playbooks/verify-identity-service.yml
KEYCLOAK_BIND_PLAYBOOK := ansible/playbooks/configure-keycloak-ldap-bind.yml
GCS_BACKUP_ROOT := opentofu/gcs-backup
override ANSIBLE_COLLECTIONS_PATH := $(shell $(PYTHON) -c 'import site; print(site.getusersitepackages() + "/ansible_collections")')

.PHONY: check test k3s-syntax k3s-preview k3s-verify identity-syntax identity-preview identity-apply identity-verify identity-bind-preview identity-bind-apply gcs-backup-check platform-check platform-preview platform-apply platform-verify registry-trust-preview registry-trust-apply registry-trust-verify

# Keep the default check offline and independent of provider or guest state.
check: test k3s-syntax identity-syntax gcs-backup-check platform-check

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

k3s-syntax:
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" -e shell_k3s_target_group=gcp_k3s_servers "$(K3S_CONFIGURE_PLAYBOOK)"
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" -e shell_k3s_target_group=gcp_k3s_servers "$(K3S_VERIFY_PLAYBOOK)"

identity-syntax:
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" "$(IDENTITY_CONFIGURE_PLAYBOOK)"
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" "$(IDENTITY_VERIFY_PLAYBOOK)"
	ANSIBLE_COLLECTIONS_PATH="$(ANSIBLE_COLLECTIONS_PATH)" $(ANSIBLE_PLAYBOOK) --syntax-check -i "$(SYNTAX_INVENTORY)" "$(KEYCLOAK_BIND_PLAYBOOK)"

# CLUSTER is validated again by the launcher. The launcher derives the exact
# inventory group and playbook for the selected cluster.
k3s-preview:
	$(PYTHON) $(LAUNCHER) configure --cluster "$(CLUSTER)" --check

k3s-verify:
	$(PYTHON) $(LAUNCHER) verify --cluster "$(CLUSTER)"

identity-preview:
	$(PYTHON) $(IDENTITY_LAUNCHER) configure --check

identity-apply:
	$(PYTHON) $(IDENTITY_LAUNCHER) configure --approval "$(APPROVAL)"

identity-verify:
	$(PYTHON) $(IDENTITY_LAUNCHER) verify

identity-bind-preview:
	$(PYTHON) $(IDENTITY_LAUNCHER) bind --check

identity-bind-apply:
	$(PYTHON) $(IDENTITY_LAUNCHER) bind --approval "$(APPROVAL)"

gcs-backup-check:
	tofu fmt -check -diff "$(GCS_BACKUP_ROOT)"

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
