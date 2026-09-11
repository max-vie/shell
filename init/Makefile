# INIT owns the source checks and fixed K3s controller entrypoint.
# Targets never select arbitrary Ansible hosts or playbooks.
PYTHON ?= python3
ANSIBLE_PLAYBOOK ?= ansible-playbook
TOFU ?= tofu
GIT ?= git
INIT_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPOSITORY_ROOT := $(abspath $(INIT_ROOT)/..)
LAUNCHER := scripts/run_k3s_runtime.py
CLUSTER ?= gcp
BOOTSTRAP_LAUNCHER := scripts/run_gcp_bootstrap.py
PLATFORM_LAUNCHER := scripts/run_platform_addons.py
SYNTAX_INVENTORY := ansible/inventory/hosts.example.yml
K3S_CONFIGURE_PLAYBOOK := ansible/playbooks/configure-k3s-runtime.yml
K3S_VERIFY_PLAYBOOK := ansible/playbooks/verify-k3s-runtime.yml
IDENTITY_LAUNCHER := scripts/run_identity_service.py
IDENTITY_CONFIGURE_PLAYBOOK := ansible/playbooks/configure-identity-service.yml
IDENTITY_VERIFY_PLAYBOOK := ansible/playbooks/verify-identity-service.yml
KEYCLOAK_BIND_PLAYBOOK := ansible/playbooks/configure-keycloak-ldap-bind.yml
GCS_BACKUP_ROOT := opentofu/gcs-backup
OPENTOFU_ROOTS := opentofu/gcp/bootstrap opentofu/gcp/network opentofu/gcp/shared-nodes opentofu/gcp/k3s opentofu/gcp/proxmox-host opentofu/proxmox/k3s $(GCS_BACKUP_ROOT)
OPENTOFU_CACHE ?= $(REPOSITORY_ROOT)/.local/opentofu/validation/plugin-cache
TOFU_PLAN_BASE ?= $(REPOSITORY_ROOT)/.local/opentofu/gcp
TOFU_PROJECT ?=
TOFU_ROOT ?=
TOFU_COMMIT ?=
TOFU_APPROVAL ?=
TOFU_VARS ?=
TOFU_PLAN ?= $(TOFU_PLAN_BASE)/$(TOFU_ROOT)/$(TOFU_PROJECT)-$(TOFU_COMMIT).tfplan
TOFU_PLAN_DIGEST ?=
TOFU_STATE_GATE ?= $(TOFU_PLAN).state-gate
TOFU_API_GATE ?= $(TOFU_PLAN).api-gate
TOFU_APPROVAL_RECORD ?= $(TOFU_PLAN).approval.json
TOFU_ACTION_SUMMARY ?= $(TOFU_PLAN).summary.txt
TOFU_APPROVAL_VALIDATOR := scripts/validate_tofu_approval.py
export GIT TOFU TOFU_PLAN_BASE TOFU_PROJECT TOFU_ROOT TOFU_COMMIT TOFU_APPROVAL TOFU_VARS TOFU_PLAN TOFU_PLAN_DIGEST TOFU_STATE_GATE TOFU_API_GATE TOFU_APPROVAL_RECORD TOFU_ACTION_SUMMARY
PLATFORM_SUPPLY := tar/manifests/platform-addons-supply.json
override ANSIBLE_COLLECTIONS_PATH := $(shell $(PYTHON) -c 'import site; print(site.getusersitepackages() + "/ansible_collections")')

.PHONY: check test k3s-syntax k3s-preview k3s-verify identity-syntax identity-preview identity-apply identity-verify identity-bind-preview identity-bind-apply bootstrap-discover bootstrap-ledger bootstrap-verify opentofu-check tofu-guard tofu-plan tofu-apply tofu-verify gcs-backup-check platform-check platform-preview platform-apply platform-verify registry-trust-preview registry-trust-apply registry-trust-verify

# A cold OpenTofu cache may download lockfile-pinned providers. The default
# check remains independent of provider APIs, backends, state, and guests.
check: test k3s-syntax identity-syntax opentofu-check platform-check

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

# Read-only bootstrap checks. The bootstrap root itself is planned and
# applied through the guarded tofu targets with the bootstrap approval.
bootstrap-discover:
	$(PYTHON) $(BOOTSTRAP_LAUNCHER) discover

bootstrap-ledger:
	$(PYTHON) $(BOOTSTRAP_LAUNCHER) ledger

bootstrap-verify:
	$(PYTHON) $(BOOTSTRAP_LAUNCHER) verify

opentofu-check:
	@set -eu; \
	umask 077; \
	workspace="$$(mktemp -d)"; \
	trap 'rm -rf -- "$$workspace"' EXIT; \
	trap 'exit 129' HUP; \
	trap 'exit 130' INT; \
	trap 'exit 143' TERM; \
	cd "$(INIT_ROOT)"; \
	"$(GIT)" ls-files --cached --others --exclude-standard -- 'opentofu/**/*.tf' > "$$workspace/opentofu-files-all"; \
	: > "$$workspace/opentofu-files"; \
	while IFS= read -r file; do \
		test -f "$$file" && printf '%s\n' "$$file" >> "$$workspace/opentofu-files"; \
	done < "$$workspace/opentofu-files-all"; \
	test -s "$$workspace/opentofu-files"; \
	while IFS= read -r file; do \
		mkdir -p "$$workspace/init/$$(dirname "$$file")"; \
		cp "$$file" "$$workspace/init/$$file"; \
	done < "$$workspace/opentofu-files"; \
	for root in $(OPENTOFU_ROOTS); do \
		test -f "$$root/.terraform.lock.hcl"; \
		mkdir -p "$$workspace/init/$$root"; \
		cp "$$root/.terraform.lock.hcl" "$$workspace/init/$$root/.terraform.lock.hcl"; \
	done; \
	mkdir -p "$$workspace/$$(dirname "$(PLATFORM_SUPPLY)")"; \
	cp "$(REPOSITORY_ROOT)/$(PLATFORM_SUPPLY)" "$$workspace/$(PLATFORM_SUPPLY)"; \
	mkdir -p "$$workspace/sudo/access"; \
	cp "$(REPOSITORY_ROOT)/sudo/access/operator-access-profile.json" "$$workspace/sudo/access/operator-access-profile.json"; \
	mkdir -p "$(OPENTOFU_CACHE)" "$$workspace/home" "$$workspace/data"; \
	env -i PATH="$$PATH" HOME="$$workspace/home" TF_IN_AUTOMATION=1 \
		"$(TOFU)" -chdir="$$workspace/init/opentofu" fmt -check -diff -recursive -no-color; \
	for root in $(OPENTOFU_ROOTS); do \
		data_dir="$$workspace/data/$$root"; \
		mkdir -p "$$data_dir"; \
		env -i PATH="$$PATH" HOME="$$workspace/home" TF_IN_AUTOMATION=1 \
			TF_PLUGIN_CACHE_DIR="$(OPENTOFU_CACHE)" TF_DATA_DIR="$$data_dir" \
			"$(TOFU)" -chdir="$$workspace/init/$$root" init \
			-backend=false -input=false -lockfile=readonly -no-color; \
		env -i PATH="$$PATH" HOME="$$workspace/home" TF_IN_AUTOMATION=1 \
			TF_PLUGIN_CACHE_DIR="$(OPENTOFU_CACHE)" TF_DATA_DIR="$$data_dir" \
			"$(TOFU)" -chdir="$$workspace/init/$$root" validate -no-color; \
	done

# These targets are deliberately limited to the current GCP network root.
# Shared-node and later roots get their own reviewed source slice. Plans are
# private, bound to the current commit, and never reused by
# path or digest substitution.
tofu-guard:
	@set -eu; \
		project="$${TOFU_PROJECT}"; \
		root="$${TOFU_ROOT}"; \
		commit="$${TOFU_COMMIT}"; \
		approval="$${TOFU_APPROVAL}"; \
		private_root="$(REPOSITORY_ROOT)/.local/opentofu/gcp"; \
		plan_base="$${TOFU_PLAN_BASE}"; \
		resolved_private_root="$$(realpath -e -- "$$private_root")"; \
		resolved_plan_base="$$(realpath -e -- "$$plan_base")"; \
		test "$$resolved_plan_base" = "$$plan_base" || { echo "tofu guard refused: plan base is not canonical" >&2; exit 2; }; \
		case "$$resolved_plan_base" in "$$resolved_private_root"/*) ;; *) echo "tofu guard refused: plan base is outside private OpenTofu state" >&2; exit 2 ;; esac; \
		test "$$(stat -c '%a' "$$resolved_private_root")" = 700 || { echo "tofu guard refused: private OpenTofu root mode is not 0700" >&2; exit 2; }; \
		test "$$(stat -c '%a' "$$resolved_plan_base")" = 700 || { echo "tofu guard refused: plan base mode is not 0700" >&2; exit 2; }; \
		root_plan_dir="$$plan_base/$$root"; \
		test ! -L "$$root_plan_dir" || { echo "tofu guard refused: root plan directory is a symlink" >&2; exit 2; }; \
		if [ -e "$$root_plan_dir" ]; then test "$$(realpath -e -- "$$root_plan_dir")" = "$$root_plan_dir" || { echo "tofu guard refused: root plan directory is not canonical" >&2; exit 2; }; fi; \
		state_gate="$${TOFU_STATE_GATE}"; api_gate="$${TOFU_API_GATE}"; \
		for gate in "$$state_gate" "$$api_gate"; do test -f "$$gate" && test ! -L "$$gate" || { echo "tofu guard refused: precondition gate is missing" >&2; exit 2; }; resolved_gate="$$(realpath -e -- "$$gate")"; test "$$resolved_gate" = "$$gate" || { echo "tofu guard refused: precondition gate is not canonical" >&2; exit 2; }; case "$$resolved_gate" in "$$plan_base"/*) ;; *) echo "tofu guard refused: precondition gate is outside private plan state" >&2; exit 2 ;; esac; test "$$(stat -c '%a' "$$gate")" = 600 || { echo "tofu guard refused: precondition gate mode is not 0600" >&2; exit 2; }; done; \
		case "$$(cat "$$state_gate")" in fresh|migrated) ;; *) echo "tofu guard refused: state gate must be fresh or migrated" >&2; exit 2 ;; esac; \
		legacy_state="$(REPOSITORY_ROOT)/.local/opentofu/gcp/shared/terraform.tfstate"; \
		if [ -e "$$legacy_state" ] && [ "$$(cat "$$state_gate")" != migrated ]; then echo "tofu guard refused: legacy state requires migration approval" >&2; exit 2; fi; \
		case "$$root" in \
			bootstrap) expected_api_gate='bootstrap=approved' ;; \
			network) expected_api_gate='compute.googleapis.com=enabled' ;; \
			*) echo "tofu guard refused: root is not allow-listed" >&2; exit 2 ;; \
		esac; \
		test "$$(cat "$$api_gate")" = "$$expected_api_gate" || { echo "tofu guard refused: API gate is not approved" >&2; exit 2; }; \
		case "$$project" in \
			''|*[!a-z0-9-]*) echo "tofu guard refused: invalid project" >&2; exit 2 ;; \
		esac; \
		case "$$root" in \
			bootstrap) expected_approval='environment-gcp/init/tofu/bootstrap' ;; \
			network) expected_approval='environment-gcp/init/tofu/network' ;; \
			*) echo "tofu guard refused: root is not allow-listed" >&2; exit 2 ;; \
		esac; \
		test "$$approval" = "$$expected_approval" || { echo "tofu guard refused: approval does not match root" >&2; exit 2; }; \
		worktree_status="$$( "$${GIT}" -C "$(REPOSITORY_ROOT)" status --porcelain=v1 --untracked-files=all )"; \
		test -z "$$worktree_status" || { echo "tofu guard refused: source tree is dirty" >&2; exit 2; }; \
		actual_commit="$$( "$${GIT}" -C "$(REPOSITORY_ROOT)" rev-parse --verify HEAD )"; \
		test "$$commit" = "$$actual_commit" || { echo "tofu guard refused: commit is not HEAD" >&2; exit 2; }; \
		root_path="$(INIT_ROOT)/opentofu/gcp/$$root"; \
		test -d "$$root_path" || { echo "tofu guard refused: root source is missing" >&2; exit 2; }; \
		case "$$project" in -*|*-) echo "tofu guard refused: invalid project" >&2; exit 2 ;; esac; \
		test "$${#commit}" -eq 40 || { echo "tofu guard refused: commit must be a full SHA" >&2; exit 2; }; \
		case "$$commit" in *[!0-9a-f]*) echo "tofu guard refused: commit must be lowercase hexadecimal" >&2; exit 2 ;; esac; \
		if [ -n "$${TF_VAR_project_id:-}" ] && [ "$${TF_VAR_project_id}" != "$$project" ]; then \
			echo "tofu guard refused: TF_VAR_project_id does not match project" >&2; exit 2; \
		fi; \
		expected_plan="$${TOFU_PLAN_BASE}/$$root/$$project-$$commit.tfplan"; \
		test "$${TOFU_PLAN}" = "$$expected_plan" || { echo "tofu guard refused: saved plan path is not exact" >&2; exit 2; }

tofu-plan: tofu-guard
	@set -eu; \
		umask 077; \
		plan="$${TOFU_PLAN}"; \
		vars="$${TOFU_VARS}"; \
		private_base="$${TOFU_PLAN_BASE}"; \
		test -n "$$vars" || { echo "tofu guard refused: private variable file is required" >&2; exit 2; }; \
		test -f "$$vars" && test ! -L "$$vars" || { echo "tofu guard refused: private variable file is missing" >&2; exit 2; }; \
		resolved_vars="$$(realpath -e -- "$$vars")"; \
		test "$$resolved_vars" = "$$vars" || { echo "tofu guard refused: variable file is not canonical" >&2; exit 2; }; \
		case "$$resolved_vars" in "$$private_base"/*) ;; *) echo "tofu guard refused: variable file is outside private plan state" >&2; exit 2 ;; esac; \
		test "$$(stat -c '%a' "$$resolved_vars")" = 600 || { echo "tofu guard refused: variable file mode is not 0600" >&2; exit 2; }; \
		digest_file="$$plan.sha256"; \
		plan_dir="$$(dirname "$$plan")"; \
		mkdir -p "$$plan_dir"; \
		chmod 700 "$$plan_dir"; \
		test "$$(realpath -e -- "$$plan_dir")" = "$$plan_dir" || { echo "tofu guard refused: plan directory is not canonical" >&2; exit 2; }; \
		test ! -e "$$plan" && test ! -L "$$plan" || { echo "tofu guard refused: plan already exists" >&2; exit 2; }; \
		test ! -e "$$digest_file" && test ! -L "$$digest_file" || { echo "tofu guard refused: plan digest already exists" >&2; exit 2; }; \
		plan_tmp="$$plan.tmp.$$"; \
		digest_tmp="$$digest_file.tmp.$$"; \
		published=0; \
		cleanup() { if [ "$$published" -ne 1 ]; then rm -f -- "$$plan" "$$digest_file"; fi; rm -f -- "$$plan_tmp" "$$digest_tmp"; }; \
		trap cleanup EXIT; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" init \
			-input=false -lockfile=readonly -no-color; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" plan \
			-input=false -no-color -out="$$plan_tmp" \
			-var-file="$$vars" \
			-var="project_id=$${TOFU_PROJECT}"; \
		test -f "$$plan_tmp" && test ! -L "$$plan_tmp"; \
		mv -- "$$plan_tmp" "$$plan"; \
		digest_output="$$(sha256sum "$$plan")"; \
		digest_value="$${digest_output%% *}"; \
		test "$${#digest_value}" -eq 64; \
		case "$$digest_value" in *[!0-9a-f]*) echo "tofu guard refused: invalid plan digest" >&2; exit 2 ;; esac; \
		printf '%s\n' "$$digest_value" > "$$digest_tmp"; \
		chmod 0600 "$$plan" "$$digest_tmp"; \
		mv -- "$$digest_tmp" "$$digest_file"; \
		published=1; \
		trap - EXIT; \
		echo "tofu plan saved: $$plan"; \
		echo "tofu action summary: $${TOFU_ACTION_SUMMARY}"; \
		echo "tofu approval record: $${TOFU_APPROVAL_RECORD}"

tofu-apply: tofu-guard
	@set -eu; \
		plan="$${TOFU_PLAN}"; \
		digest_file="$$plan.sha256"; \
		test -f "$$plan" && test ! -L "$$plan" || { echo "tofu guard refused: saved plan is missing" >&2; exit 2; }; \
		test -f "$$digest_file" && test ! -L "$$digest_file" || { echo "tofu guard refused: plan digest is missing" >&2; exit 2; }; \
		test "$$(stat -c '%a' "$$plan")" = 600 || { echo "tofu guard refused: plan mode is not 0600" >&2; exit 2; }; \
		test "$$(stat -c '%a' "$$digest_file")" = 600 || { echo "tofu guard refused: plan digest mode is not 0600" >&2; exit 2; }; \
		digest_output="$$(sha256sum "$$plan")"; actual_digest="$${digest_output%% *}"; \
		test "$${#actual_digest}" -eq 64; case "$$actual_digest" in *[!0-9a-f]*) echo "tofu guard refused: invalid plan digest" >&2; exit 2 ;; esac; \
		recorded_digest="$$(cat "$$digest_file")"; \
		test "$$recorded_digest" = "$$actual_digest" || { echo "tofu guard refused: saved plan digest changed" >&2; exit 2; }; \
		test -n "$${TOFU_PLAN_DIGEST}" && test "$${TOFU_PLAN_DIGEST}" = "$$actual_digest" || { echo "tofu guard refused: supplied plan digest does not match" >&2; exit 2; }; \
		approval_record="$${TOFU_APPROVAL_RECORD}"; action_summary="$${TOFU_ACTION_SUMMARY}"; private_base="$${TOFU_PLAN_BASE}"; \
		test -f "$$approval_record" && test ! -L "$$approval_record" || { echo "tofu guard refused: approval record is missing" >&2; exit 2; }; \
		test -f "$$action_summary" && test ! -L "$$action_summary" || { echo "tofu guard refused: action summary is missing" >&2; exit 2; }; \
		resolved_approval="$$(realpath -e -- "$$approval_record")"; resolved_summary="$$(realpath -e -- "$$action_summary")"; \
		test "$$resolved_approval" = "$$approval_record" && test "$$resolved_summary" = "$$action_summary" || { echo "tofu guard refused: approval evidence is not canonical" >&2; exit 2; }; \
		case "$$resolved_approval" in "$$private_base"/*) ;; *) echo "tofu guard refused: approval record is outside private plan state" >&2; exit 2 ;; esac; \
		case "$$resolved_summary" in "$$private_base"/*) ;; *) echo "tofu guard refused: action summary is outside private plan state" >&2; exit 2 ;; esac; \
		test "$$(stat -c '%a' "$$approval_record")" = 600 || { echo "tofu guard refused: approval record mode is not 0600" >&2; exit 2; }; \
		test "$$(stat -c '%a' "$$action_summary")" = 600 || { echo "tofu guard refused: action summary mode is not 0600" >&2; exit 2; }; \
		test -s "$$action_summary" || { echo "tofu guard refused: action summary is empty" >&2; exit 2; }; \
		python3 "$(INIT_ROOT)/$(TOFU_APPROVAL_VALIDATOR)" --record "$$approval_record" --project "$${TOFU_PROJECT}" --root "$${TOFU_ROOT}" --commit "$${TOFU_COMMIT}" --approval "$${TOFU_APPROVAL}" --digest "$$actual_digest"; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" init -input=false -lockfile=readonly -no-color; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" apply -input=false -no-color "$$plan"

tofu-verify: tofu-guard
	@set -eu; \
		plan="$${TOFU_PLAN}"; \
		vars="$${TOFU_VARS}"; \
		test -n "$$vars" || { echo "tofu guard refused: private variable file is required" >&2; exit 2; }; \
		test -f "$$vars" && test ! -L "$$vars" || { echo "tofu guard refused: private variable file is missing" >&2; exit 2; }; \
		resolved_vars="$$(realpath -e -- "$$vars")"; \
		test "$$resolved_vars" = "$$vars" || { echo "tofu guard refused: variable file is not canonical" >&2; exit 2; }; \
		private_base="$${TOFU_PLAN_BASE}"; \
		case "$$resolved_vars" in "$$private_base"/*) ;; *) echo "tofu guard refused: variable file is outside private plan state" >&2; exit 2 ;; esac; \
		test "$$(stat -c '%a' "$$resolved_vars")" = 600 || { echo "tofu guard refused: variable file mode is not 0600" >&2; exit 2; }; \
		digest_file="$$plan.sha256"; \
		test -f "$$plan" && test ! -L "$$plan" || { echo "tofu guard refused: saved plan is missing" >&2; exit 2; }; \
		test -f "$$digest_file" && test ! -L "$$digest_file" || { echo "tofu guard refused: plan digest is missing" >&2; exit 2; }; \
		test "$$(stat -c '%a' "$$plan")" = 600 || { echo "tofu guard refused: plan mode is not 0600" >&2; exit 2; }; \
		test "$$(stat -c '%a' "$$digest_file")" = 600 || { echo "tofu guard refused: plan digest mode is not 0600" >&2; exit 2; }; \
		digest_output="$$(sha256sum "$$plan")"; actual_digest="$${digest_output%% *}"; \
		test "$${#actual_digest}" -eq 64; case "$$actual_digest" in *[!0-9a-f]*) echo "tofu guard refused: invalid plan digest" >&2; exit 2 ;; esac; \
		recorded_digest="$$(cat "$$digest_file")"; \
		test "$$recorded_digest" = "$$actual_digest" || { echo "tofu guard refused: saved plan digest changed" >&2; exit 2; }; \
		test -n "$${TOFU_PLAN_DIGEST}" && test "$${TOFU_PLAN_DIGEST}" = "$$actual_digest" || { echo "tofu guard refused: supplied plan digest does not match" >&2; exit 2; }; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" init -input=false -lockfile=readonly -no-color; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" output -json -no-color; \
		set +e; \
		"$${TOFU}" -chdir="$(INIT_ROOT)/opentofu/gcp/$${TOFU_ROOT}" plan \
			-input=false -no-color -detailed-exitcode \
			-var-file="$$vars" \
			-var="project_id=$${TOFU_PROJECT}"; \
			result="$$?"; \
		set -e; \
		if [ "$$result" -eq 2 ]; then echo "tofu verify refused: zero-change plan has changes" >&2; exit 2; fi; \
		test "$$result" -eq 0 || { echo "tofu verify refused: zero-change plan failed" >&2; exit "$$result"; }

gcs-backup-check:
	$(TOFU) fmt -check -diff "$(GCS_BACKUP_ROOT)"

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
