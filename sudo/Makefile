# SUDO owns value-free access and private-input contract validation.
PYTHON ?= python3
SUDO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: check test access-check stateful-check input-check

check: test access-check input-check

test:
	$(PYTHON) -m unittest discover -s $(SUDO_ROOT)/tests -p 'test_*.py'

access-check:
	$(PYTHON) $(SUDO_ROOT)/scripts/validate_access_contracts.py

stateful-check:
	$(PYTHON) $(SUDO_ROOT)/scripts/validate_stateful_inputs.py

input-check:
	$(PYTHON) $(SUDO_ROOT)/scripts/generate_release_feed_inputs.py \
		--check-only --approval source-only
