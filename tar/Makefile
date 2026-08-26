# TAR owns verified WATCH charts and runtime image pins.
PYTHON ?= python3
WATCH_VALIDATOR := scripts/validate_watch.py

.PHONY: check test check-watch-supply

check: test

test: check-watch-supply
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

check-watch-supply:
	$(PYTHON) $(WATCH_VALIDATOR)
