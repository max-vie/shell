# TAR owns verified WATCH charts and runtime image pins.
PYTHON ?= python3
WATCH_VALIDATOR := scripts/validate_watch.py
WATCH_LOGS_VALIDATOR := scripts/validate_watch_logs.py
WATCH_LOGS_STAGER := scripts/stage_watch_logs.py
WATCH_LOGS_LOCAL_ROOT ?= ../.local/tar/watch

.PHONY: check test check-watch-supply check-watch-logs-supply stage-watch-logs

check: test

test: check-watch-supply check-watch-logs-supply
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

check-watch-supply:
	$(PYTHON) $(WATCH_VALIDATOR)

check-watch-logs-supply:
	$(PYTHON) $(WATCH_LOGS_VALIDATOR)

stage-watch-logs: check-watch-logs-supply
	$(PYTHON) $(WATCH_LOGS_STAGER) --local-root "$(WATCH_LOGS_LOCAL_ROOT)"
