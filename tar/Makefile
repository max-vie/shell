# TAR owns verified charts, images, staging policy, and publication handoffs.
PYTHON ?= python3
WATCH_VALIDATOR := scripts/validate_watch.py
WATCH_LOGS_VALIDATOR := scripts/validate_watch_logs.py
WATCH_LOGS_STAGER := scripts/stage_watch_logs.py
WATCH_LOGS_LOCAL_ROOT ?= ../.local/tar/watch
PLATFORM_VALIDATOR := scripts/validate_platform_supply.py
RELEASE_FEED_VALIDATOR := scripts/validate_release_feed.py
PLATFORM_STAGER := scripts/stage_platform.py
PLATFORM_CHART_PUBLISHER := scripts/publish_platform_charts.py
PLATFORM_IMAGE_PUBLISHER := scripts/publish_platform_images.py
PLATFORM_LOCAL_ROOT ?= ../.local/tar/platform-addons
INVENTORY ?= ../.local/ansible/inventory.json
CONNECTION_INVENTORY ?= ../.local/ansible/connection-inventory.yml

.PHONY: check test check-watch-supply check-watch-logs-supply check-platform-supply check-release-feed-supply stage-watch-logs stage-platform stage-platform-addons publish-platform-charts publish-platform-images publish-release-feed

check: test check-platform-supply check-release-feed-supply

test: check-watch-supply check-watch-logs-supply
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py'

check-watch-supply:
	$(PYTHON) $(WATCH_VALIDATOR)

check-watch-logs-supply:
	$(PYTHON) $(WATCH_LOGS_VALIDATOR)

check-platform-supply:
	$(PYTHON) $(PLATFORM_VALIDATOR)
	$(PYTHON) scripts/validate_harbor.py

check-release-feed-supply:
	$(PYTHON) $(RELEASE_FEED_VALIDATOR)

stage-watch-logs: check-watch-logs-supply
	$(PYTHON) $(WATCH_LOGS_STAGER) --local-root "$(WATCH_LOGS_LOCAL_ROOT)"

stage-platform-addons: check-platform-supply
	$(PYTHON) $(PLATFORM_STAGER) --local-root "$(PLATFORM_LOCAL_ROOT)"

stage-platform: stage-platform-addons

publish-platform-charts:
	@printf '%s\n' 'platform chart publication is blocked until Helm provenance, isolated credentials, and Argo image pins exist' >&2
	@exit 2

publish-platform-images:
	@printf '%s\n' 'platform image publication is blocked until Harbor routing and robot custody exist' >&2
	@exit 2

publish-release-feed:
	@printf '%s\n' 'release-feed publication is blocked until immutable tags and a promotion handoff exist' >&2
	@exit 2
