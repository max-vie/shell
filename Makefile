# Run each lifecycle owner's source checks in dependency order.
.PHONY: check

check:
	$(MAKE) -C sudo check
	$(MAKE) -C tar check
	$(MAKE) -C init check
	$(MAKE) -C make check
	$(MAKE) -C watch check
