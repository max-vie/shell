# Contributing

SHELL welcomes focused fixes, tests, and documentation improvements.

Keep a change within one lifecycle owner when possible. Cross-boundary changes
should describe each handoff and the owner of the resulting behavior. Discuss
changes to ownership, dependencies, or live permissions before implementing
them.

Run the check target for every lifecycle touched by a change:

```text
make -C sudo check
make -C tar check
make -C init check
make -C make check
make -C watch check
```

In a change description, state the behavior or decision being changed, the
checks that passed, and the evidence boundary. Keep credentials, private
inputs, state, plans, generated images, and copied secret output out of Git.

Ask before live infrastructure, guest, image, registry, Kubernetes, recovery,
external-service, commit, or push operations.
