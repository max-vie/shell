# MAN

Architecture decisions, runbooks, and operating records for SHELL.

## Documentation

- [Platform architecture](docs/architecture/platform-nodes.md)
- [Release-feed bootstrap](docs/runbooks/release-feed-bootstrap.md)
- [WATCH Grafana recovery](docs/runbooks/watch-grafana-recovery.md)
- [Architecture decisions](docs/adr/)
- [SUDO token decision](../sudo/docs/adr/001-use-sudo-owned-k3s-server-tokens.md)

## Boundary

MAN records why the platform is shaped this way and what each source slice can
prove. It does not provision hosts, transfer artifacts, mutate workloads, or
operate monitoring.
