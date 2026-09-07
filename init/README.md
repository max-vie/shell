# INIT

The provisioning boundary for SHELL's GCP and Proxmox foundations.

## Contents

- `opentofu/` declares shared GCP resources, K3s clusters, the nested Proxmox
  host, Proxmox guests, and the GCS backup foundation.
- `ansible/` contains host and guest configuration and verification.
- `images/` contains the Debian guest-image workflow.
- `scripts/` renders inventory and runs fixed controllers.

## Boundary

INIT checks source, syntax, and locked OpenTofu roots in isolated workspaces.
Provider state, guest startup, cluster convergence, and backup operation
require separate evidence.

## Documentation

- [Platform architecture](../man/docs/architecture/platform-nodes.md)
- [Runtime guidance](docs/runtime.md)
- [K3s runtime](docs/k3s-runtime.md)
