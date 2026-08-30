# SHELL platform nodes

SHELL defines two independent K3s variants and two shared platform nodes.
This page lists their intended placement and separates assigned node addresses
from proposed workload addresses.

## Topology

```mermaid
flowchart LR
    SHARED["Shared platform<br/>identity-01<br/>delivery-01"]
    GCP["Direct GCP<br/>gcp-k3s-01 to 03"]
    PROXMOX["Nested Proxmox on GCP<br/>proxmox-host<br/>proxmox-k3s-01 to 03"]

    SHARED --> GCP
    SHARED --> PROXMOX
```

## Shared platform nodes

The shared nodes support both K3s variants. The design places them in the GCP
environment; no separate Proxmox copies are planned.

| Node | Contract address | Role |
| --- | --- | --- |
| `identity-01` | `10.77.0.210` | FreeIPA identity and internal DNS |
| `delivery-01` | `10.77.0.211` | Forgejo and rootless runner |

## Proposed GCP service endpoints

The release-feed decision proposes two addresses next to the assigned
Proxmox host address. `[OPEN]` means the source names the address but no GCP
reservation or routing implementation exists.

| Address | Lifecycle owner | Intended use | Status |
| --- | --- | --- | --- |
| `10.77.0.220` | INIT | `proxmox-host` | Assigned by the GCP host contract |
| `10.77.0.221` | MAKE | Harbor registry and chart source | `[OPEN]` GCP reservation and routing |
| `10.77.0.222` | MAKE | release-feed HTTPS service | `[OPEN]` GCP reservation and routing |

The proposed Argo CD and OpenBao services are ClusterIP-only. Argo CD would
use loopback-bound operator access, and the release-feed pod would reach
OpenBao inside the cluster. These are source designs, not deployed endpoint
or reachability evidence.

## GCP K3s Cluster

The primary K3s cluster will run on three direct GCP virtual machines.

| Node | Cluster | Role |
| --- | --- | --- |
| `gcp-k3s-01` | `gcp` | K3s server and embedded etcd member |
| `gcp-k3s-02` | `gcp` | K3s server and embedded etcd member |
| `gcp-k3s-03` | `gcp` | K3s server and embedded etcd member |

## Proxmox K3s Cluster

The Proxmox variant will use one nested Proxmox host and three Debian K3s
guests. The host runs as a private GCP VM with nested virtualization enabled.

| Node | Placement | Role |
| --- | --- | --- |
| `proxmox-host` | Private GCP VM at `10.77.0.220` | Proxmox virtualization host with nested virtualization |
| `proxmox-k3s-01` | Proxmox guest | K3s server and embedded etcd member |
| `proxmox-k3s-02` | Proxmox guest | K3s server and embedded etcd member |
| `proxmox-k3s-03` | Proxmox guest | K3s server and embedded etcd member |

The GCP VPC remains `10.77.0.0/24`. The nested guest bridge uses the separate
`10.66.0.0/24` network with gateway `10.66.0.1`; the three guests use
`10.66.0.201` through `10.66.0.203`. Guest traffic is masqueraded through the
private GCP host, and Ansible reaches guests through that host. The guests use
`identity-01` at `10.77.0.210` as their declared DNS server. The GCP network,
nested bridge, and guest interfaces use an MTU of `1460`.
