# K3s runtime contract

INIT owns the K3s server runtime on the three direct-GCP guests and the three
Proxmox guests. Each cluster is configured and verified separately through the
private rendered inventory groups `gcp_k3s_servers` and
`proxmox_k3s_servers`.

## Private inputs

The runtime playbooks require these values from private SUDO/TAR handoffs:

- `shell_k3s_cluster_name`: `gcp` or `proxmox`.
- `shell_k3s_target_group`: one rendered cluster group only.
- `shell_k3s_api_endpoint`: an HTTPS endpoint ending in `:6443`.
- `shell_k3s_api_host`: the endpoint host used for the K3s TLS SAN.
- `shell_k3s_version`: the pinned K3s version reported by the binary.
- `shell_k3s_binary_path` and `shell_k3s_binary_sha256`: the private TAR
  artifact and its lowercase SHA-256 digest.
- `shell_k3s_token_path`: a private SUDO/TAR token-file path.
- `shell_k3s_pod_cidr` and `shell_k3s_service_cidr`: distinct cluster ranges.
- Proxmox uses API VIP `10.66.0.200`, a private guest interface, and a
  private TAR Kube-VIP image digest.

The token is sensitive runtime material. Its handling rules live in the
[`runtime.md`](runtime.md) guide. The input file and generated kubeconfig
remain under private ignored state described in that guide.

## Runtime behavior

The configuration playbook assumes the Debian guest baseline has already been
applied. It installs the checksum-verified K3s binary, writes a mode-0600
token and config, initializes embedded etcd on the first server, waits for
`etcd` and `etcd-readiness` on `/readyz?verbose` before the next server
starts, and joins later servers through the stable endpoint. For the Proxmox
group it also waits for the `kube-vip-ds` DaemonSet to become ready on the
first server so the `10.66.0.200` VIP is announced before joiners probe it.
K3s uses its default Flannel VXLAN backend for this foundation and disables
bundled ServiceLB and Traefik so later ownership stays explicit.

For the Proxmox group, INIT renders a host-networked Kube-VIP DaemonSet before
K3s starts. It uses ARP leader election for the control-plane VIP and leaves
service load balancing disabled.

The playbook stops before mutation in Ansible check mode. On failure, its
rescue path restores `fstab` and swap where possible, stops and disables K3s,
and removes a unit or Kube-VIP manifest created by that run. Review the guest
before another run.

## Verification boundary

The verification playbook is read-only. It checks the service, private runtime
file modes, embedded-etcd member directory, exact Ready node set, declared
K3s version, Kube-VIP readiness when enabled, and stable API readiness. CNI
replacement, storage, identity, delivery, and application workloads remain
separate lifecycle decisions.

Kubeconfig output is written only under ignored `.local/ansible/kubeconfig/`
state. Live execution, guest startup, OpenTofu changes, and cluster proof
require separate approval.
