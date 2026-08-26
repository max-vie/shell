# K3s runtime contract

INIT owns the K3s server runtime on the three direct-GCP guests and the three
Proxmox guests. Each cluster is configured and verified separately through the
private rendered inventory groups `gcp_k3s_servers` and
`proxmox_k3s_servers`.

## Private inputs

The runtime playbooks require values from separate private SUDO, TAR, and INIT
handoffs:

- `shell_k3s_cluster_name`: `gcp` or `proxmox`.
- `shell_k3s_target_group`: the exact matching rendered cluster group. There
  is no default target.
- `shell_k3s_api_endpoint`: an HTTPS endpoint ending in `:6443`.
- `shell_k3s_api_host`: the endpoint host used for the K3s TLS SAN.
- `shell_k3s_version`: the pinned K3s version reported by the binary.
- `shell_k3s_binary_path` and `shell_k3s_binary_sha256`: the private TAR
  artifact and its lowercase SHA-256 digest.
- `shell_k3s_pod_cidr` and `shell_k3s_service_cidr`: distinct cluster ranges.
- Proxmox uses API VIP `10.66.0.200`, a private INIT guest-interface input,
  and a private TAR Kube-VIP image digest.

SUDO supplies one separate short server token for each cluster at private
ignored paths. INIT derives the fixed token path from the selected cluster and
requires exactly 64 lowercase hexadecimal characters; callers cannot supply a
different token path. The first server uses the short form because its
self-signed certificate authority does not exist until startup. K3s later
writes secure token material that must remain protected and be backed up with
the matching datastore. Its handling rules live in the
[`runtime.md`](runtime.md) guide. The input file and generated kubeconfig
remain under private ignored state described in that guide.

## Controller launcher

Use the INIT controller launcher for K3s configuration and verification. It
accepts only `gcp` or `proxmox` and derives the matching Ansible group and
playbook. It does not accept arbitrary target groups, `--limit`, or
`--start-at-task` values.

Before Ansible starts, the launcher checks the generated inventory, the
TAR-to-INIT K3s handoff, the staged binary checksum, and the private cluster
runtime variables. The runtime variable files are
`.local/ansible/k3s-runtime/gcp.json` and
`.local/ansible/k3s-runtime/proxmox.json`. GCP requires the pod and service
CIDRs. Proxmox also requires the Kube-VIP interface. These files contain no
credentials and must be mode `0600` below mode-`0700` private directories.

The generated topology inventory is combined with the private connection
inventory at `.local/ansible/connection-inventory.yml`. The latter supplies
the user, SSH route, and reviewed host-key settings. It remains a local
mode-`0600` input and is never replaced by the generated topology file.
Its effective target variables may add only `ansible_connection`,
`ansible_user`, `ansible_ssh_common_args`, `ansible_ssh_private_key_file`,
`ansible_python_interpreter`, `ansible_port`, and `gcp_known_hosts_file`.
The launcher renders both inventories with `ansible-inventory` before starting
the playbook. It rejects connection plugins other than SSH, root login,
non-port-22 SSH, missing strict host-key checking, unsupported connection
variables, and connection values that change the rendered target contract. GCP
routes must retain the generated IAP host, project, and zone expressions.
Proxmox routes must use a proxy through `proxmox-host` or `10.77.0.220`.
The shared target preflight repeats these connection checks inside Ansible.

The launcher writes merged Ansible variables to a temporary mode-`0600` file
and removes it after Ansible exits. Token values remain owned and read by the
existing INIT playbook from the fixed SUDO paths.

## Runtime behavior

The shared preflight rejects an invented group, a cluster/group mismatch, an
altered or reordered node set, or a partial host selection when it runs.
Inventory hosts must carry the expected K3s role, cluster, literal address,
transport, and Debian 13 metadata.

The first node is always `*-k3s-01`, which preserves the embedded-etcd seed
role.

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

Direct playbook selectors can bypass in-play gates. Treat zero-host runs,
`--start-at-task`, skipped preflight tasks, and direct playbook commands as
unsupported evidence. Live K3s execution remains unauthorized until a fixed
controller launcher closes that boundary.
