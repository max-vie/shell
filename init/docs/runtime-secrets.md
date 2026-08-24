# Temporary runtime authentication and secrets

This file is temporary. It documents how INIT passes runtime authentication and
secrets to the OpenTofu providers until OpenBao takes over secret management.
When OpenBao resolves the secrets setup, delete this file and move the guidance
into the OpenBao handoff.

The Proxmox provider reads its connection details from the private process
environment:

- `PROXMOX_VE_ENDPOINT` is the API endpoint.
- `PROXMOX_VE_API_TOKEN` is the API token. Keep this value private.

The local provider also needs two IAP TCP tunnels because the Proxmox host has
no external address: API port `8006` is exposed on local port `18006`, and SSH
port `22` is exposed on local port `10022`. Set `PROXMOX_VE_ENDPOINT` to the
private local API endpoint without an `/api2/json` suffix, and supply the OS
Login account through the ignored OpenTofu variables. The SSH upload uses the
current `SSH_AUTH_SOCK`; do not put a private key in HCL. A private wrapper
must start both tunnels and clean them up after OpenTofu exits.
Set `PROXMOX_VE_TMPDIR` to a private directory with enough disk space for the
prepared image; the provider can stage local image uploads there.

Keep TLS verification enabled. The local API name and the control machine's
trust store must validate the Proxmox certificate through the tunnel; a
loopback endpoint with an untrusted or mismatched certificate is not an
acceptable reason to set `PROXMOX_VE_INSECURE=true`.

Do not put the token in HCL, `.tfvars`, state, saved plans, Git, or shell
history. Set the variables only for the OpenTofu process, through a private
wrapper or secret handoff. Use `umask 077` for any local handoff files and
remove the variables after the command exits.

The guest root sets Proxmox cloud-init package upgrades to `false`. The BPG
provider documents that field as available only to a `root@pam` identity. Use
a privilege-separated `root@pam` API token with ACLs limited to the INIT pool,
image datastore, guest datastore, bridge, and declared VM IDs. Do not use an
unrestricted root token. Replace this exception when INIT gains a separate
cloud-init data handoff that works with a dedicated automation user.
The current INIT playbooks do not create that API identity, token, or ACL
tree. Supply and review them through the private SUDO handoff before any
Proxmox plan.

## GCP authentication

The Google provider blocks set the project and region. They do not contain a
credential or read one from a `.tfvars` file. The provider uses Google
Application Default Credentials.

For local work, create user ADC with `gcloud auth application-default login`.
For CI or execution outside Google Cloud, use a Workload Identity Federation
external credential configuration and set `GOOGLE_APPLICATION_CREDENTIALS` to
its private path. Keep that file outside the checkout. A long-lived service
account key is a fallback and follows the same handling rules.

`project_id` identifies the GCP project and is not a secret. Do not add a
`credentials` attribute to the provider blocks or put credential JSON in HCL,
`.tfvars`, state, saved plans, or Git.

Ansible reaches direct GCP guests through an IAP `ProxyCommand`. The generated
inventory supplies each instance name, zone, and validated project ID; the
ignored private inventory supplies the OS Login user, SSH agent or key handoff,
and reviewed host-key policy. Keep the IAP route private and do not put a
private key path or generated inventory in Git. The GCP guest baseline requires
the pinned source image to include `google-guest-agent` and
`google-compute-engine-oslogin`. Use a Google-provided Debian 13 image or
record equivalent package evidence for a reviewed custom image; the baseline
does not install an unreviewed Google APT repository. Because the baseline
uses Ansible `become`, the OS Login identity also needs the reviewed
administrative login/sudo grant; INIT does not create or broaden that IAM
binding.

## Private state and plans

OpenTofu state remains under the private `.local` directory:

- `.local/opentofu/gcp/shared/`
- `.local/opentofu/gcp/k3s/`
- `.local/opentofu/gcp/proxmox-host/`
- `.local/opentofu/proxmox/k3s/`

Keep state and saved plans private because they contain infrastructure details,
even when provider credentials are supplied through the environment.

The Debian image workflow also writes downloaded sources, prepared images,
manifests, and generated image inputs under `.local/init-images/`. Keep those
files private; only the source checksum and preparation scripts belong in Git.
`INIT_PUBLIC_KEY_FILE` must point to one public SSH key. `SHELL_IMAGE_ROOT`, if
set, must remain below the checkout's private `.local` directory.
