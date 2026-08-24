# Temporary runtime authentication and secrets

This file is temporary. It documents how INIT passes runtime authentication and
secrets to the OpenTofu providers until OpenBao takes over secret management.
When OpenBao resolves the secrets setup, delete this file and move the guidance
into the OpenBao handoff.

The Proxmox provider reads its connection details from the private process
environment:

- `PROXMOX_VE_ENDPOINT` is the API endpoint.
- `PROXMOX_VE_API_TOKEN` is the API token. Keep this value private.

Do not put the token in HCL, `.tfvars`, state, saved plans, Git, or shell
history. Set the variables only for the OpenTofu process, through a private
wrapper or secret handoff. Use `umask 077` for any local handoff files and
remove the variables after the command exits.

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

## Private state and plans

OpenTofu state remains under the private `.local` directory:

- `.local/opentofu/gcp/shared/`
- `.local/opentofu/gcp/k3s/`
- `.local/opentofu/proxmox/k3s/`

Keep state and saved plans private because they contain infrastructure details,
even when provider credentials are supplied through the environment.
