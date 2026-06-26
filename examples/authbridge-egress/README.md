<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->
# AuthBridge Egress Integration (example)

Route an OpenShell sandbox's egress through an [AuthBridge](https://github.com/kagenti/kagenti-extensions/tree/main/authbridge)
sidecar using `NetworkMode::External`. AuthBridge performs TLS interception,
credential injection (the sandbox holds only an `openshell:resolve:env:<KEY>`
placeholder), and per-session traffic observability, while OpenShell keeps
kernel-level isolation and hard egress containment.

Full walkthrough and concepts: **[docs/sandboxes/authbridge-egress.mdx](../../docs/sandboxes/authbridge-egress.mdx)**.

> Experimental PoC — hand-wires one sandbox pod via a `Sandbox` CR patch (no
> operator/webhook). Requires the `feat/authbridge-egress` OpenShell branch and the
> `feat/placeholder-resolve-plugin` kagenti-extensions branch.

## Scripts

| Script | What it does |
|--------|--------------|
| `01-build-images.sh` | Build the External-capable supervisor image + the AuthBridge proxy image; load both into kind |
| `02-setup-authbridge.sh` | Generate the TLS-bridge CA; create the `authbridge-ca` Secret, `authbridge-sidecar-config` ConfigMap (from `config.yaml`), and `authbridge-cred` Secret |
| `03-inject-authbridge.sh` | Patch a sandbox's `podTemplate` (External mode + AuthBridge sidecar + volumes, auto-handling the env index and the revision-keyed placeholder) and recreate the pod |
| `04-verify.sh` | End-to-end checks: External mode, AuthBridge up, `claude` → LLM, placeholder-only env, egress containment, session API |
| `config.yaml` | The AuthBridge sidecar config (forward proxy + tls_bridge + parsers + placeholder-resolve) |

## Quick start

Prerequisite: a working OpenShell install with a `team1` tenant gateway, per the
[Kagenti Sandbox Guide](https://github.com/kagenti/kagenti/blob/main/docs/sandbox-guide.md).

```bash
cd examples/authbridge-egress

# 1. Build + load both images (point EXT_DIR at your kagenti-extensions checkout)
EXT_DIR=~/src/kagenti-extensions ./01-build-images.sh
# then point the gateway at the supervisor image (Kagenti repo); pin the gateway tag
# too — the chart default v0.0.56-rc.3 predates the inference-scoped-provider-lookup fix:
#   scripts/openshell/deploy-tenant.sh team1 \
#     --set supervisorImage.repository=localhost/openshell/supervisor \
#     --set supervisorImage.tag=dev \
#     --set images.gateway.tag=mvp-v2-7784be8 \
#     --set sandboxImagePullPolicy=Never
# (re-run 'openshell gateway login' after the gateway restart)

# 2. CA + k8s objects (LLM_TOKEN keeps the real token off the command line)
LLM_TOKEN='<your real LLM token>' ./02-setup-authbridge.sh

# 3. Create a provider-bound sandbox, then inject AuthBridge
openshell provider create --name claude --type anthropic \
  --credential ANTHROPIC_AUTH_TOKEN --config ANTHROPIC_BASE_URL=https://<your-llm-url>
openshell inference set --provider claude --model claude-sonnet-4-6 --no-verify
openshell sandbox create --provider claude -- sleep infinity
openshell sandbox list   # note the generated name
./03-inject-authbridge.sh <sandbox-name> https://<your-llm-url>

# 4. Verify
./04-verify.sh <sandbox-name>
```

## Common env knobs

| Var | Default | Used by |
|-----|---------|---------|
| `NS` | `team1` | 02, 03, 04 |
| `CLUSTER` | `kagenti` | 01 |
| `ARCH` | `arm64` | 01 |
| `EXT_DIR` | _(required)_ | 01 |
| `SUPERVISOR_IMAGE` | `localhost/openshell/supervisor:dev` | 01 |
| `AUTHBRIDGE_IMAGE` | `localhost/authbridge-proxy:dev` | 01, 03 |
| `LLM_TOKEN` | _(optional)_ | 02 |

See the [guide](../../docs/sandboxes/authbridge-egress.mdx) for troubleshooting,
the architecture diagram, and limitations.
