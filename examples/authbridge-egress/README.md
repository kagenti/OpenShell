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

## Prerequisites

1. A working OpenShell install with a `team1` tenant gateway, per the
   [Kagenti Sandbox Guide](https://github.com/kagenti/kagenti/blob/main/docs/sandbox-guide.md).
2. **Check out the unmerged feature branches this integration depends on:**
   - this repo (OpenShell) on **`feat/authbridge-egress`** (adds `NetworkMode::External`);
   - a [kagenti-extensions](https://github.com/kagenti/kagenti-extensions) checkout on
     **`feat/placeholder-resolve-plugin`** (the `placeholder-resolve` plugin).

   `01-build-images.sh` fails fast if a checkout is missing its feature.
3. `kubectl`, `jq`, `openssl`, and `podman` (or Docker).

## Quick start

```bash
cd examples/authbridge-egress

# Set these once: your checkouts + your upstream LLM endpoint.
export EXT_DIR=~/src/kagenti-extensions        # kagenti-extensions @ feat/placeholder-resolve-plugin
export KAGENTI_DIR=~/src/kagenti               # kagenti repo (lets step 1 redeploy the gateway)
export LLM_URL=https://your-litellm.example.com

# 1. Build + load both images AND redeploy the team1 gateway (gateway tag auto-pinned),
#    then log back in (the gateway restart expires your CLI token).
./01-build-images.sh
openshell gateway login

# 2. CA + k8s objects (LLM_TOKEN keeps the real token off the command line).
LLM_TOKEN='<your real LLM token>' ./02-setup-authbridge.sh

# 3. Create a provider-bound sandbox, then inject AuthBridge.
openshell provider create --name claude --type anthropic \
  --credential ANTHROPIC_AUTH_TOKEN --config ANTHROPIC_BASE_URL="$LLM_URL"
openshell inference set --provider claude --model claude-sonnet-4-6 --no-verify
openshell sandbox create --provider claude -- sleep infinity
openshell sandbox list                         # note the generated name, then:
SANDBOX=<sandbox-name>
./03-inject-authbridge.sh "$SANDBOX" "$LLM_URL"

# 4. Verify.
./04-verify.sh "$SANDBOX"
```

> If you don't set `KAGENTI_DIR`, step 1 instead prints the `deploy-tenant.sh` command
> to run yourself (the gateway tag must be pinned).

## Common env knobs

| Var | Default | Used by |
|-----|---------|---------|
| `EXT_DIR` | _(required)_ | 01 |
| `KAGENTI_DIR` | _(optional — if set, 01 auto-redeploys the gateway)_ | 01 |
| `NS` | `team1` | 01, 02, 03, 04 |
| `CLUSTER` | `kagenti` | 01 |
| `ARCH` | `arm64` | 01 |
| `GATEWAY_TAG` | `mvp-v2-7784be8` | 01 |
| `SUPERVISOR_IMAGE` | `localhost/openshell/supervisor:dev` | 01 |
| `AUTHBRIDGE_IMAGE` | `localhost/authbridge-proxy:dev` | 01, 03 |
| `LLM_TOKEN` | _(optional)_ | 02 |

See the [guide](../../docs/sandboxes/authbridge-egress.mdx) for troubleshooting,
the architecture diagram, and limitations.
