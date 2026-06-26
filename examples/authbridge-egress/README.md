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
2. **This OpenShell repo on the `feat/authbridge-egress` branch** (adds
   `NetworkMode::External`) — you're already on it if you're reading this, and the
   supervisor image is built from it.

   The kagenti-extensions **`placeholder-resolve`** plugin is **cloned automatically** by
   `01-build-images.sh` (from `huang195/kagenti-extensions @ feat/placeholder-resolve-plugin`
   by default — override with `EXT_REPO`/`EXT_REF`, or set `EXT_DIR` to a local checkout).
   The script fails fast if the resolved source is missing the plugin.
3. `kubectl`, `jq`, `openssl`, and `podman` (or Docker).

## Quick start

```bash
cd examples/authbridge-egress

# Set this once: your upstream LLM endpoint.
export LLM_URL=https://your-litellm.example.com
# kagenti-extensions is cloned for you (override: EXT_DIR / EXT_REPO / EXT_REF).
# The kagenti repo is auto-detected beside this OpenShell checkout; set KAGENTI_DIR if it's elsewhere.

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

> Step 1 auto-detects the kagenti repo beside this OpenShell checkout (`../kagenti`). If it
> lives elsewhere, set `KAGENTI_DIR`; if it can't be found, step 1 prints the
> `deploy-tenant.sh` command to run yourself (the gateway tag must be pinned).

## Common env knobs

| Var | Default | Used by |
|-----|---------|---------|
| `EXT_DIR` | _(optional — local kagenti-extensions checkout; else auto-cloned)_ | 01 |
| `EXT_REPO` | `https://github.com/huang195/kagenti-extensions` | 01 |
| `EXT_REF` | `feat/placeholder-resolve-plugin` | 01 |
| `KAGENTI_DIR` | _(auto: `../kagenti` beside OpenShell; used to redeploy the gateway)_ | 01 |
| `NS` | `team1` | 01, 02, 03, 04 |
| `CLUSTER` | `kagenti` | 01 |
| `ARCH` | `arm64` | 01 |
| `GATEWAY_TAG` | `mvp-v2-7784be8` | 01 |
| `SUPERVISOR_IMAGE` | `localhost/openshell/supervisor:dev` | 01 |
| `AUTHBRIDGE_IMAGE` | `localhost/authbridge-proxy:dev` | 01, 03 |
| `LLM_TOKEN` | _(optional)_ | 02 |

See the [guide](../../docs/sandboxes/authbridge-egress.mdx) for troubleshooting,
the architecture diagram, and limitations.
