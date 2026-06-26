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

**1. Set your values** — edit these for your environment:

```bash
cd examples/authbridge-egress

export LLM_URL=https://your-litellm.example.com    # your upstream LLM endpoint (Bearer-auth)
export LLM_TOKEN='sk-...'                           # the real LLM token (read by step 2 from the env)
```

Everything else has a working default — override only if needed: `EXT_DIR`/`EXT_REPO`/`EXT_REF`
(the kagenti-extensions plugin, cloned for you), `KAGENTI_DIR` (the kagenti repo, auto-detected
beside this OpenShell checkout), and `NS`/`CLUSTER`/`ARCH`. See the table below.

**2. Run** — copy-paste as-is:

```bash
SANDBOX=authbridge-egress    # the sandbox this run creates (rename if you like)

# Build + load both images, redeploy the team1 gateway, then re-authenticate
# (the restart expires your CLI token; if `gateway login` errors, see the note below).
./01-build-images.sh
openshell gateway login

# CA + Kubernetes objects (reads $LLM_TOKEN from the environment).
./02-setup-authbridge.sh

# Provider-bound sandbox, then inject the AuthBridge sidecar.
openshell provider create --name claude --type anthropic \
  --credential ANTHROPIC_AUTH_TOKEN --config ANTHROPIC_BASE_URL="$LLM_URL"
openshell inference set --provider claude --model claude-sonnet-4-6 --no-verify
openshell sandbox create --name "$SANDBOX" --provider claude -- sleep infinity
./03-inject-authbridge.sh "$SANDBOX" "$LLM_URL"

# Verify end-to-end.
./04-verify.sh "$SANDBOX"
```

> If the kagenti repo isn't beside this checkout, set `KAGENTI_DIR`; if it can't be found,
> `01-build-images.sh` prints the gateway `deploy-tenant.sh` command to run yourself.

**If `openshell gateway login` fails** with *"does not use edge authentication"*, your CLI predates
OIDC `gateway login`. Re-register instead — this re-runs the OIDC login your CLI *does* support (run it
interactively so the browser opens, and finish within ~120s):

```bash
openshell gateway remove openshell-team1
scripts/openshell/configure-cli.sh team1     # from your kagenti checkout
```

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
