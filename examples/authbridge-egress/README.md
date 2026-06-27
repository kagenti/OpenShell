<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->
# AuthBridge Egress Integration (example)

Route an OpenShell sandbox's egress through an [AuthBridge](https://github.com/kagenti/kagenti-extensions/tree/main/authbridge)
sidecar using `NetworkMode::External`. AuthBridge performs TLS interception,
credential injection (the sandbox holds only an `openshell:resolve:env:<KEY>`
placeholder; AuthBridge fetches the real token from the OpenShell gateway and swaps
it in), and per-session traffic observability, while OpenShell keeps kernel-level
isolation and hard egress containment.

This README is the runnable walkthrough. For the concepts — how the integration works, the
trust model, and the architecture diagram — see the
**[guide](../../docs/sandboxes/authbridge-egress.mdx)**.

> Experimental PoC — hand-wires one sandbox pod via a `Sandbox` CR patch (no
> operator/webhook). Requires the `feat/authbridge-egress` OpenShell branch and the
> `feat/placeholder-resolve-plugin` kagenti-extensions branch.

## Scripts

| Script | What it does |
|--------|--------------|
| `01-build-images.sh` | Build the External-capable supervisor image + the AuthBridge proxy image; load both into kind |
| `02-setup-authbridge.sh` | Generate the TLS-bridge CA and create the `authbridge-ca` Secret (the sidecar config ConfigMap is rendered per-sandbox by `03`) |
| `03-inject-authbridge.sh` | Render the sidecar config (gateway endpoint + sandbox id from the pod), patch the `podTemplate` (External mode + AuthBridge sidecar mounting the sandbox's gateway SA token / mTLS certs), and recreate the pod |
| `04-verify.sh` | End-to-end checks: External mode, AuthBridge up, `claude` → LLM, placeholder-only env, egress containment, session API |
| `config.yaml` | The AuthBridge sidecar config **template** (forward proxy + tls_bridge + parsers + placeholder-resolve `gateway` source); `03` renders the per-sandbox values |

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

### What gets built (unmerged branches)

The integration depends on code on feature branches not yet merged to mainline, so the
images are built from those checkouts; `01-build-images.sh` fails fast if a checkout is
missing its feature.

| Image | Source | Must contain |
|-------|--------|--------------|
| supervisor (built) | OpenShell `feat/authbridge-egress` | `NetworkMode::External` |
| authbridge-proxy (built) | kagenti-extensions `feat/placeholder-resolve-plugin` | `placeholder-resolve` (incl. the `gateway`-source revision-strip fix) + `inference-parser` + the session API |
| gateway (pulled) | image tag `mvp-v2-7784be8` | the `inference-scoped-provider-lookup` fix — **not** in the chart default `v0.0.56-rc.3`, so `01` pins this tag when it redeploys the gateway |

## Quick start

**1. Set your values** — edit these for your environment:

```bash
cd examples/authbridge-egress

export LLM_URL=https://your-litellm.example.com    # your upstream LLM endpoint (Bearer-auth)
export ANTHROPIC_AUTH_TOKEN='sk-...'                # your real LLM token (stored in the gateway; the sandbox never sees it)
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

# TLS-bridge CA (the gateway holds the credential — no mounted secret).
./02-setup-authbridge.sh

# Provider-bound sandbox, then inject the AuthBridge sidecar. --credential stores
# $ANTHROPIC_AUTH_TOKEN (the real token) in the gateway; AuthBridge fetches it as the sandbox
# and swaps it in. The sandbox itself only ever holds the openshell:resolve:env:<KEY> placeholder.
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

> **Security note:** the AuthBridge session API (`:9094`, used by `abctl`) is unauthenticated
> and captures raw request/response bodies. It's force-bound to localhost and only reachable
> via `kubectl port-forward` — never expose it via ingress.

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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `openshell gateway login` → *"does not use edge authentication"* | Your CLI predates OIDC `gateway login` (it only re-auths edge/Cloudflare gateways); the redeployed gateway *is* OIDC — `deploy-tenant.sh` sets `oidc.issuer`/`oidc.audience` on every run | Re-register — re-runs the OIDC login your CLI *does* support (interactive, finish within ~120s): `openshell gateway remove openshell-team1` then `scripts/openshell/configure-cli.sh team1` from your kagenti checkout. Or update the CLI to a current build |
| `provider create`: `--credential ANTHROPIC_AUTH_TOKEN requires local env var … non-empty` | `--credential KEY` reads the value from your local env var `KEY`, which isn't set | `export ANTHROPIC_AUTH_TOKEN='<your real LLM token>'` before `provider create` — it's stored in the gateway and fetched by AuthBridge |
| `401 unresolvable credential placeholder`; sidecar logs `provider-environment fetch failed` or the resolver never readies | The `gateway` resolver can't fetch the credential: the SA-token volume isn't mounted into the sidecar, the rendered `endpoint`/scheme is wrong, `sandbox_id` doesn't match the sandbox's gateway JWT, or a plaintext endpoint was refused | `kubectl logs <sandbox> -c authbridge-proxy`. Confirm `openshell-sa-token` is mounted; the `endpoint` matches the supervisor's `OPENSHELL_ENDPOINT` (https→mTLS needs the client-tls mount; plaintext needs `insecure: true`); and `sandbox_id` is the UUID (`OPENSHELL_SANDBOX_ID`) |
| Interactive `claude` hangs / "queries not going through", `response body too large` in the sidecar log | claude-code's auto-update/telemetry downloads (`downloads.claude.ai`, `github.com`) exceed AuthBridge's 1 MB MITM body cap and 502 | `export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` in the connect shell before running `claude` |
| `claude` via `exec` says no credentials, but the env is set on the container | `openshell sandbox exec`/`connect` rebuilds the child env from an allowlist (`provider_env` + proxy/TLS + `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL`/`CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS`). Arbitrary container env is dropped | Attach the provider (placeholder rides in `provider_env`), or set vars inline: `VAR=val claude …` |
| Sandbox stuck `ErrImageNeverPull` | The agent base image isn't loaded and `sandboxImagePullPolicy` forbids pulling | Newer `01` sets `IfNotPresent`; otherwise `podman pull <base> && kind load …`, or redeploy with `--set sandboxImagePullPolicy=IfNotPresent` |
| Pod stuck `Terminating`, blocking recreate | The supervisor's SIGTERM teardown is slow | `kubectl delete pod <name> -n team1 --grace-period=0 --force` (the script does this) |
| `abctl` doesn't list the pod | Sidecar container isn't named `authbridge-proxy` | Name it `authbridge-proxy` (or `-envoy`/`-lite`) |
| `abctl`: `connect: connection refused` on `/v1/sessions` | Session API not started | Ensure `session.enabled: true` **and** `listener.session_api_addr: ":9094"` in `config.yaml`, then recreate the pod |
| Egress "bypass" appears to work in tests | You didn't clear `ALL_PROXY`/`grpc_proxy`, so curl used the proxy; or AuthBridge skip-listed the host and blind-tunneled it | Clear *all* proxy vars and test with a raw IP (no DNS) — egress is in fact rejected |
| TLS errors from the agent | Agent doesn't trust the forge CA | Confirm `OPENSHELL_EXTERNAL_CA` points to the mounted `tls.crt`; the supervisor installs it into `NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE` |

See the [guide](../../docs/sandboxes/authbridge-egress.mdx) for the concepts, the trust
model, and the architecture diagram.
