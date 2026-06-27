<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->
# Design: `EgressProvider` — a pluggable sandbox egress strategy

## Status

Proposal. Supersedes the inline `NetworkMode::External` enum approach (commit
`d506f5d`) as the intended upstream shape. The enum is a valid first increment;
this doc describes the refactor that turns "which proxy handles egress" into a
fixed-interface pluggable component.

## Problem

The supervisor's egress handling is selected by the `NetworkMode` enum
(`policy.rs`: `Block | Proxy | Allow | External`) and wired inline in the main
startup path in `crates/openshell-sandbox/src/lib.rs`. `External` was added to
route egress to an out-of-pod proxy (an AuthBridge sidecar) instead of starting
the supervisor's internal L7 proxy. Because `External` reuses *almost all* of
`Proxy`'s behavior and differs in only two places, the startup path is now
littered with `matches!(policy.network.mode, NetworkMode::Proxy | NetworkMode::External)`
checks, plus a post-`load_policy` override (`apply_external_network_mode`) that
forces the mode from a CLI flag.

Concretely, the `NetworkMode` decision touches these sites in `lib.rs`:

| Site (lib.rs) | What it does | Differs Internal vs External? |
|---|---|---|
| 507 `matches!(… Proxy)` | generate ephemeral CA → `ProxyTlsState` (`SandboxCa::generate` → `write_ca_files`) | **yes** — External reads an external CA instead |
| 560 `matches!(… External)` | read external CA PEM → trust (`write_external_ca_files`), no TLS state | **yes** |
| 623-626 `Proxy \| External` | create `NetworkNamespace` + `install_bypass_rules(port)` | no — shared |
| 679-680 `matches!(… Proxy)` | start the internal proxy (`ProxyHandle::start_with_bind_addr`) | **yes** — External starts nothing |
| 784-786 `Proxy \| External` | compute `ssh_proxy_url` = `http://<host_ip>:<port>` | no — shared |
| 1810-1813 `Proxy \| External` | `enrich_sandbox_baseline_paths` include proxy paths | no — shared |
| 2150 `apply_external_network_mode` | CLI override: force mode = External + set `ProxyPolicy` | selection |

The shared rows (netns, ssh proxy url, baseline paths) are exactly the behavior
that should live behind one capability query; the differing rows (CA source,
start-a-proxy-or-not) are exactly the behavior that should live behind the
provider implementations.

## Goals

- Make the egress strategy a **fixed interface** with multiple implementations,
  consistent with OpenShell's existing extension seams (`L7Provider` for
  protocol handlers, `ProviderPlugin`, `K8sIdentityResolver`, the compute-driver
  crates).
- Collapse the scattered `matches!(NetworkMode::…)` sites into trait calls.
- Keep `External` generic (an "external egress proxy"), not AuthBridge-specific.
- **No behavior change** for existing modes; default stays `Proxy`.

## Non-goals

- Rewriting the L7 proxy itself. The ~14k lines in `l7/` (relay, parse, TLS,
  inference/MCP routing, the `L7Provider` protocol handlers) are **wrapped, not
  touched**. `InternalL7Proxy::start` calls the existing `ProxyHandle::start_with_bind_addr`.
- Changing the netns / nftables egress-lockdown mechanism. The supervisor keeps
  owning it; the provider only declares whether it applies.
- Third-party out-of-tree providers (the trait makes it *possible*; we ship the
  in-tree set).

## The interface

New module `crates/openshell-sandbox/src/egress/mod.rs` (+ `internal.rs`,
`external.rs`). The trait is a closed in-tree set, so prefer **enum dispatch**
(`enum Egress`) over `Box<dyn>` — it sidesteps the async-in-dyn-trait friction
(the codebase uses RPITIT, e.g. `L7Provider`, not `#[async_trait]`), keeps static
dispatch, and is still a single fixed interface. (If true out-of-tree
pluggability is wanted later, swap the enum for `#[async_trait] + Box<dyn>`; the
method set below is unchanged.)

```rust
/// A sandbox egress strategy: it decides the CA trust to install, whether an
/// internal proxy runs, and (implicitly) the endpoint the workload uses. The
/// supervisor owns the common wiring (netns, nftables egress lockdown,
/// HTTP_PROXY env, baseline paths) and consults the provider for the parts that
/// differ between strategies.
pub enum Egress {
    /// Built-in L7 proxy: supervisor terminates TLS with an ephemeral CA and
    /// runs the proxy in the netns. (Today's `NetworkMode::Proxy`.)
    Internal(InternalL7Proxy),
    /// Egress routed to an out-of-pod proxy at the veth host IP; supervisor
    /// installs an externally-supplied CA and starts no proxy. (`External`.)
    External(ExternalProxy),
    /// No netns proxy egress (Block / Allow). CA: none; proxy: none.
    None,
}

impl Egress {
    /// Stable label for logs/telemetry.
    pub fn name(&self) -> &'static str;

    /// Whether this strategy uses the network namespace + nftables egress
    /// lockdown + the workload HTTP_PROXY env + proxy baseline paths.
    /// True for Internal and External; false for None.
    pub fn uses_netns_egress(&self) -> bool;

    /// Phase 1 (before netns + workload start): install CA trust into the
    /// workload trust store and prepare any data-plane state. Internal generates
    /// an ephemeral CA and stashes the resulting `ProxyTlsState` for `start`;
    /// External writes the configured external CA PEM; None does nothing.
    /// Returns the written CA file paths (for Landlock/baseline enrichment).
    pub fn prepare(&mut self, ctx: &EgressCaCtx<'_>) -> Result<Option<CaFilePaths>>;

    /// The proxy endpoint the workload points HTTP_PROXY / ssh proxy url at,
    /// given the created netns. For Internal/External this is the veth host IP +
    /// configured port; None otherwise. (Internal binds it; External expects the
    /// out-of-pod proxy to bind it.)
    pub fn proxy_endpoint(&self, netns: Option<&NetworkNamespace>) -> Option<SocketAddr>;

    /// Phase 2 (after netns + supervisor hardening): start the data plane if this
    /// strategy runs one in-supervisor. Internal starts the L7 proxy and returns
    /// its handle + denial/activity receivers; External and None return Ok(None).
    pub async fn start(&mut self, ctx: EgressStartCtx<'_>) -> Result<Option<RunningProxy>>;
}
```

### Context + return types

```rust
/// Inputs to `prepare`. tls_dir is `/etc/openshell-tls` today.
pub struct EgressCaCtx<'a> {
    pub tls_dir: &'a Path,
    pub system_ca_bundle: &'a str, // from read_system_ca_bundle()
}

/// Paths written into the trust store (whatever write_ca_files /
/// write_external_ca_files return today — keep that type, just name it).
pub type CaFilePaths = /* the existing return type of write_ca_files */;

/// Inputs to `start`. Mirrors the current ProxyHandle::start_with_bind_addr
/// argument list so InternalL7Proxy::start is a thin delegation.
pub struct EgressStartCtx<'a> {
    pub proxy_policy: &'a ProxyPolicy,
    pub netns: Option<&'a NetworkNamespace>,   // start computes bind_addr from this
    pub opa_engine: Arc<OpaEngine>,            // required by Internal
    pub identity_cache: Arc<IdentityCache>,    // required by Internal
    pub entrypoint_pid: Arc<AtomicU32>,
    pub inference_ctx: InferenceContext,
    pub provider_credentials: ProviderCredentials,
    pub policy_local_ctx: PolicyLocalCtx,
    pub sandbox_id: Option<&'a str>,           // gates denial/activity channels
}

/// What a running internal proxy hands back to the supervisor.
pub struct RunningProxy {
    pub handle: ProxyHandle,
    pub denial_rx: Option<UnboundedReceiver<…>>,
    pub bypass_denial_tx: Option<UnboundedSender<…>>,
    pub activity_rx: Option<…>,
    pub bypass_activity_tx: Option<…>,
}
```

> `prepare`/`start` are split because the CA must be installed **before** the
> netns + workload (current `lib.rs:507`), while the proxy starts **after** the
> netns + `apply_supervisor_startup_hardening` + `entrypoint_pid` setup
> (`lib.rs:673-679`). `InternalL7Proxy` stores the `Arc<ProxyTlsState>` produced
> in `prepare` as a field and consumes it in `start` — hence `&mut self`.

### Implementations

**`InternalL7Proxy`** (struct holds `tls_state: Option<Arc<ProxyTlsState>>`):
- `name()` → `"internal-l7"`; `uses_netns_egress()` → `true`.
- `prepare(ctx)`: the current `lib.rs:508-558` body — `SandboxCa::generate()` →
  `write_ca_files(&ca, ctx.tls_dir, ctx.system_ca_bundle)` →
  `ProxyTlsState::new(CertCache::new(ca), build_upstream_client_config(bundle))`.
  Store the state in `self.tls_state`; return `Some(paths)`. (Keep the existing
  `ocsf_emit!` calls.)
- `proxy_endpoint(netns)`: `netns.map(|ns| SocketAddr::new(ns.host_ip(), port))`
  where `port` = `proxy_policy.http_addr.port()` or 3128.
- `start(ctx)`: the current `lib.rs:681-748` body — build `bind_addr` from
  `ctx.netns`, create the denial/activity channels (gated on `ctx.sandbox_id`),
  `build_inference_context(...)`, call `ProxyHandle::start_with_bind_addr(...,
  self.tls_state.take(), ...)`, return `Ok(Some(RunningProxy{…}))`.

**`ExternalProxy`** (struct holds `external_ca: PathBuf`, `proxy_addr: SocketAddr`):
- `name()` → `"external"`; `uses_netns_egress()` → `true`.
- `prepare(ctx)`: the current `lib.rs:564-615` body — read `self.external_ca` PEM,
  `write_external_ca_files(&pem, ctx.tls_dir, ctx.system_ca_bundle)`, return
  `Some(paths)`; no TLS state.
- `proxy_endpoint(netns)`: same as Internal (veth host IP + port). The supervisor
  does not bind it; the out-of-pod proxy does.
- `start(_)`: `Ok(None)` — no in-supervisor proxy.

**`Egress::None`** (Block / Allow):
- `uses_netns_egress()` → `false`; `prepare` → `Ok(None)`; `proxy_endpoint` →
  `None`; `start` → `Ok(None)`.

### Selection (replaces `apply_external_network_mode`)

Build the provider once, right after `load_policy`, from the policy mode + the
CLI flags. This replaces the post-load mode override:

```rust
fn select_egress(policy: &SandboxPolicy,
                 external_proxy: Option<&str>,
                 external_ca: Option<&str>) -> Result<Egress> {
    // CLI external-ca opt-in wins (operator wiring an out-of-pod proxy).
    if let Some(ca) = external_ca {
        let addr = match external_proxy {
            Some(s) => s.parse().map_err(|e| miette!("invalid --external-proxy {s:?}: {e}"))?,
            None => SocketAddr::from(([10,200,0,1], 3128)),
        };
        return Ok(Egress::External(ExternalProxy { external_ca: ca.into(), proxy_addr: addr }));
    }
    Ok(match policy.network.mode {
        NetworkMode::Proxy => Egress::Internal(InternalL7Proxy::default()),
        _ => Egress::None,            // Block / Allow
    })
}
```

`NetworkMode::External` and `ProxyPolicy.external_ca` can then be **removed** from
`policy.rs` (the strategy is no longer carried in the policy enum — it's selected
operationally). Keep `ProxyPolicy.http_addr` (the port still feeds
`proxy_endpoint` + `install_bypass_rules`). If a policy-expressible external mode
is desired later, re-add a variant and branch in `select_egress`.

## How `lib.rs` changes (site by site)

```rust
let mut egress = select_egress(&policy, args.external_proxy.as_deref(),
                               args.external_ca.as_deref())?;

// 507-618  →
let ca_file_paths = egress.prepare(&EgressCaCtx {
    tls_dir: Path::new("/etc/openshell-tls"),
    system_ca_bundle: &read_system_ca_bundle(),
})?;

// 623-663  →  if egress.uses_netns_egress() { NetworkNamespace::create() + install_bypass_rules(port) }
// 679-751  →  let running = egress.start(EgressStartCtx { … }).await?;
//             let (denial_rx, bypass_denial_tx, activity_rx, bypass_activity_tx) =
//                 running.map(RunningProxy::into_parts).unwrap_or_default();
// 784-808  →  let ssh_proxy_url = egress.proxy_endpoint(netns.as_ref()).map(|a| format!("http://{a}"));
// 1810-1813 → active_baseline_enrichment_paths(egress.uses_netns_egress())
```

The three `Proxy | External` sites all become `egress.uses_netns_egress()`; the
two `matches!(Proxy)` sites move into `Internal::{prepare,start}`; the override
becomes `select_egress`.

## File-by-file change set (≈450-600 line diff)

| File | Change | Est. |
|---|---|---|
| `egress/mod.rs` (new) | `Egress` enum + methods + ctx/return structs | +120 |
| `egress/internal.rs` (new) | `InternalL7Proxy` — move CA-gen (507-558) + proxy-start (681-748) bodies here | +180 (mostly moved) |
| `egress/external.rs` (new) | `ExternalProxy` — move external-CA body (564-615) here | +60 (moved) |
| `lib.rs` | replace the 7 sites with provider calls; delete the moved bodies; add `select_egress` (replaces `apply_external_network_mode`) | net −80 / churn ~150 |
| `policy.rs` | remove `NetworkMode::External` + `ProxyPolicy.external_ca` (kept only if policy-expressible mode wanted) | −20 |
| `main.rs` | unchanged (`--external-proxy`/`--external-ca` flags feed `select_egress`) | 0 |
| `l7/tls.rs` | unchanged (`write_ca_files`/`write_external_ca_files`/`SandboxCa`/`ProxyTlsState` are called by the impls) | 0 |
| tests | per-provider unit tests (see below) | +80 |

Net new logic is small; most of the line count is **moving** the two existing
bodies into `internal.rs`/`external.rs`.

## Testing

- `egress::select_egress`: external-ca opt-in → `External` with parsed/default
  addr; bad `--external-proxy` → error; `Proxy` → `Internal`; `Block`/`Allow` →
  `None`. (Port of the existing `external_mode_*` tests at `lib.rs:3045-3071`.)
- `uses_netns_egress()` truth table (Internal/External true, None false).
- `proxy_endpoint`: Internal and External both yield `host_ip:port`; None → None.
- `ExternalProxy::prepare`: writes the external CA, returns paths; missing/unreadable
  file → error path matches today's `(None, None)` behavior.
- `InternalL7Proxy::prepare`: generates a CA and populates `tls_state`.
- Integration (existing): the live AuthBridge-egress e2e
  (`examples/authbridge-egress`) is unchanged from the workload's perspective —
  same veth endpoint, same external CA — and is the behavioral regression gate.

## Migration / rollout

1. Land `egress/` (trait + impls) with the bodies moved out of `lib.rs`; wire the
   7 sites; keep `NetworkMode` as-is for one step to minimize churn.
2. Replace `apply_external_network_mode` with `select_egress`.
3. Remove `NetworkMode::External` + `ProxyPolicy.external_ca` (optional cleanup;
   the variant is now unreachable through the policy path).
4. `cargo fmt`, `clippy`, `cargo test`; rebuild the arm64 supervisor image and
   re-run the AuthBridge-egress e2e as the regression check.

## Risks

- **netns/spawn context threading** is the main risk: `start` needs the OPA
  engine, identity cache, `entrypoint_pid`, inference ctx, resolver, and channels.
  `EgressStartCtx` bundles them; if borrow/lifetime threading gets awkward the
  `lib.rs` delta can exceed the estimate. Validate by prototyping `start` first.
- **Async dispatch**: `start` is async. The enum keeps static dispatch (no
  `async_trait`); if migrated to `Box<dyn>` later, add `#[async_trait]`.
- **`ProxyTlsState` lifetime across phases**: handled by storing it on
  `InternalL7Proxy` and `take()`-ing it in `start`. Calling `start` without
  `prepare` (or twice) must fail loudly, not silently start without TLS.
