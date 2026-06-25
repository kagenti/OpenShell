// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox policy configuration.

use openshell_core::proto::{
    FilesystemPolicy as ProtoFilesystemPolicy, LandlockPolicy as ProtoLandlockPolicy,
    ProcessPolicy as ProtoProcessPolicy, SandboxPolicy as ProtoSandboxPolicy,
};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub version: u32,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub landlock: LandlockPolicy,
    pub process: ProcessPolicy,
}

#[derive(Debug, Clone)]
pub struct FilesystemPolicy {
    /// Read-only directory allow list.
    pub read_only: Vec<PathBuf>,

    /// Read-write directory allow list.
    pub read_write: Vec<PathBuf>,

    /// Automatically include the workdir as read-write.
    pub include_workdir: bool,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            include_workdir: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub proxy: Option<ProxyPolicy>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Block,
            proxy: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum NetworkMode {
    #[default]
    Block,
    Proxy,
    Allow,
    /// Like `Proxy` (netns containment + workload CA trust + `HTTP_PROXY`
    /// env) but the supervisor does NOT start its internal proxy. Egress is
    /// routed to an external proxy (an `AuthBridge` sidecar) and the workload
    /// trusts an externally-supplied CA. See [`ProxyPolicy::external_ca`].
    External,
}

#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    /// TCP address for a local HTTP proxy (loopback-only). In `External` mode
    /// this carries the external proxy (`AuthBridge` sidecar) address; only the
    /// port is used in netns mode (the veth host IP is fixed at 10.200.0.1).
    pub http_addr: Option<SocketAddr>,

    /// Path to an externally-supplied CA certificate (PEM) to write into the
    /// workload trust store. Set only in `External` mode; the supervisor reads
    /// this instead of generating an ephemeral CA.
    pub external_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct LandlockPolicy {
    pub compatibility: LandlockCompatibility,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessPolicy {
    /// User name to run the sandboxed process as.
    pub run_as_user: Option<String>,

    /// Group name to run the sandboxed process as.
    pub run_as_group: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub enum LandlockCompatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

// ============================================================================
// Proto to Rust type conversions
// ============================================================================

impl TryFrom<ProtoSandboxPolicy> for SandboxPolicy {
    type Error = miette::Report;

    fn try_from(proto: ProtoSandboxPolicy) -> Result<Self, Self::Error> {
        // In cluster mode we always run with proxy networking so all egress
        // can be evaluated by OPA and `inference.local` is always addressable.
        let network = NetworkPolicy {
            mode: NetworkMode::Proxy,
            proxy: Some(ProxyPolicy {
                http_addr: None,
                external_ca: None,
            }),
        };

        Ok(Self {
            version: proto.version,
            filesystem: proto
                .filesystem
                .map(FilesystemPolicy::from)
                .unwrap_or_default(),
            network,
            landlock: proto.landlock.map(LandlockPolicy::from).unwrap_or_default(),
            process: proto.process.map(ProcessPolicy::from).unwrap_or_default(),
        })
    }
}

impl From<ProtoFilesystemPolicy> for FilesystemPolicy {
    fn from(proto: ProtoFilesystemPolicy) -> Self {
        Self {
            read_only: proto
                .read_only
                .into_iter()
                .map(|p| PathBuf::from(openshell_policy::normalize_path(&p)))
                .collect(),
            read_write: proto
                .read_write
                .into_iter()
                .map(|p| PathBuf::from(openshell_policy::normalize_path(&p)))
                .collect(),
            include_workdir: proto.include_workdir,
        }
    }
}

impl From<ProtoLandlockPolicy> for LandlockPolicy {
    fn from(proto: ProtoLandlockPolicy) -> Self {
        let compatibility = if proto.compatibility == "hard_requirement" {
            LandlockCompatibility::HardRequirement
        } else {
            LandlockCompatibility::BestEffort
        };
        Self { compatibility }
    }
}

impl From<ProtoProcessPolicy> for ProcessPolicy {
    fn from(proto: ProtoProcessPolicy) -> Self {
        Self {
            run_as_user: if proto.run_as_user.is_empty() {
                None
            } else {
                Some(proto.run_as_user)
            },
            run_as_group: if proto.run_as_group.is_empty() {
                None
            } else {
                Some(proto.run_as_group)
            },
        }
    }
}
