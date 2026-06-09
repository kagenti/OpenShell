// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for NetworkMode::Platform (Issue #899).

use openshell_sandbox::policy::{NetworkMode, SandboxPolicy};

#[test]
fn platform_mode_from_proto() {
    use openshell_core::proto::{NetworkEnforcementMode, SandboxPolicy as ProtoSandboxPolicy};

    let mut proto = ProtoSandboxPolicy::default();
    proto.network_enforcement = NetworkEnforcementMode::Platform as i32;

    let policy: SandboxPolicy = proto.try_into().expect("conversion should succeed");
    assert!(
        matches!(policy.network.mode, NetworkMode::Platform),
        "expected Platform, got {:?}",
        policy.network.mode
    );
}

#[test]
fn namespace_mode_from_proto_default() {
    use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;

    let proto = ProtoSandboxPolicy::default();
    let policy: SandboxPolicy = proto.try_into().expect("conversion should succeed");
    assert!(
        matches!(policy.network.mode, NetworkMode::Proxy),
        "default (zero) should map to Proxy, got {:?}",
        policy.network.mode
    );
}

#[test]
fn platform_mode_allows_proxy_config() {
    use openshell_core::proto::{NetworkEnforcementMode, SandboxPolicy as ProtoSandboxPolicy};

    let mut proto = ProtoSandboxPolicy::default();
    proto.network_enforcement = NetworkEnforcementMode::Platform as i32;

    let policy: SandboxPolicy = proto.try_into().expect("conversion should succeed");
    assert!(
        policy.network.proxy.is_some(),
        "Platform mode should still have proxy config for loopback CONNECT proxy"
    );
}
