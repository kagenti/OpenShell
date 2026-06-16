// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-user sandbox ownership enforcement.
//!
//! Stamps an `openshell.ai/owner` label on sandboxes at creation time (from the
//! verified caller identity) and gates access on subsequent operations. Admin
//! callers bypass the ownership check.

use std::collections::HashMap;

use tonic::Status;

use super::identity::Identity;
use super::principal::Principal;

/// Reserved label key for sandbox ownership. Server-set, never client-controlled.
pub const OWNER_LABEL: &str = "openshell.ai/owner";

/// Reserved label key prefix. All keys starting with this are stripped from
/// client-supplied labels on create.
const RESERVED_PREFIX: &str = "openshell.ai/";

/// Sanitize an identity subject into a valid Kubernetes label value.
///
/// K8s label values: alphanumeric, `-`, `_`, `.`, max 63 chars, must start and
/// end with alphanumeric. Keycloak UUID subjects (`sub`) satisfy this directly.
/// For non-conforming subjects, we produce a hex-encoded SHA-256 truncated to 63
/// chars (always alphanumeric).
pub fn sanitize_subject(subject: &str) -> Result<String, Status> {
    if subject.is_empty() {
        return Err(Status::unauthenticated(
            "identity subject is empty; cannot determine sandbox owner",
        ));
    }

    if is_valid_label_value(subject) {
        return Ok(subject.to_string());
    }

    // Fallback: hex SHA-256 truncated to 63 chars (always valid).
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let hash = Sha256::digest(subject.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in &hash {
        let _ = write!(hex, "{byte:02x}");
    }
    hex.truncate(63);
    Ok(hex)
}

/// Strip all reserved `openshell.ai/` keys from client-supplied labels and stamp
/// the owner label from the caller's identity.
///
/// Returns `UNAUTHENTICATED` if the principal is `Anonymous` (ownership requires
/// a verified identity).
pub fn stamp_owner(
    labels: &mut HashMap<String, String>,
    principal: Option<&Principal>,
) -> Result<(), Status> {
    let identity = require_identity(principal)?;
    labels.retain(|key, _| !key.starts_with(RESERVED_PREFIX));
    let owner_value = sanitize_subject(&identity.subject)?;
    labels.insert(OWNER_LABEL.to_string(), owner_value);
    Ok(())
}

/// Check that the caller owns the sandbox (or is an admin).
///
/// Returns `PERMISSION_DENIED` if the sandbox has an owner label that doesn't
/// match the caller's identity subject.
///
/// When `admin_role` is non-empty and the caller has that role, the check is
/// bypassed (admins operate across all users' sandboxes).
///
/// When the sandbox has no owner label (pre-existing sandboxes created before
/// this feature), access is allowed to maintain backward compatibility.
pub fn check_owner(
    sandbox_labels: &HashMap<String, String>,
    principal: Option<&Principal>,
    admin_role: &str,
) -> Result<(), Status> {
    let Some(owner_value) = sandbox_labels.get(OWNER_LABEL) else {
        // No owner label → legacy sandbox, allow access.
        return Ok(());
    };

    let identity = match principal_identity(principal) {
        Some(id) => id,
        None => {
            // Anonymous caller on an owned sandbox → deny.
            return Err(Status::permission_denied(
                "sandbox is owned; authenticated identity required",
            ));
        }
    };

    // Admin bypass.
    if !admin_role.is_empty() && identity.roles.iter().any(|r| r == admin_role) {
        return Ok(());
    }

    let caller_value = sanitize_subject(&identity.subject)?;
    if caller_value != *owner_value {
        return Err(Status::permission_denied(
            "you do not own this sandbox",
        ));
    }

    Ok(())
}

/// AND the caller's owner selector into an existing label selector string.
///
/// Returns the augmented selector. When the principal is `Anonymous` and no OIDC
/// is configured, returns the selector unchanged (backward compat).
pub fn owner_selector(
    principal: Option<&Principal>,
    existing_selector: &str,
    admin_role: &str,
) -> Result<String, Status> {
    let identity = match principal_identity(principal) {
        Some(id) => id,
        None => {
            // Anonymous → no owner filtering (backward compat).
            return Ok(existing_selector.to_string());
        }
    };

    // Admin bypass — see all sandboxes.
    if !admin_role.is_empty() && identity.roles.iter().any(|r| r == admin_role) {
        return Ok(existing_selector.to_string());
    }

    let owner_value = sanitize_subject(&identity.subject)?;
    let owner_filter = format!("{OWNER_LABEL}={owner_value}");

    if existing_selector.is_empty() {
        Ok(owner_filter)
    } else {
        Ok(format!("{existing_selector},{owner_filter}"))
    }
}

/// Extract identity from principal, returning `UNAUTHENTICATED` if anonymous.
fn require_identity(principal: Option<&Principal>) -> Result<&Identity, Status> {
    match principal {
        Some(Principal::User(user)) => Ok(&user.identity),
        Some(Principal::Sandbox(_)) | Some(Principal::Anonymous) | None => Err(
            Status::unauthenticated("authenticated user identity required for sandbox operations"),
        ),
    }
}

/// Extract identity without failing — returns `None` for anonymous/sandbox/missing.
fn principal_identity(principal: Option<&Principal>) -> Option<&Identity> {
    match principal {
        Some(Principal::User(user)) => Some(&user.identity),
        _ => None,
    }
}

fn is_valid_label_value(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::IdentityProvider;
    use crate::auth::principal::UserPrincipal;

    fn user_principal(subject: &str, roles: &[&str]) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: roles.iter().map(|r| (*r).to_string()).collect(),
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    fn admin_principal() -> Principal {
        user_principal("admin-uuid", &["openshell-admin", "openshell-user"])
    }

    fn alice() -> Principal {
        user_principal("alice-uuid-1234", &["openshell-user"])
    }

    fn bob() -> Principal {
        user_principal("bob-uuid-5678", &["openshell-user"])
    }

    // ---- sanitize_subject ----

    #[test]
    fn sanitize_uuid_passthrough() {
        let result = sanitize_subject("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(result, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn sanitize_simple_alphanumeric() {
        assert_eq!(sanitize_subject("user123").unwrap(), "user123");
    }

    #[test]
    fn sanitize_email_hashes() {
        // Email contains '@' which is invalid for labels → hashed
        let result = sanitize_subject("alice@corp.com").unwrap();
        assert_ne!(result, "alice@corp.com");
        assert!(result.len() <= 63);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sanitize_empty_subject_fails() {
        assert!(sanitize_subject("").is_err());
    }

    #[test]
    fn sanitize_long_subject_hashes() {
        let long = "a".repeat(100);
        let result = sanitize_subject(&long).unwrap();
        assert!(result.len() <= 63);
    }

    // ---- stamp_owner ----

    #[test]
    fn stamp_owner_sets_label() {
        let principal = alice();
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "dev".to_string());

        stamp_owner(&mut labels, Some(&principal)).unwrap();

        assert_eq!(labels.get(OWNER_LABEL).unwrap(), "alice-uuid-1234");
        assert_eq!(labels.get("env").unwrap(), "dev");
    }

    #[test]
    fn stamp_owner_strips_reserved_keys() {
        let principal = alice();
        let mut labels = HashMap::new();
        labels.insert("openshell.ai/owner".to_string(), "spoofed".to_string());
        labels.insert("openshell.ai/custom".to_string(), "sneaky".to_string());
        labels.insert("safe-key".to_string(), "kept".to_string());

        stamp_owner(&mut labels, Some(&principal)).unwrap();

        assert_eq!(labels.get(OWNER_LABEL).unwrap(), "alice-uuid-1234");
        assert!(!labels.contains_key("openshell.ai/custom"));
        assert_eq!(labels.get("safe-key").unwrap(), "kept");
    }

    #[test]
    fn stamp_owner_rejects_anonymous() {
        let mut labels = HashMap::new();
        let result = stamp_owner(&mut labels, Some(&Principal::Anonymous));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn stamp_owner_rejects_none() {
        let mut labels = HashMap::new();
        let result = stamp_owner(&mut labels, None);
        assert!(result.is_err());
    }

    // ---- check_owner ----

    #[test]
    fn check_owner_allows_owner() {
        let mut labels = HashMap::new();
        labels.insert(OWNER_LABEL.to_string(), "alice-uuid-1234".to_string());

        let principal = alice();
        assert!(check_owner(&labels, Some(&principal), "openshell-admin").is_ok());
    }

    #[test]
    fn check_owner_denies_non_owner() {
        let mut labels = HashMap::new();
        labels.insert(OWNER_LABEL.to_string(), "alice-uuid-1234".to_string());

        let principal = bob();
        let result = check_owner(&labels, Some(&principal), "openshell-admin");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn check_owner_admin_bypass() {
        let mut labels = HashMap::new();
        labels.insert(OWNER_LABEL.to_string(), "alice-uuid-1234".to_string());

        let principal = admin_principal();
        assert!(check_owner(&labels, Some(&principal), "openshell-admin").is_ok());
    }

    #[test]
    fn check_owner_no_label_allows_access() {
        let labels = HashMap::new();
        let principal = bob();
        assert!(check_owner(&labels, Some(&principal), "openshell-admin").is_ok());
    }

    #[test]
    fn check_owner_anonymous_on_owned_sandbox_denied() {
        let mut labels = HashMap::new();
        labels.insert(OWNER_LABEL.to_string(), "alice-uuid-1234".to_string());

        let result = check_owner(&labels, Some(&Principal::Anonymous), "openshell-admin");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn check_owner_none_principal_on_owned_sandbox_denied() {
        let mut labels = HashMap::new();
        labels.insert(OWNER_LABEL.to_string(), "alice-uuid-1234".to_string());

        let result = check_owner(&labels, None, "openshell-admin");
        assert!(result.is_err());
    }

    // ---- owner_selector ----

    #[test]
    fn owner_selector_empty_base() {
        let principal = alice();
        let result = owner_selector(Some(&principal), "", "openshell-admin").unwrap();
        assert_eq!(result, "openshell.ai/owner=alice-uuid-1234");
    }

    #[test]
    fn owner_selector_appends_to_existing() {
        let principal = alice();
        let result = owner_selector(Some(&principal), "env=dev", "openshell-admin").unwrap();
        assert_eq!(result, "env=dev,openshell.ai/owner=alice-uuid-1234");
    }

    #[test]
    fn owner_selector_admin_sees_all() {
        let principal = admin_principal();
        let result = owner_selector(Some(&principal), "env=dev", "openshell-admin").unwrap();
        assert_eq!(result, "env=dev");
    }

    #[test]
    fn owner_selector_anonymous_no_filter() {
        let result = owner_selector(Some(&Principal::Anonymous), "env=dev", "openshell-admin").unwrap();
        assert_eq!(result, "env=dev");
    }

    #[test]
    fn owner_selector_none_no_filter() {
        let result = owner_selector(None, "", "openshell-admin").unwrap();
        assert_eq!(result, "");
    }
}
