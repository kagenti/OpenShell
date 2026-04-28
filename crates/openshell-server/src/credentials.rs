// SPDX-FileCopyrightText: Copyright (c) 2026 Kagenti Authors
// SPDX-License-Identifier: Apache-2.0

//! Credentials driver client.
//!
//! When `--credentials-driver-socket` is set, the gateway delegates credential
//! resolution to an out-of-process driver over a Unix domain socket. The driver
//! implements the `CredentialsDriver` gRPC contract defined in
//! `proto/credentials_driver.proto`.

use openshell_core::proto::credentials::v1::credentials_driver_client::CredentialsDriverClient;
use openshell_core::proto::credentials::v1::{
    ListCredentialsRequest, ListCredentialsResponse, ResolveCredentialRequest,
    ResolveCredentialResponse,
};
use openshell_core::{Error, Result};
use std::path::Path;
use std::sync::Arc;
use tonic::transport::Channel;
use tracing::info;

#[cfg(unix)]
use {
    hyper_util::rt::TokioIo,
    std::time::Duration,
    tokio::net::UnixStream,
    tonic::transport::Endpoint,
    tower::service_fn,
};

/// Handle to an out-of-process credentials driver connected over UDS.
#[derive(Clone)]
pub struct CredentialsDriverHandle {
    channel: Channel,
}

impl CredentialsDriverHandle {
    /// Connect to a credentials driver at the given Unix domain socket path.
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let channel = connect_uds(socket_path).await?;
        info!(
            socket = %socket_path.display(),
            "Connected to credentials driver"
        );
        Ok(Self { channel })
    }

    /// Resolve a named credential to an access token.
    pub async fn resolve_credential(
        &self,
        name: &str,
    ) -> Result<ResolveCredentialResponse> {
        let mut client = CredentialsDriverClient::new(self.channel.clone());
        let response = client
            .resolve_credential(tonic::Request::new(ResolveCredentialRequest {
                name: name.to_string(),
            }))
            .await
            .map_err(|s| {
                Error::execution(format!(
                    "credentials driver ResolveCredential failed for '{}': {}",
                    name, s
                ))
            })?;
        Ok(response.into_inner())
    }

    /// List all available credential names.
    pub async fn list_credentials(&self) -> Result<ListCredentialsResponse> {
        let mut client = CredentialsDriverClient::new(self.channel.clone());
        let response = client
            .list_credentials(tonic::Request::new(ListCredentialsRequest {}))
            .await
            .map_err(|s| {
                Error::execution(format!(
                    "credentials driver ListCredentials failed: {}",
                    s
                ))
            })?;
        Ok(response.into_inner())
    }
}

impl std::fmt::Debug for CredentialsDriverHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialsDriverHandle")
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
async fn connect_uds(socket_path: &Path) -> Result<Channel> {
    let mut last_error: Option<String> = None;
    for _ in 0..100 {
        match connect_once(socket_path).await {
            Ok(channel) => return Ok(channel),
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(Error::execution(format!(
        "timed out waiting for credentials driver socket '{}': {}",
        socket_path.display(),
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

#[cfg(unix)]
async fn connect_once(socket_path: &Path) -> Result<Channel> {
    let socket_path = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    Endpoint::from_static("http://[::]:50052")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| {
            Error::execution(format!(
                "failed to connect to credentials driver socket '{}': {e}",
                display_path.display()
            ))
        })
}

#[cfg(not(unix))]
async fn connect_uds(_socket_path: &Path) -> Result<Channel> {
    Err(Error::config(
        "the credentials driver requires unix domain socket support",
    ))
}

/// Optional credentials driver, wrapped in Arc for sharing across handlers.
pub type SharedCredentialsDriver = Option<Arc<CredentialsDriverHandle>>;
