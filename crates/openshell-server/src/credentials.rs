// SPDX-FileCopyrightText: Copyright (c) 2026 Kagenti Authors
// SPDX-License-Identifier: Apache-2.0

//! Client for the out-of-process credentials driver sidecar.

use openshell_core::proto::credentials::v1::{
    ListCredentialsRequest, ListCredentialsResponse, ResolveCredentialRequest,
    ResolveCredentialResponse, credentials_driver_client::CredentialsDriverClient,
};
use openshell_core::{Error, Result};
use std::sync::Arc;
use tonic::transport::Channel;
use tracing::debug;

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tonic::transport::Endpoint;
#[cfg(unix)]
use tower::service_fn;

pub type SharedCredentialsDriver = Option<Arc<CredentialsDriverHandle>>;

pub struct CredentialsDriverHandle {
    client: tokio::sync::Mutex<CredentialsDriverClient<Channel>>,
}

impl CredentialsDriverHandle {
    /// Connect to the credentials driver over a Unix domain socket.
    ///
    /// Retries up to 100 times with 100ms intervals (~10s total).
    #[cfg(unix)]
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let socket_path_buf = socket_path.to_path_buf();
        let mut last_err = None;

        for attempt in 0..100 {
            let path = socket_path_buf.clone();
            let result = Endpoint::from_static("http://[::]:50051")
                .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
                    let path = path.clone();
                    async move { UnixStream::connect(path).await.map(TokioIo::new) }
                }))
                .await;

            match result {
                Ok(channel) => {
                    debug!(
                        path = %socket_path_buf.display(),
                        attempts = attempt + 1,
                        "Connected to credentials driver"
                    );
                    let client = CredentialsDriverClient::new(channel);
                    return Ok(Self {
                        client: tokio::sync::Mutex::new(client),
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }

        Err(Error::execution(format!(
            "failed to connect to credentials driver socket '{}' after 10s: {}",
            socket_path_buf.display(),
            last_err.unwrap()
        )))
    }

    #[cfg(not(unix))]
    pub async fn connect(_socket_path: &std::path::Path) -> Result<Self> {
        Err(Error::config(
            "credentials driver is only supported on Unix",
        ))
    }

    pub async fn resolve_credential(&self, name: &str) -> Result<ResolveCredentialResponse> {
        let request = ResolveCredentialRequest {
            name: name.to_string(),
        };
        let mut client = self.client.lock().await;
        let response = client
            .resolve_credential(request)
            .await
            .map_err(|e| Error::execution(format!("credentials driver RPC failed: {e}")))?;
        Ok(response.into_inner())
    }

    pub async fn list_credentials(&self) -> Result<ListCredentialsResponse> {
        let mut client = self.client.lock().await;
        let response = client
            .list_credentials(ListCredentialsRequest {})
            .await
            .map_err(|e| Error::execution(format!("credentials driver RPC failed: {e}")))?;
        Ok(response.into_inner())
    }
}
