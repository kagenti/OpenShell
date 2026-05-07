// SPDX-FileCopyrightText: Copyright (c) 2026 Kagenti Authors
// SPDX-License-Identifier: Apache-2.0

//! External compute driver: connect to a pre-existing Unix domain socket.
//!
//! Unlike the VM driver ([`super::vm`]) which spawns and manages a subprocess,
//! the external driver assumes the socket is already listening (e.g. a sidecar
//! container in the same pod). The gateway just connects to it.

#[cfg(unix)]
use hyper_util::rt::TokioIo;
use openshell_core::{Error, Result};
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tonic::transport::Channel;
#[cfg(unix)]
use tonic::transport::Endpoint;
#[cfg(unix)]
use tower::service_fn;

/// Connect to an external compute driver at the given Unix domain socket path.
///
/// Retries for up to 10 seconds to allow the sidecar time to start.
#[cfg(unix)]
pub async fn connect(socket_path: &std::path::Path) -> Result<Channel> {
    let mut last_error: Option<String> = None;
    for _ in 0..100 {
        match connect_once(socket_path).await {
            Ok(channel) => return Ok(channel),
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(Error::execution(format!(
        "timed out waiting for external compute driver socket '{}': {}",
        socket_path.display(),
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

#[cfg(unix)]
async fn connect_once(socket_path: &std::path::Path) -> Result<Channel> {
    let socket_path = socket_path.to_path_buf();
    let display_path = socket_path.clone();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(|e| {
            Error::execution(format!(
                "failed to connect to external compute driver socket '{}': {e}",
                display_path.display()
            ))
        })
}

#[cfg(not(unix))]
pub(crate) async fn connect(_socket_path: &std::path::Path) -> Result<Channel> {
    Err(Error::config(
        "the external compute driver requires unix domain socket support",
    ))
}
