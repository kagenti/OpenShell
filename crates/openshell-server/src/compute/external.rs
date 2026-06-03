// SPDX-FileCopyrightText: Copyright (c) 2026 Kagenti Authors
// SPDX-License-Identifier: Apache-2.0

//! External compute driver connection over a pre-existing Unix domain socket.

#[cfg(unix)]
use hyper_util::rt::TokioIo;
use openshell_core::{Error, Result};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
use tonic::transport::Channel;
#[cfg(unix)]
use tonic::transport::Endpoint;
#[cfg(unix)]
use tower::service_fn;
#[cfg(unix)]
use tracing::debug;

/// Connect to an external compute driver over a Unix domain socket.
///
/// Retries up to 100 times with 100ms intervals (~10s total) to allow the
/// sidecar container to become ready.
#[cfg(unix)]
pub async fn connect(socket_path: &Path) -> Result<Channel> {
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
                    "Connected to external compute driver"
                );
                return Ok(channel);
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Err(Error::execution(format!(
        "failed to connect to external compute driver socket '{}' after 10s: {}",
        socket_path_buf.display(),
        last_err.unwrap()
    )))
}

#[cfg(not(unix))]
pub async fn connect(_socket_path: &std::path::Path) -> Result<Channel> {
    Err(Error::config(
        "external compute driver is only supported on Unix",
    ))
}
