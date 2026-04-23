use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::proxy::http;
use crate::state::AppState;

pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
  let bind = state.config.listeners.https_bind;
  let listener = TcpListener::bind(bind)
    .await
    .with_context(|| format!("failed to bind downstream listener to {bind}"))?;
  let acceptor = TlsAcceptor::from(state.tls_server_config.clone());

  info!(bind = %bind, "downstream HTTPS listener started");

  loop {
    tokio::select! {
        biased;
        result = tokio::signal::ctrl_c() => {
            result.context("failed to wait for ctrl_c signal")?;
            info!("shutdown signal received");
            return Ok(());
        }
        accepted = listener.accept() => {
            let (stream, peer_addr) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "failed to accept downstream connection");
                    continue;
                }
            };

            let connection_state = state.clone();
            let connection_acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, peer_addr, connection_acceptor, connection_state).await {
                    warn!(peer = %peer_addr, error = %error, "downstream connection closed with error");
                }
            });
        }
    }
  }
}

async fn handle_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  acceptor: TlsAcceptor,
  state: Arc<AppState>,
) -> anyhow::Result<()> {
  let tls_stream = acceptor
    .accept(stream)
    .await
    .context("TLS handshake failed")?;

  let negotiated = tls_stream
    .get_ref()
    .1
    .alpn_protocol()
    .map(|proto| proto.to_vec())
    .unwrap_or_else(|| b"http/1.1".to_vec());

  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    async move { Ok::<_, Infallible>(http::handle(request, peer_addr, state).await) }
  });

  if negotiated == b"h2" {
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
      .serve_connection(TokioIo::new(tls_stream), service)
      .await
      .map_err(|error| {
        error!(peer = %peer_addr, error = %error, "HTTP/2 downstream connection failed");
        anyhow::anyhow!(error)
      })?;
  } else {
    hyper::server::conn::http1::Builder::new()
      .keep_alive(true)
      .serve_connection(TokioIo::new(tls_stream), service)
      .with_upgrades()
      .await
      .map_err(|error| {
        error!(peer = %peer_addr, error = %error, "HTTP/1.1 downstream connection failed");
        anyhow::anyhow!(error)
      })?;
  }

  Ok(())
}
