use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::digest;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::proxy::http;
use crate::state::AppState;
use crate::tcp_hop;
use crate::waf::WafTlsMetadata;

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
  let tcp_max_hop = state.waf.person_proof_tcp_max_hop();
  if let Some(max_hop) = tcp_max_hop {
    tcp_hop::apply_tcp_max_hop(&stream, peer_addr.ip(), max_hop)
      .with_context(|| format!("failed to apply TCP max hop {max_hop} for {peer_addr}"))?;
  }

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
  let tls_metadata = Arc::new(downstream_tls_metadata(tls_stream.get_ref().1));

  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    let tls_metadata = tls_metadata.clone();
    async move {
      Ok::<_, Infallible>(http::handle(request, peer_addr, tcp_max_hop, tls_metadata, state).await)
    }
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

fn downstream_tls_metadata(connection: &rustls::ServerConnection) -> WafTlsMetadata {
  let version = connection
    .protocol_version()
    .map(|version| format!("{version:?}"));
  let cipher_suite = connection
    .negotiated_cipher_suite()
    .map(|suite| format!("{:?}", suite.suite()));
  let sni = connection.server_name().map(str::to_string);
  let alpn = connection
    .alpn_protocol()
    .map(|proto| String::from_utf8_lossy(proto).into_owned());
  let fingerprint = Some(tls_fingerprint(
    version.as_deref(),
    cipher_suite.as_deref(),
    sni.as_deref(),
    alpn.as_deref(),
  ));

  WafTlsMetadata {
    enabled: true,
    version,
    cipher_suite,
    sni,
    alpn,
    fingerprint,
  }
}

fn tls_fingerprint(
  version: Option<&str>,
  cipher_suite: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  let payload = format!(
    "rustls-negotiated-v1\nversion={}\ncipher_suite={}\nsni={}\nalpn={}",
    version.unwrap_or_default(),
    cipher_suite.unwrap_or_default(),
    sni.unwrap_or_default(),
    alpn.unwrap_or_default()
  );
  let hash = digest::digest(&digest::SHA256, payload.as_bytes());
  hex_encode(hash.as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}
