//! Admin TCP listener connection handling.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::{AdminControlHandle, AdminOperationRuntime, admin_response};
use crate::state::AppHandle;

struct AdminHttp1Context {
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  scheme: &'static str,
  client_certificate: Option<crate::tls::VerifiedClientCertificate>,
}

pub(super) async fn tcp_stream_starts_with_tls(stream: &TcpStream) -> bool {
  let mut byte = [0_u8; 1];
  matches!(stream.peek(&mut byte).await, Ok(1..) if byte[0] == 22)
}

pub(super) async fn handle_admin_tls_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  let config = snapshot
    .admin_tls_server_config
    .clone()
    .ok_or_else(|| anyhow::anyhow!("admin TLS is not configured"))?;
  drop(snapshot);
  let acceptor = TlsAcceptor::from(config);
  let tls_stream = tokio::time::timeout(
    Duration::from_millis(state.snapshot().config.limits.tls_handshake_timeout_ms),
    acceptor.accept(stream),
  )
  .await
  .context("admin TLS handshake timed out")?
  .context("admin TLS handshake failed")?;
  let client_certificate = crate::tls::verified_client_certificate(
    tls_stream
      .get_ref()
      .1
      .peer_certificates()
      .unwrap_or_default(),
  );
  serve_admin_http1(
    tls_stream,
    AdminHttp1Context {
      peer_addr,
      listener_bind,
      state,
      admin_control,
      admin_operations,
      scheme: "https",
      client_certificate,
    },
  )
  .await
}

pub(super) async fn handle_admin_plaintext_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
) -> anyhow::Result<()> {
  serve_admin_http1(
    stream,
    AdminHttp1Context {
      peer_addr,
      listener_bind,
      state,
      admin_control,
      admin_operations,
      scheme: "http",
      client_certificate: None,
    },
  )
  .await
}

async fn serve_admin_http1<I>(io: I, context: AdminHttp1Context) -> anyhow::Result<()>
where
  I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
  let AdminHttp1Context {
    peer_addr,
    listener_bind,
    state,
    admin_control,
    admin_operations,
    scheme,
    client_certificate,
  } = context;
  let snapshot = state.snapshot();
  let header_timeout_ms = snapshot.config.limits.client_header_timeout_ms;
  let max_headers = snapshot.config.limits.max_headers;
  let max_total_header_bytes = snapshot.config.limits.max_total_header_bytes.max(8192);
  drop(snapshot);

  let service = service_fn(move |mut request: hyper::Request<Incoming>| {
    let state = state.clone();
    let admin_control = admin_control.clone();
    let admin_operations = admin_operations.clone();
    let client_certificate = client_certificate.clone();
    async move {
      if let Some(client_certificate) = client_certificate {
        request.extensions_mut().insert(client_certificate);
      }
      Ok::<_, Infallible>(
        admin_response(
          request,
          state,
          admin_control,
          admin_operations,
          peer_addr,
          listener_bind,
          scheme,
        )
        .await,
      )
    }
  });
  let mut builder = hyper::server::conn::http1::Builder::new();
  builder
    .timer(TokioTimer::new())
    .header_read_timeout(Duration::from_millis(header_timeout_ms))
    .max_headers(max_headers)
    .max_buf_size(max_total_header_bytes)
    .keep_alive(true);
  let io = super::http1_framing_guard::Http1FramingGuard::new(io, max_total_header_bytes);
  builder
    .serve_connection(TokioIo::new(io), service)
    .with_upgrades()
    .await
    .map_err(|error| anyhow::anyhow!(error))
}
