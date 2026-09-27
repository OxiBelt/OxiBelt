//! Dedicated RFC 8441 WebSocket upstream connection.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, Uri, Version};
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::AsyncWriteExt as _;
use tokio::task::JoinHandle;

use crate::config::{HttpVersion, UpstreamConfig};
use crate::proxy_protocol_egress::tls::PreparedTlsHeader;
use crate::state::AppSnapshot;
use crate::waf::metadata::WafCertificateMetadata;

use super::EffectiveTimeouts;

/// The accepted HTTP/2 CONNECT stream and its dedicated connection lifetime.
pub(crate) struct H2WebSocketUpstream {
  pub(crate) response_headers: HeaderMap,
  pub(crate) stream: TokioIo<hyper::upgrade::Upgraded>,
  pub(crate) guard: H2WebSocketConnectionGuard,
  pub(crate) upstream_certificate: Option<Arc<WafCertificateMetadata>>,
}

/// Keeps the HTTP/2 connection driver and its admitted TCP lease alive while
/// the caller bridges the WebSocket stream.
pub(crate) struct H2WebSocketConnectionGuard {
  driver: JoinHandle<()>,
}

impl Drop for H2WebSocketConnectionGuard {
  fn drop(&mut self) {
    self.driver.abort();
  }
}

/// Opens one HTTP/2 upstream WebSocket session. The selected version is exact:
/// failure to negotiate extended CONNECT never retries through HTTP/1.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_upstream_websocket_h2(
  upstream: &UpstreamConfig,
  target_uri: Uri,
  headers: HeaderMap,
  state: &AppSnapshot,
  client_addr: SocketAddr,
  pool_name: Option<&str>,
  timeouts: EffectiveTimeouts,
  prepared_tls: Option<PreparedTlsHeader>,
) -> anyhow::Result<H2WebSocketUpstream> {
  anyhow::ensure!(
    upstream.websocket,
    "selected upstream does not allow WebSocket"
  );
  anyhow::ensure!(
    upstream.max_http_version >= HttpVersion::H2,
    "selected upstream does not allow HTTP/2"
  );
  anyhow::ensure!(
    matches!(upstream.origin.scheme(), "http" | "https"),
    "HTTP/2 WebSocket upstream requires an HTTP or HTTPS origin"
  );
  anyhow::ensure!(
    target_uri.scheme_str() == Some(upstream.origin.scheme()),
    "HTTP/2 WebSocket target scheme does not match the upstream origin"
  );
  anyhow::ensure!(
    target_uri.authority().is_some() && target_uri.path().starts_with('/'),
    "HTTP/2 WebSocket target must have an authority and absolute path"
  );
  anyhow::ensure!(
    upstream.proxy_protocol_tls.is_none() || prepared_tls.is_some(),
    "required PROXY TLS metadata was not prepared"
  );

  let headers = prepare_connect_headers(headers);
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .version(Version::HTTP_2)
    .uri(target_uri)
    .body(Empty::<Bytes>::new())
    .context("failed to build upstream HTTP/2 WebSocket CONNECT")?;
  *request.headers_mut() = headers;
  request
    .extensions_mut()
    .insert(hyper::ext::Protocol::from_static("websocket"));

  let admission = crate::upstream_resolution::ConnectionAdmissionContext::new(
    state.circuit_breakers.clone(),
    pool_name.map(Arc::<str>::from),
  );
  let (mut tcp, remote_addr, connect_deadline) = super::connect_upstream_tcp(
    upstream,
    &state.config.proxy.upstream_resolution,
    timeouts,
    admission,
  )
  .await?;
  crate::tcp_socket::enable_tcp_nodelay(tcp.get_ref(), remote_addr, "upstream HTTP/2 WebSocket");
  tokio::time::timeout_at(connect_deadline, async {
    if let Some(prepared_tls) = prepared_tls {
      tcp.write_all(prepared_tls.bytes()).await
    } else {
      crate::proxy_protocol_egress::write_header(
        &mut tcp,
        upstream.proxy_protocol_egress,
        client_addr,
        remote_addr,
      )
      .await
    }
  })
  .await
  .context("upstream HTTP/2 WebSocket PROXY header timed out")?
  .context("failed to write upstream HTTP/2 WebSocket PROXY header")?;

  let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
  crate::h2_tuning::apply_client_conn_defaults(&mut builder, &state.config.proxy.http2);
  let (mut sender, connection, upstream_certificate) = if upstream.origin.scheme() == "https" {
    let tls_config = state
      .clients
      .one_shot_tls_config(upstream, HttpVersion::H2)
      .context("upstream HTTP/2 WebSocket TLS policy is unavailable")?;
    let origin_host = upstream
      .origin
      .host_str()
      .context("HTTP/2 WebSocket upstream origin has no host")?;
    let server_name = upstream.tls.server_name.as_deref().unwrap_or(origin_host);
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
      .context("invalid HTTP/2 WebSocket upstream TLS server name")?;
    let tls = tokio::time::timeout_at(
      connect_deadline,
      tokio_rustls::TlsConnector::from(tls_config).connect(server_name, tcp),
    )
    .await
    .context("upstream HTTP/2 WebSocket TLS handshake timed out")?
    .context("upstream HTTP/2 WebSocket TLS handshake failed")?;
    anyhow::ensure!(
      tls.get_ref().1.alpn_protocol() == Some(b"h2"),
      "upstream HTTP/2 WebSocket did not negotiate ALPN h2"
    );
    let certificate = tls
      .get_ref()
      .1
      .peer_certificates()
      .and_then(crate::tls::peer_certificate_metadata);
    let (sender, connection) =
      tokio::time::timeout_at(connect_deadline, builder.handshake(TokioIo::new(tls)))
        .await
        .context("upstream HTTP/2 WebSocket connection handshake timed out")?
        .context("failed to establish upstream HTTP/2 WebSocket connection")?;
    (sender, EitherConnection::Tls(connection), certificate)
  } else {
    let (sender, connection) =
      tokio::time::timeout_at(connect_deadline, builder.handshake(TokioIo::new(tcp)))
        .await
        .context("upstream HTTP/2 WebSocket h2c handshake timed out")?
        .context("failed to establish upstream HTTP/2 WebSocket h2c connection")?;
    (sender, EitherConnection::Clear(connection), None)
  };

  let guard = H2WebSocketConnectionGuard {
    driver: tokio::spawn(async move {
      let result = match connection {
        EitherConnection::Tls(connection) => connection.await,
        EitherConnection::Clear(connection) => connection.await,
      };
      if let Err(error) = result {
        tracing::debug!(error = %error, "upstream HTTP/2 WebSocket connection closed");
      }
    }),
  };
  let request_deadline = request_deadline(timeouts)?;
  tokio::time::timeout_at(
    request_deadline,
    sender.wait_for_extended_connect_protocol(),
  )
  .await
  .context("upstream HTTP/2 WebSocket extended CONNECT SETTINGS timed out")?
  .context("upstream HTTP/2 WebSocket extended CONNECT SETTINGS failed")?;
  anyhow::ensure!(
    sender.is_extended_connect_protocol_enabled(),
    "upstream HTTP/2 WebSocket extended CONNECT was disabled"
  );

  let mut response = tokio::time::timeout_at(request_deadline, sender.send_request(request))
    .await
    .context("upstream HTTP/2 WebSocket CONNECT timed out")?
    .context("upstream HTTP/2 WebSocket CONNECT failed")?;
  anyhow::ensure!(
    response.status() == StatusCode::OK,
    "upstream HTTP/2 WebSocket CONNECT returned {}",
    response.status()
  );
  let response_headers = response.headers().clone();
  let stream = tokio::time::timeout_at(request_deadline, hyper::upgrade::on(&mut response))
    .await
    .context("upstream HTTP/2 WebSocket upgrade timed out")?
    .context("upstream HTTP/2 WebSocket upgrade failed")?;
  Ok(H2WebSocketUpstream {
    response_headers,
    stream: TokioIo::new(stream),
    guard,
    upstream_certificate,
  })
}

fn prepare_connect_headers(mut headers: HeaderMap) -> HeaderMap {
  // RFC 8441 sends :protocol=websocket in an extended CONNECT. The version
  // offer remains part of the WebSocket handshake; HTTP/1 Upgrade and key
  // challenge fields do not.
  super::headers::strip_hop_by_hop_headers(&mut headers);
  for name in [
    "connection",
    "upgrade",
    "host",
    "content-length",
    "transfer-encoding",
    "sec-websocket-key",
    "sec-websocket-accept",
  ] {
    headers.remove(name);
  }
  headers
}

// TLS and h2c carry different IO types but have identical connection-driver
// lifecycle. Keep the driver inside one guard without boxing the transport.
enum EitherConnection<Tls, Clear> {
  Tls(Tls),
  Clear(Clear),
}

fn request_deadline(timeouts: EffectiveTimeouts) -> anyhow::Result<tokio::time::Instant> {
  let deadline = std::time::Instant::now()
    .checked_add(timeouts.upstream_first_byte)
    .context("upstream HTTP/2 WebSocket request deadline overflow")?;
  Ok(tokio::time::Instant::from_std(
    timeouts
      .upstream_deadline
      .map_or(deadline, |configured| configured.min(deadline)),
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn extended_connect_preserves_version_and_application_negotiation() {
    let mut headers = HeaderMap::new();
    headers.insert("connection", "Upgrade, x-local".parse().unwrap());
    headers.insert("upgrade", "websocket".parse().unwrap());
    headers.insert("x-local", "discard".parse().unwrap());
    headers.insert(
      "sec-websocket-key",
      "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
    );
    headers.insert("sec-websocket-version", "13".parse().unwrap());
    headers.insert("sec-websocket-protocol", "chat".parse().unwrap());
    headers.insert("origin", "https://example.test".parse().unwrap());

    let headers = prepare_connect_headers(headers);
    assert!(!headers.contains_key("connection"));
    assert!(!headers.contains_key("upgrade"));
    assert!(!headers.contains_key("x-local"));
    assert!(!headers.contains_key("sec-websocket-key"));
    assert_eq!(headers["sec-websocket-version"], "13");
    assert_eq!(headers["sec-websocket-protocol"], "chat");
    assert_eq!(headers["origin"], "https://example.test");
  }
}
