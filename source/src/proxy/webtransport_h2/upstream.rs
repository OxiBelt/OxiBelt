//! Dedicated HTTP/2 WebTransport upstream connections.
//!
//! A WebTransport session never borrows an ordinary HTTP client-pool connection:
//! the driver, TCP admission lease, and negotiated SETTINGS live until this guard
//! is dropped.

use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use http::{HeaderValue, Method, Request, Version};
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::task::JoinHandle;

use crate::config::HttpVersion;
use crate::proxy::http::{EffectiveTimeouts, PreparedWebTransport};
use crate::proxy::http3::UpstreamWebTransportSession;
use crate::state::AppSnapshot;

/// Owns the HTTP/2 connection driver for one dedicated upstream session.
pub(crate) struct H2WebTransportConnectionGuard {
  driver: Option<JoinHandle<()>>,
  actor: JoinHandle<std::io::Result<()>>,
}

/// Aborts a just-started driver on every error path before ownership moves to
/// the session guard.  This keeps the admitted TCP lease from surviving a
/// CONNECT timeout or malformed response.
struct PendingDriver {
  task: Option<JoinHandle<()>>,
}

impl PendingDriver {
  fn new(task: JoinHandle<()>) -> Self {
    Self { task: Some(task) }
  }
}

impl Drop for PendingDriver {
  fn drop(&mut self) {
    if let Some(task) = self.task.take() {
      task.abort();
    }
  }
}

impl H2WebTransportConnectionGuard {
  fn new(driver: Option<JoinHandle<()>>, actor: JoinHandle<std::io::Result<()>>) -> Self {
    Self { driver, actor }
  }

  pub(crate) async fn finish(&mut self) {
    // Keep the session's caller-owned permits until queued CLOSE/RESET and the
    // connection driver have retired. A non-reading peer cannot extend cleanup.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    if tokio::time::timeout_at(deadline, &mut self.actor)
      .await
      .is_err()
    {
      self.actor.abort();
      let _ = (&mut self.actor).await;
    }
    if let Some(mut driver) = self.driver.take()
      && tokio::time::timeout_at(deadline, &mut driver)
        .await
        .is_err()
    {
      driver.abort();
      let _ = driver.await;
    }
  }
}

impl Drop for H2WebTransportConnectionGuard {
  fn drop(&mut self) {
    self.actor.abort();
    if let Some(driver) = self.driver.take() {
      driver.abort();
    }
  }
}

/// Establishes one TLS 1.3-only, HTTP/2-only upstream WebTransport session.
/// The selected HTTP version is exact: this function never retries on H3 or
/// borrows an ordinary HTTP/2 pool connection.
pub(crate) async fn connect_upstream_webtransport(
  prepared: &PreparedWebTransport,
  state: &AppSnapshot,
) -> anyhow::Result<(
  UpstreamWebTransportSession,
  H2WebTransportConnectionGuard,
  Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
)> {
  anyhow::ensure!(
    prepared.upstream_version == HttpVersion::H2,
    "HTTP/2 WebTransport connector received a non-HTTP/2 upstream selection"
  );
  anyhow::ensure!(
    prepared.upstream.origin.scheme() == "https",
    "HTTP/2 WebTransport requires an HTTPS upstream origin"
  );

  let inherited_roots = state
    .config
    .proxy
    .trusted_ca_certs
    .iter()
    .chain(&prepared.upstream.extra_trusted_ca_certs)
    .cloned()
    .collect::<Vec<_>>();
  let revocation_policy = state
    .outbound_revocation
    .policy_for_upstream(&prepared.upstream);
  let tls_config = crate::tls::build_upstream_h2_webtransport_client_config_with_policy(
    &state.config.crypto,
    &inherited_roots,
    &prepared.upstream.tls,
    Some(&state.tls_resumption),
    &prepared.upstream.name,
    Some((&state.outbound_revocation, revocation_policy)),
  )
  .with_context(|| {
    format!(
      "failed to build TLS 1.3-only HTTP/2 WebTransport client for {}",
      prepared.upstream.name
    )
  })?;
  let origin_host = prepared
    .upstream
    .origin
    .host_str()
    .context("HTTP/2 WebTransport upstream origin has no host")?;
  let server_name = prepared
    .upstream
    .tls
    .server_name
    .as_deref()
    .unwrap_or(origin_host);
  let server_name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
    .context("invalid HTTP/2 WebTransport upstream TLS server name")?;
  let admission = crate::upstream_resolution::ConnectionAdmissionContext::new(
    state.circuit_breakers.clone(),
    crate::pools::circuit_pool_for_upstream(&prepared.upstream.name, &state.config.upstream_pools),
  );
  let (mut tcp, remote_addr, connect_deadline) = crate::proxy::http::connect_upstream_tcp(
    &prepared.upstream,
    &state.config.proxy.upstream_resolution,
    prepared.timeouts,
    admission,
  )
  .await?;
  crate::tcp_socket::enable_tcp_nodelay(tcp.get_ref(), remote_addr, "upstream HTTP/2 WebTransport");
  tokio::time::timeout_at(connect_deadline, async {
    crate::proxy_protocol_egress::write_header(
      &mut tcp,
      prepared.upstream.proxy_protocol_egress,
      prepared.client_addr,
      remote_addr,
    )
    .await
  })
  .await
  .context("upstream HTTP/2 WebTransport PROXY protocol egress header timed out")?
  .context("failed to write upstream HTTP/2 WebTransport PROXY protocol egress header")?;

  let tls = tokio::time::timeout_at(
    connect_deadline,
    tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(server_name, tcp),
  )
  .await
  .context("upstream HTTP/2 WebTransport TLS handshake timed out")?
  .context("upstream HTTP/2 WebTransport TLS handshake failed")?;
  if tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
    anyhow::bail!("upstream HTTP/2 WebTransport did not negotiate TLS 1.3");
  }
  if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
    anyhow::bail!("upstream HTTP/2 WebTransport did not negotiate ALPN h2");
  }
  let upstream_certificate = tls
    .get_ref()
    .1
    .peer_certificates()
    .and_then(crate::tls::peer_certificate_metadata);

  let limits = state.config.proxy.http2.webtransport;
  let stream_credit = u32::try_from(limits.max_stream_buffer_bytes)
    .context("HTTP/2 WebTransport stream buffer exceeds protocol credit range")?;
  let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
  crate::h2_tuning::apply_client_conn_defaults(&mut builder, &state.config.proxy.http2);
  builder.webtransport_settings(hyper::ext::WebTransportSettings {
    enabled: true,
    initial_max_data: Some(0),
    initial_max_stream_data_uni: Some(stream_credit),
    initial_max_stream_data_bidi_local: Some(stream_credit),
    initial_max_stream_data_bidi_remote: Some(stream_credit),
    initial_max_streams_uni: Some(0),
    initial_max_streams_bidi: Some(0),
  });
  let request = h2_connect_request(prepared)?;
  crate::webtransport::handshake::validate_capsule_headers(request.headers())
    .context("invalid upstream HTTP/2 WebTransport CONNECT capsule headers")?;
  let request_deadline = request_deadline(prepared.timeouts)?;
  let (mut sender, connection) =
    tokio::time::timeout_at(connect_deadline, builder.handshake(TokioIo::new(tls)))
      .await
      .context("upstream HTTP/2 WebTransport handshake timed out")?
      .context("failed to establish upstream HTTP/2 WebTransport connection")?;
  let mut driver = PendingDriver::new(tokio::spawn(async move {
    if let Err(error) = connection.await {
      tracing::debug!(error = %error, "upstream HTTP/2 WebTransport connection closed");
    }
  }));
  let (response, carrier) = match tokio::time::timeout_at(
    request_deadline,
    sender.send_webtransport_request(request),
  )
  .await
  {
    Ok(Ok(result)) => result,
    Ok(Err(error)) => {
      return Err(anyhow::Error::new(error).context("upstream HTTP/2 WebTransport CONNECT failed"));
    }
    Err(_) => anyhow::bail!("upstream HTTP/2 WebTransport CONNECT timed out"),
  };
  if !response.status().is_success() {
    anyhow::bail!(
      "upstream HTTP/2 WebTransport CONNECT returned {}",
      response.status()
    );
  }
  crate::webtransport::handshake::validate_capsule_headers(response.headers())
    .context("invalid upstream HTTP/2 WebTransport response capsule headers")?;
  let peer_stream_limits = crate::webtransport::handshake::peer_stream_limits(response.headers())
    .context("invalid upstream HTTP/2 WebTransport-Init header")?;
  let selected_protocol = selected_h2_protocol(response.headers(), &prepared.protocols);
  let response_headers = response_header_pairs(response.headers());
  let mut options =
    crate::webtransport::SessionOptions::proxy(limits, crate::webtransport::Role::Client);
  options.peer_stream_limits = peer_stream_limits;
  let (session, actor) = match crate::webtransport::Session::start(
    carrier,
    options,
    state.webtransport_h2_budget.clone(),
  ) {
    Ok(session) => session,
    Err(error) => {
      return Err(
        anyhow::Error::new(error).context("failed to start HTTP/2 WebTransport capsule session"),
      );
    }
  };
  Ok((
    UpstreamWebTransportSession::from_h2(session, selected_protocol, response_headers),
    H2WebTransportConnectionGuard::new(driver.task.take(), actor),
    upstream_certificate,
  ))
}

fn response_header_pairs(headers: &http::HeaderMap) -> Vec<(http::HeaderName, HeaderValue)> {
  headers
    .iter()
    .map(|(name, value)| (name.clone(), value.clone()))
    .collect()
}

fn selected_h2_protocol(headers: &http::HeaderMap, offered: &[String]) -> Option<String> {
  let mut values = headers.get_all("wt-protocol").iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  let item = sfv::Parser::new(value.as_bytes())
    .with_version(sfv::Version::Rfc8941)
    .parse::<sfv::Item>()
    .ok()?;
  let selected = item.bare_item.as_string()?.as_str();
  offered
    .contains(&selected.to_string())
    .then(|| selected.to_string())
}

fn h2_connect_request(prepared: &PreparedWebTransport) -> anyhow::Result<Request<Empty<Bytes>>> {
  let mut headers = prepared.headers.clone();
  // These fields describe the existing H3 CONNECT wire and cannot be replayed
  // over the HTTP/2 draft.  The HTTP/2 capsule contract is regenerated below.
  headers.remove("sec-webtransport-http3-draft");
  headers.remove("sec-webtransport-http3-draft02");
  headers.remove(http::header::CONTENT_LENGTH);
  headers.remove(http::header::CONTENT_TYPE);
  headers.remove(http::header::TRANSFER_ENCODING);
  headers.remove("capsule-protocol");
  headers.insert("capsule-protocol", HeaderValue::from_static("?1"));
  let mut request = Request::builder()
    .method(Method::CONNECT)
    .version(Version::HTTP_2)
    .uri(prepared.target_url.as_str())
    .body(Empty::<Bytes>::new())
    .context("failed to build upstream HTTP/2 WebTransport CONNECT request")?;
  *request.headers_mut() = headers;
  Ok(request)
}

fn request_deadline(timeouts: EffectiveTimeouts) -> anyhow::Result<tokio::time::Instant> {
  let deadline = std::time::Instant::now()
    .checked_add(timeouts.upstream_first_byte)
    .context("upstream HTTP/2 WebTransport request deadline overflow")?;
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
  fn h2_selected_protocol_is_forwarded_only_when_valid_and_offered() {
    let offered = vec!["a".to_string(), "b".to_string()];
    let mut headers = http::HeaderMap::new();
    headers.insert("wt-protocol", HeaderValue::from_static("\"b\";v=1"));
    assert_eq!(
      selected_h2_protocol(&headers, &offered).as_deref(),
      Some("b")
    );

    headers.insert("wt-protocol", HeaderValue::from_static("\"c\""));
    assert_eq!(selected_h2_protocol(&headers, &offered), None);

    headers.insert("wt-protocol", HeaderValue::from_static("\"unterminated"));
    assert_eq!(selected_h2_protocol(&headers, &offered), None);

    headers.insert("wt-protocol", HeaderValue::from_static("\"b\""));
    headers.append("wt-protocol", HeaderValue::from_static("\"a\""));
    assert_eq!(selected_h2_protocol(&headers, &offered), None);
  }

  #[test]
  fn h2_connect_response_retains_duplicate_application_headers() {
    let mut headers = http::HeaderMap::new();
    headers.append("x-webtransport-test", HeaderValue::from_static("one"));
    headers.append("x-webtransport-test", HeaderValue::from_static("two"));
    let pairs = response_header_pairs(&headers);
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].1, "one");
    assert_eq!(pairs[1].1, "two");
  }

  #[tokio::test]
  async fn cleanup_retains_admission_until_actor_and_driver_retire() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = permits.clone().acquire_owned().await.unwrap();
    let (actor_release, actor_wait) = tokio::sync::oneshot::channel();
    let (driver_release, driver_wait) = tokio::sync::oneshot::channel();
    let actor = tokio::spawn(async move {
      let _ = actor_wait.await;
      Ok(())
    });
    let driver = tokio::spawn(async move {
      let _ = driver_wait.await;
    });
    let mut guard = H2WebTransportConnectionGuard::new(Some(driver), actor);
    let cleanup = tokio::spawn(async move {
      guard.finish().await;
      drop(permit);
    });
    actor_release.send(()).unwrap();
    tokio::task::yield_now().await;
    assert!(permits.try_acquire().is_err());
    assert!(!cleanup.is_finished());
    driver_release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), cleanup)
      .await
      .unwrap()
      .unwrap();
    assert!(permits.try_acquire().is_ok());
  }
}
