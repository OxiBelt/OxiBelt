use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::http::{Method, Request, Response, StatusCode};
use anyhow::Context;
use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::config::{Config, ConnectionLimitIdentityMode, HttpVersion, UpstreamConfig};
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::proxy::http as http_proxy;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{
  KNOWN_SMALL_BODY_MAX_BYTES, KnownSmallResponseBody, ProxyBody, boxed_error, channel_body,
};
use crate::proxy::http::response::text_response;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::server::downstream_quic_tls_metadata;
use crate::state::AppSnapshot;
use crate::tls;

type H3BidiStream = crate::quic::h3::BidiStream<Bytes>;
type H3RequestStream = h3::server::RequestStream<H3BidiStream, Bytes>;
type H3RequestRecvStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::RecvStream, Bytes>;
type H3ServerConnection = h3::server::Connection<crate::quic::h3::Connection, Bytes>;
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

const H3_BODY_CHANNEL_CAPACITY: usize = 16;

mod request_body;
mod webtransport_bridge;

#[derive(Clone)]
pub(super) struct H3DownstreamRequestContext {
  peer_addr: SocketAddr,
  udp_connection_id: Arc<str>,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  drain: ConnectionDrain,
}

#[derive(Clone, Default)]
pub(crate) struct UpstreamH3Pools {
  by_upstream: HashMap<String, Arc<UpstreamH3Pool>>,
}

impl UpstreamH3Pools {
  pub(crate) fn new(
    upstreams: &[UpstreamConfig],
    config: &Config,
    tls_resumption: &tls::TlsResumptionState,
  ) -> anyhow::Result<Self> {
    if !config.quic.upstream_pool.enabled {
      return Ok(Self::default());
    }

    let mut by_upstream = HashMap::new();
    for upstream in upstreams {
      if upstream.max_http_version != HttpVersion::H3 {
        continue;
      }
      let quic_config = tls::build_upstream_quic_client_config_with_resumption(
        &config.proxy.trusted_ca_certs,
        &upstream.tls.ech,
        &config.quic,
        &upstream.tls.resumption,
        Some(tls_resumption),
        &upstream.name,
      )
      .with_context(|| format!("failed to build upstream HTTP/3 pool for {}", upstream.name))?;
      by_upstream.insert(
        upstream.name.clone(),
        Arc::new(UpstreamH3Pool {
          client_config: quic_config,
          quic_config: config.quic.clone(),
          quic_host_key_base_dir: config.source_paths.cert_dir.clone(),
          entries: Mutex::new(HashMap::new()),
        }),
      );
    }

    Ok(Self { by_upstream })
  }

  pub(crate) fn for_upstream(&self, upstream_name: &str) -> Option<Arc<UpstreamH3Pool>> {
    self.by_upstream.get(upstream_name).cloned()
  }
}

pub(crate) struct UpstreamH3Pool {
  client_config: h3_quinn::quinn::ClientConfig,
  quic_config: crate::config::QuicConfig,
  quic_host_key_base_dir: Option<PathBuf>,
  entries: Mutex<HashMap<H3PoolKey, Arc<PooledH3Connection>>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct H3PoolKey {
  remote_addr: SocketAddr,
  server_name: String,
}

struct PooledH3Connection {
  _endpoint: h3_quinn::quinn::Endpoint,
  connection: h3_quinn::quinn::Connection,
  send_request: H3SendRequest,
  created_at: Instant,
  last_used: std::sync::Mutex<Instant>,
  driver_task: JoinHandle<()>,
}

impl PooledH3Connection {
  fn usable(&self, upstream: &UpstreamConfig, quic_config: &crate::config::QuicConfig) -> bool {
    self.connection.close_reason().is_none()
      && self.created_at.elapsed()
        < Duration::from_millis(quic_config.upstream_pool.max_lifetime_ms)
      && self
        .last_used
        .lock()
        .expect("pooled H3 connection last_used lock poisoned")
        .elapsed()
        < Duration::from_millis(upstream.idle_timeout_ms)
  }

  fn mark_used(&self) {
    *self
      .last_used
      .lock()
      .expect("pooled H3 connection last_used lock poisoned") = Instant::now();
  }
}

impl Drop for PooledH3Connection {
  fn drop(&mut self) {
    self.connection.close(0u32.into(), b"pool entry dropped");
    self.driver_task.abort();
  }
}

impl UpstreamH3Pool {
  async fn forward_request(
    self: Arc<Self>,
    request: Request<ProxyBody>,
    upstream: &UpstreamConfig,
    timeouts: EffectiveTimeouts,
  ) -> anyhow::Result<Response<ProxyBody>> {
    let uri = request.uri().clone();
    let (server_name, remote_addr) = resolve_upstream_addr(&upstream.origin).await?;
    let key = H3PoolKey {
      remote_addr,
      server_name,
    };
    let send_request = self
      .send_request_for(key.clone(), upstream, timeouts)
      .await?;
    match send_h3_request(send_request, request, &uri, timeouts).await {
      Ok(response) => Ok(response),
      Err(error) => {
        self.remove_entry(&key).await;
        Err(error)
      }
    }
  }

  async fn send_request_for(
    &self,
    key: H3PoolKey,
    upstream: &UpstreamConfig,
    timeouts: EffectiveTimeouts,
  ) -> anyhow::Result<H3SendRequest> {
    let mut entries = self.entries.lock().await;
    if let Some(entry) = entries.get(&key).cloned() {
      if entry.usable(upstream, &self.quic_config) {
        entry.mark_used();
        return Ok(entry.send_request.clone());
      }
      entries.remove(&key);
    }

    if entries.len() >= self.quic_config.upstream_pool.max_connections_per_upstream
      && let Some(oldest_key) = entries
        .iter()
        .min_by_key(|(_, entry)| {
          *entry
            .last_used
            .lock()
            .expect("pooled H3 connection last_used lock poisoned")
        })
        .map(|(key, _)| key.clone())
    {
      entries.remove(&oldest_key);
    }

    let connected = connect_h3_upstream(
      key.server_name.clone(),
      key.remote_addr,
      self.client_config.clone(),
      &self.quic_config,
      self.quic_host_key_base_dir.as_deref(),
      timeouts.upstream_connect,
    )
    .await?;
    let entry = Arc::new(PooledH3Connection {
      _endpoint: connected.endpoint,
      connection: connected.connection,
      send_request: connected.send_request,
      created_at: Instant::now(),
      last_used: std::sync::Mutex::new(Instant::now()),
      driver_task: connected.driver_task,
    });
    let send_request = entry.send_request.clone();
    entries.insert(key, entry);
    Ok(send_request)
  }

  async fn remove_entry(&self, key: &H3PoolKey) {
    self.entries.lock().await.remove(key);
  }
}

struct ConnectedH3Upstream {
  endpoint: h3_quinn::quinn::Endpoint,
  connection: h3_quinn::quinn::Connection,
  send_request: H3SendRequest,
  driver_task: JoinHandle<()>,
}

async fn connect_h3_upstream(
  server_name: String,
  remote_addr: SocketAddr,
  quic_config: h3_quinn::quinn::ClientConfig,
  oxibelt_quic_config: &crate::config::QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  connect_timeout: Duration,
) -> anyhow::Result<ConnectedH3Upstream> {
  let endpoint =
    crate::quic::bind_client_endpoint(remote_addr, oxibelt_quic_config, quic_host_key_base_dir)?;
  let quinn_connection = tokio::time::timeout(
    connect_timeout,
    endpoint
      .connect_with(quic_config, remote_addr, &server_name)
      .with_context(|| format!("failed to start upstream HTTP/3 connection to {server_name}"))?,
  )
  .await
  .context("upstream HTTP/3 connect timed out")?
  .with_context(|| format!("failed to connect upstream HTTP/3 to {server_name}"))?;
  let connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, send_request) = h3::client::builder()
    .enable_datagram(true)
    .enable_extended_connect(true)
    .build(h3_connection)
    .await
    .context("failed to establish upstream HTTP/3 connection")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  Ok(ConnectedH3Upstream {
    endpoint,
    connection,
    send_request,
    driver_task,
  })
}

pub(crate) async fn handle_downstream_connection(
  connection: h3_quinn::quinn::Connection,
  snapshot: Arc<AppSnapshot>,
  mut shutdown: tokio::sync::watch::Receiver<bool>,
  mut data_plane_drain: tokio::sync::watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let peer_addr = connection.remote_address();
  let udp_connection_id: Arc<str> = format!("quinn-stable:{}", connection.stable_id()).into();
  let _global_permit = snapshot
    .limits
    .acquire_global_connection(&snapshot.config.limits)
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))?;
  let _http3_connection_guard = snapshot
    .runtime_introspection
    .guard(RuntimeCounter::Http3Connection);
  let connection_limit_identity = snapshot.config.limits.connection_limit_identity;
  let _ip_permit = if connection_limit_identity == ConnectionLimitIdentityMode::ProxyProtocol {
    Some(
      snapshot
        .limits
        .acquire_ip_connection(
          peer_addr.ip(),
          &snapshot.config.limits,
          &snapshot.config.connection_limits,
        )
        .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))?,
    )
  } else {
    None
  };
  let connection_limit_context = (connection_limit_identity
    == ConnectionLimitIdentityMode::FirstRequestRealIp)
    .then(ConnectionLimitContext::default);
  let max_webtransport_sessions_per_connection = snapshot
    .config
    .limits
    .max_webtransport_sessions_per_connection;
  let tls_metadata = Arc::new(downstream_quic_tls_metadata(&connection));
  let early_data = crate::quic::h3::EarlyDataTracker::default();
  let quic_connection = crate::quic::h3::Connection::new(connection, early_data.clone());
  let mut h3_connection = h3::server::builder()
    .enable_extended_connect(true)
    .enable_datagram(true)
    .enable_webtransport(true)
    .max_webtransport_sessions(max_webtransport_sessions_per_connection as u64)
    .build(quic_connection)
    .await
    .context("failed to establish downstream HTTP/3 connection")?;

  loop {
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      return Ok(());
    }
    let resolver = tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          return Ok(());
        }
        continue;
      }
      changed = data_plane_drain.changed() => {
        if changed.is_ok() && *data_plane_drain.borrow() {
          return Ok(());
        }
        continue;
      }
      accepted = h3_connection.accept() => {
        match accepted {
          Ok(resolver) => resolver,
          Err(error) if downstream_h3_accept_closed_normally(&error) => return Ok(()),
          Err(error) => return Err(error).context("failed to accept downstream HTTP/3 request"),
        }
      }
    };
    let Some(resolver) = resolver else {
      return Ok(());
    };

    let (request, stream) = resolver
      .resolve_request()
      .await
      .context("failed to resolve downstream HTTP/3 request")?;
    let is_early_data = early_data.take(stream.id());

    if rejects_unsafe_early_data(&request, snapshot.config.quic.zero_rtt, is_early_data) {
      respond_to_h3_request(stream, text_response(StatusCode::TOO_EARLY, "too early")).await?;
      continue;
    }

    if is_webtransport_request(&request) {
      webtransport_bridge::serve_webtransport_connection(
        h3_connection,
        request,
        stream,
        peer_addr,
        udp_connection_id.clone(),
        tls_metadata,
        connection_limit_context.clone(),
        snapshot,
        early_data.clone(),
        shutdown,
        drain.clone(),
      )
      .await?;
      return Ok(());
    }

    let context = H3DownstreamRequestContext {
      peer_addr,
      udp_connection_id: udp_connection_id.clone(),
      tls_metadata: tls_metadata.clone(),
      connection_limit_context: connection_limit_context.clone(),
      state: snapshot.clone(),
      drain: drain.clone(),
    };
    let _request_guard = snapshot
      .runtime_introspection
      .guard(RuntimeCounter::Http3Request);
    let status = handle_h3_request(request, stream, context).await?;
    debug!(peer = %peer_addr, %status, "handled downstream HTTP/3 request");
  }
}

pub(crate) async fn forward_request(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  if let Some(pool) = state.h3_clients.for_upstream(&upstream.name) {
    return pool.forward_request(request, upstream, timeouts).await;
  }

  forward_one_shot_request(request, upstream, state, timeouts).await
}

pub(crate) async fn forward_one_shot_request(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  let uri = request.uri().clone();
  let quic_config = tls::build_upstream_quic_client_config_with_resumption(
    &state.config.proxy.trusted_ca_certs,
    &upstream.tls.ech,
    &state.config.quic,
    &upstream.tls.resumption,
    Some(&state.tls_resumption),
    &upstream.name,
  )
  .with_context(|| format!("failed to build upstream QUIC client for {}", upstream.name))?;
  let (server_name, remote_addr) = resolve_upstream_addr(&upstream.origin).await?;
  let connected = connect_h3_upstream(
    server_name,
    remote_addr,
    quic_config,
    &state.config.quic,
    state.config.source_paths.cert_dir.as_deref(),
    timeouts.upstream_connect,
  )
  .await?;
  let guard = OneShotH3Connection {
    _endpoint: connected.endpoint,
    connection: connected.connection,
    driver_task: connected.driver_task,
  };

  let response = send_h3_request(connected.send_request, request, &uri, timeouts).await?;
  let (parts, body) = response.into_parts();
  let close_body = wrap_body_close_connection(body, move || drop(guard));
  Ok(Response::from_parts(parts, close_body))
}

struct OneShotH3Connection {
  _endpoint: h3_quinn::quinn::Endpoint,
  connection: h3_quinn::quinn::Connection,
  driver_task: JoinHandle<()>,
}

impl Drop for OneShotH3Connection {
  fn drop(&mut self) {
    self
      .connection
      .close(0u32.into(), b"one-shot request complete");
    self.driver_task.abort();
  }
}

async fn send_h3_request(
  mut send_request: H3SendRequest,
  request: Request<ProxyBody>,
  uri: &http::Uri,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  let (parts, mut body) = request.into_parts();
  let h3_request = Request::from_parts(parts, ());
  let mut stream = send_request
    .send_request(h3_request)
    .await
    .with_context(|| format!("failed to send upstream HTTP/3 request {uri}"))?;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read request body for upstream HTTP/3: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        tokio::time::timeout(timeouts.upstream_send, stream.send_data(data))
          .await
          .context("upstream HTTP/3 request data send timed out")?
          .context("failed to send upstream HTTP/3 request data")?;
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          tokio::time::timeout(timeouts.upstream_send, stream.send_trailers(trailers))
            .await
            .context("upstream HTTP/3 request trailers send timed out")?
            .context("failed to send upstream HTTP/3 request trailers")?;
        }
      }
    }
  }
  tokio::time::timeout(timeouts.upstream_send, stream.finish())
    .await
    .context("upstream HTTP/3 request finish timed out")?
    .context("failed to finish upstream HTTP/3 request")?;

  let mut interim = crate::proxy::http::semantics::InterimResponses::default();
  let parts = loop {
    let response = tokio::time::timeout(timeouts.upstream_first_byte, stream.recv_response())
      .await
      .context("upstream HTTP/3 first byte timed out")?
      .context("failed to receive upstream HTTP/3 response")?;
    if let Some(response) = crate::proxy::http::semantics::sanitize_interim_response(
      response.status(),
      response.headers(),
    ) {
      interim.responses.push(response);
      continue;
    }
    let (mut parts, _) = response.into_parts();
    if !interim.responses.is_empty() {
      parts.extensions.insert(interim);
    }
    break parts;
  };
  let (body_sender, body) = channel_body(H3_BODY_CHANNEL_CAPACITY);
  tokio::spawn(async move {
    loop {
      match tokio::time::timeout(timeouts.upstream_read, stream.recv_data()).await {
        Ok(Ok(Some(mut chunk))) => {
          let len = chunk.remaining();
          if body_sender
            .send(Ok(Frame::data(chunk.copy_to_bytes(len))))
            .await
            .is_err()
          {
            break;
          }
        }
        Ok(Ok(None)) => break,
        Ok(Err(error)) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::other(format!(
              "failed to receive upstream HTTP/3 response data: {error}"
            )))))
            .await;
          break;
        }
        Err(_) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::other(
              "upstream HTTP/3 response body read timed out",
            ))))
            .await;
          break;
        }
      }
    }
  });
  Ok(Response::from_parts(parts, body))
}

fn wrap_body_close_connection<F>(mut body: ProxyBody, close: F) -> ProxyBody
where
  F: FnOnce() + Send + 'static,
{
  let (body_sender, wrapped) = channel_body(H3_BODY_CHANNEL_CAPACITY);
  tokio::spawn(async move {
    while let Some(frame) = body.frame().await {
      if body_sender.send(frame).await.is_err() {
        break;
      }
    }
    close();
  });
  wrapped
}

async fn handle_h3_request(
  request: Request<()>,
  stream: H3RequestStream,
  context: H3DownstreamRequestContext,
) -> anyhow::Result<StatusCode> {
  let (send_stream, recv_stream) = stream.split();
  let request = request_body::prepare_h3_request_body(request, recv_stream).await;
  let response = http_proxy::handle_http3(
    request,
    context.peer_addr,
    context.udp_connection_id.as_ref(),
    context.tls_metadata,
    context.connection_limit_context,
    context.state,
    context.drain,
  )
  .await;
  let status = response.status();
  respond_to_h3_request(send_stream, response).await?;
  Ok(status)
}

pub(crate) async fn respond_to_h3_request<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  response: Response<ProxyBody>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let response_send_timeout = http_proxy::downstream_response_send_timeout(&response);
  let (parts, mut body) = response.into_parts();
  let mut parts = parts;
  if let Some(interim) = parts
    .extensions
    .remove::<crate::proxy::http::semantics::InterimResponses>()
  {
    for response in interim.responses {
      let head = Response::builder()
        .status(response.status)
        .body(())
        .context("failed to build downstream HTTP/3 interim response")?;
      let (mut interim_parts, _) = head.into_parts();
      interim_parts.headers = response.headers;
      stream
        .send_response(Response::from_parts(interim_parts, ()))
        .await
        .context("failed to send downstream HTTP/3 interim response")?;
    }
  }
  let use_known_small_response_body = use_h3_known_small_body_path(
    parts.extensions.get::<KnownSmallResponseBody>().is_some(),
    &body,
  );
  let head = Response::from_parts(parts, ());
  stream
    .send_response(head)
    .await
    .context("failed to send downstream HTTP/3 response headers")?;

  if use_known_small_response_body {
    return respond_to_h3_known_small_body(stream, body, response_send_timeout).await;
  }

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read downstream HTTP/3 response body: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        maybe_timeout(response_send_timeout, stream.send_data(data))
          .await
          .context("failed to send downstream HTTP/3 response data")?;
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          maybe_timeout(response_send_timeout, stream.send_trailers(trailers))
            .await
            .context("failed to send downstream HTTP/3 response trailers")?;
        }
      }
    }
  }
  maybe_timeout(response_send_timeout, stream.finish())
    .await
    .context("failed to finish downstream HTTP/3 response")?;

  Ok(())
}

fn use_h3_known_small_body_path(marked_known_small: bool, body: &ProxyBody) -> bool {
  marked_known_small
    && body
      .size_hint()
      .upper()
      .is_some_and(|upper| upper <= KNOWN_SMALL_BODY_MAX_BYTES as u64)
}

async fn respond_to_h3_known_small_body<S>(
  mut stream: h3::server::RequestStream<S, Bytes>,
  body: ProxyBody,
  response_send_timeout: Option<Duration>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  let collected = collect_h3_known_small_body(body).await?;
  let trailers = collected.trailers;
  let data = collected.data;
  if !data.is_empty() {
    maybe_timeout(response_send_timeout, stream.send_data(data))
      .await
      .context("failed to send downstream HTTP/3 response data")?;
  }
  if let Some(trailers) = trailers {
    maybe_timeout(response_send_timeout, stream.send_trailers(trailers))
      .await
      .context("failed to send downstream HTTP/3 response trailers")?;
  }
  maybe_timeout(response_send_timeout, stream.finish())
    .await
    .context("failed to finish downstream HTTP/3 response")?;
  Ok(())
}

#[derive(Debug)]
struct H3KnownSmallBody {
  data: Bytes,
  trailers: Option<http::HeaderMap>,
}

async fn collect_h3_known_small_body(mut body: ProxyBody) -> anyhow::Result<H3KnownSmallBody> {
  let mut chunks = Vec::new();
  let mut total = 0usize;
  let mut trailers = None;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read downstream HTTP/3 response body: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        if data.is_empty() {
          continue;
        }
        total = total
          .checked_add(data.len())
          .context("downstream HTTP/3 known-small response body length overflow")?;
        if total > KNOWN_SMALL_BODY_MAX_BYTES {
          anyhow::bail!(
            "downstream HTTP/3 known-small response body exceeded {} bytes",
            KNOWN_SMALL_BODY_MAX_BYTES
          );
        }
        chunks.push(data);
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
          break;
        }
      }
    }
  }

  let data = match chunks.len() {
    0 => Bytes::new(),
    1 => chunks.pop().unwrap_or_default(),
    _ => {
      let mut bytes = BytesMut::with_capacity(total);
      for chunk in chunks {
        bytes.extend_from_slice(&chunk);
      }
      bytes.freeze()
    }
  };

  Ok(H3KnownSmallBody { data, trailers })
}

async fn maybe_timeout<F, T, E>(timeout: Option<Duration>, future: F) -> anyhow::Result<T>
where
  F: std::future::Future<Output = Result<T, E>>,
  E: std::error::Error + Send + Sync + 'static,
{
  match timeout {
    Some(timeout) => tokio::time::timeout(timeout, future)
      .await
      .context("downstream HTTP/3 response send timed out")?
      .map_err(Into::into),
    None => future.await.map_err(Into::into),
  }
}

async fn connect_upstream_webtransport(
  prepared: &http_proxy::PreparedWebTransport,
  state: &AppSnapshot,
) -> anyhow::Result<web_transport_quinn::Session> {
  let quic_config = tls::build_upstream_quic_client_config_with_resumption(
    &state.config.proxy.trusted_ca_certs,
    &prepared.upstream.tls.ech,
    &state.config.quic,
    &prepared.upstream.tls.resumption,
    Some(&state.tls_resumption),
    &prepared.upstream.name,
  )
  .with_context(|| {
    format!(
      "failed to build upstream WebTransport QUIC client for {}",
      prepared.upstream.name
    )
  })?;
  let mut request = web_transport_quinn::proto::ConnectRequest::new(prepared.target_url.clone())
    .with_headers(prepared.headers.clone());
  if !prepared.protocols.is_empty() {
    request = request.with_protocols(prepared.protocols.clone());
  }
  let (server_name, remote_addr) = resolve_upstream_addr(&prepared.target_url).await?;
  let endpoint = crate::quic::bind_client_endpoint(
    remote_addr,
    &state.config.quic,
    state.config.source_paths.cert_dir.as_deref(),
  )
  .context("failed to create upstream WebTransport endpoint")?;
  let connection = tokio::time::timeout(
    prepared.timeouts.upstream_connect,
    endpoint
      .connect_with(quic_config, remote_addr, &server_name)
      .with_context(|| {
        format!("failed to start upstream WebTransport connection to {server_name}")
      })?,
  )
  .await
  .context("upstream WebTransport connect timed out")?
  .with_context(|| format!("failed to connect upstream WebTransport to {server_name}"))?;
  tokio::time::timeout(
    prepared.timeouts.upstream_first_byte,
    web_transport_quinn::Session::connect(connection, request),
  )
  .await
  .context("upstream WebTransport CONNECT timed out")?
  .context("upstream WebTransport CONNECT failed")
}

async fn resolve_upstream_addr(origin: &url::Url) -> anyhow::Result<(String, SocketAddr)> {
  let port = origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {origin}"))?;
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {origin}"))?
    .to_string();
  let remote = tokio::net::lookup_host((host.as_str(), port))
    .await
    .with_context(|| format!("failed to resolve upstream HTTP/3 host {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("upstream HTTP/3 host resolved no addresses: {host}:{port}"))?;
  Ok((host, remote))
}

pub(crate) fn is_webtransport_request(request: &Request<()>) -> bool {
  request.method() == Method::CONNECT
    && request
      .extensions()
      .get::<Protocol>()
      .is_some_and(|protocol| protocol == &Protocol::WEB_TRANSPORT)
}

pub(crate) fn rejects_unsafe_early_data(
  request: &Request<()>,
  zero_rtt: crate::config::QuicZeroRttMode,
  is_early_data: bool,
) -> bool {
  zero_rtt == crate::config::QuicZeroRttMode::SafeMethods
    && is_early_data
    && !matches!(request.method(), &Method::GET | &Method::HEAD)
}

fn downstream_h3_accept_closed_normally(error: &h3::error::ConnectionError) -> bool {
  error.is_h3_no_error() || downstream_h3_accept_message_is_normal_close(&error.to_string())
}

fn downstream_h3_accept_message_is_normal_close(message: &str) -> bool {
  let message = message.to_ascii_lowercase();
  [
    "closed before request headers completed",
    "closed by peer",
    "connection closed",
    "graceful shutdown",
    "h3_no_error",
  ]
  .iter()
  .any(|needle| message.contains(needle))
}

#[cfg(test)]
mod tests {
  use super::*;
  use http_body_util::{BodyExt, Full};

  fn full_test_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
      .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
      .boxed()
  }

  #[test]
  fn detects_webtransport_extended_connect() {
    let mut request = Request::builder()
      .method(Method::CONNECT)
      .uri("https://example.com/session")
      .body(())
      .unwrap();
    request.extensions_mut().insert(Protocol::WEB_TRANSPORT);

    assert!(is_webtransport_request(&request));
  }

  #[test]
  fn plain_connect_is_not_webtransport() {
    let request = Request::builder()
      .method(Method::CONNECT)
      .uri("https://example.com/session")
      .body(())
      .unwrap();

    assert!(!is_webtransport_request(&request));
  }

  #[test]
  fn zero_rtt_policy_rejects_non_safe_early_data_methods() {
    let request = Request::builder()
      .method(Method::POST)
      .uri("https://example.com/upload")
      .body(())
      .unwrap();

    assert!(rejects_unsafe_early_data(
      &request,
      crate::config::QuicZeroRttMode::SafeMethods,
      true
    ));
  }

  #[test]
  fn zero_rtt_policy_allows_safe_early_data_methods() {
    for method in [Method::GET, Method::HEAD] {
      let request = Request::builder()
        .method(method)
        .uri("https://example.com/read")
        .body(())
        .unwrap();

      assert!(!rejects_unsafe_early_data(
        &request,
        crate::config::QuicZeroRttMode::SafeMethods,
        true
      ));
    }
  }

  #[test]
  fn zero_rtt_policy_ignores_spoofed_early_data_header_after_handshake() {
    let request = Request::builder()
      .method(Method::POST)
      .uri("https://example.com/upload")
      .header("early-data", "1")
      .body(())
      .unwrap();

    assert!(!rejects_unsafe_early_data(
      &request,
      crate::config::QuicZeroRttMode::SafeMethods,
      false
    ));
  }

  #[test]
  fn zero_rtt_policy_is_disabled_when_zero_rtt_is_off() {
    let request = Request::builder()
      .method(Method::POST)
      .uri("https://example.com/upload")
      .body(())
      .unwrap();

    assert!(!rejects_unsafe_early_data(
      &request,
      crate::config::QuicZeroRttMode::Off,
      true
    ));
  }

  #[test]
  fn h3_accept_normal_close_messages_are_not_warnable() {
    for message in [
      "Remote error: ApplicationClose: H3_NO_ERROR",
      "connection closed before request headers completed",
      "connection closed",
      "graceful shutdown",
    ] {
      assert!(downstream_h3_accept_message_is_normal_close(message));
    }
  }

  #[test]
  fn h3_accept_protocol_errors_remain_warnable() {
    for message in [
      "Local error: Application { code: H3_MESSAGE_ERROR, reason: \"bad frame\" }",
      "Remote error: ApplicationClose: H3_FRAME_UNEXPECTED",
      "Timeout",
    ] {
      assert!(!downstream_h3_accept_message_is_normal_close(message));
    }
  }

  #[test]
  fn h3_known_small_path_requires_marker_and_small_upper_bound() {
    let small = full_test_body(Bytes::from_static(b"ok"));
    assert!(use_h3_known_small_body_path(true, &small));
    assert!(!use_h3_known_small_body_path(false, &small));

    let (_sender, unknown_upper) = channel_body(1);
    assert!(!use_h3_known_small_body_path(true, &unknown_upper));

    let large = full_test_body(Bytes::from(vec![0; KNOWN_SMALL_BODY_MAX_BYTES + 1]));
    assert!(!use_h3_known_small_body_path(true, &large));
  }

  #[tokio::test]
  async fn h3_known_small_collect_rejects_body_over_limit() {
    let body = full_test_body(Bytes::from(vec![0; KNOWN_SMALL_BODY_MAX_BYTES + 1]));
    let error = collect_h3_known_small_body(body)
      .await
      .expect_err("known-small body over the limit should fail closed");

    assert!(
      error
        .to_string()
        .contains("known-small response body exceeded")
    );
  }
}
