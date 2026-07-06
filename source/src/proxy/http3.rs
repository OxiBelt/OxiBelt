//! HTTP/3 downstream and upstream handling.
//! QUIC session state stays explicit because stream lifetimes differ from TCP request lifetimes.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use ::http::{Method, Request, Response, StatusCode};
use anyhow::Context;
use bytes::Bytes;
use h3::ext::Protocol;
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::{Config, ConnectionLimitIdentityMode, HttpVersion, UpstreamConfig};
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::proxy::http as http_proxy;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::fast_path::stage_timing as timing;
use crate::proxy::http::response::is_silent_close_response;
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::server::downstream_quic_tls_metadata;
use crate::state::AppSnapshot;
use crate::tls;
use crate::waf::WafProtocol;

type H3BidiStream = crate::quic::h3::BidiStream<Bytes>;
type H3RequestStream = h3::server::RequestStream<H3BidiStream, Bytes>;
type H3RequestSendStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::SendStream, Bytes>;
type H3RequestRecvStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::RecvStream, Bytes>;
type H3ServerConnection = h3::server::Connection<crate::quic::h3::Connection, Bytes>;
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

mod fast_response;
mod request_body;
mod request_tasks;
mod response_body;
#[cfg(test)]
mod tests;
mod webtransport_bridge;

#[cfg(test)]
use crate::proxy::http::body::{InlinedKnownSmallResponseBody, KNOWN_SMALL_BODY_MAX_BYTES};
#[cfg(test)]
use fast_response::{
  H3KnownSmallBodyPlan, collect_h3_known_small_body, take_h3_known_small_body_plan,
  use_h3_known_small_body_path,
};

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
    outbound_revocation: &tls::OutboundRevocationRuntime,
  ) -> anyhow::Result<Self> {
    if !config.quic.upstream_pool.enabled {
      return Ok(Self::default());
    }

    let mut by_upstream = HashMap::new();
    for upstream in upstreams {
      if upstream.max_http_version != HttpVersion::H3 {
        continue;
      }
      let quic_config =
        tls::build_upstream_quic_client_config_with_crypto_resumption_and_revocation(
          &config.crypto,
          &config.proxy.trusted_ca_certs,
          &upstream.tls.ech,
          &config.quic,
          &upstream.tls.resumption,
          Some(tls_resumption),
          &upstream.name,
          Some((
            outbound_revocation,
            outbound_revocation.policy_for_upstream(upstream),
          )),
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
  entries: Mutex<HashMap<H3PoolKey, Arc<H3PoolSlot>>>,
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

struct H3PoolSlot {
  connection: Mutex<Option<Arc<PooledH3Connection>>>,
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
    metrics: &Arc<crate::metrics::Metrics>,
  ) -> anyhow::Result<Response<ProxyBody>> {
    let uri = request.uri().clone();
    metrics.record_http_upstream_client_request("h3", "https", "primary");
    let (server_name, remote_addr) = resolve_upstream_addr(&upstream.origin).await?;
    let key = H3PoolKey {
      remote_addr,
      server_name,
    };
    let send_request = self
      .send_request_for(key.clone(), upstream, timeouts, metrics)
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
    metrics: &Arc<crate::metrics::Metrics>,
  ) -> anyhow::Result<H3SendRequest> {
    let slot = self.slot_for_key(key.clone()).await;
    let mut connection = slot.connection.lock().await;
    if let Some(entry) = connection.as_ref() {
      if entry.usable(upstream, &self.quic_config) {
        entry.mark_used();
        return Ok(entry.send_request.clone());
      }
      *connection = None;
    }

    metrics.record_http_upstream_client_pool_miss("h3", "https", "primary");
    let connected = connect_h3_upstream(
      key.server_name.clone(),
      key.remote_addr,
      self.client_config.clone(),
      &self.quic_config,
      self.quic_host_key_base_dir.as_deref(),
      timeouts.upstream_connect,
    )
    .await?;
    metrics.record_http_upstream_client_connection_created("h3", "https", "primary");
    let entry = Arc::new(PooledH3Connection {
      _endpoint: connected.endpoint,
      connection: connected.connection,
      send_request: connected.send_request,
      created_at: Instant::now(),
      last_used: std::sync::Mutex::new(Instant::now()),
      driver_task: connected.driver_task,
    });
    let send_request = entry.send_request.clone();
    *connection = Some(entry);
    Ok(send_request)
  }

  async fn slot_for_key(&self, key: H3PoolKey) -> Arc<H3PoolSlot> {
    let mut entries = self.entries.lock().await;
    if let Some(slot) = entries.get(&key) {
      return slot.clone();
    }

    if entries.len() >= self.quic_config.upstream_pool.max_connections_per_upstream {
      let oldest_key = entries
        .iter()
        .filter_map(|(candidate_key, slot)| {
          let connection = slot.connection.try_lock().ok()?;
          let entry = connection.as_ref()?;
          let last_used = *entry
            .last_used
            .lock()
            .expect("pooled H3 connection last_used lock poisoned");
          Some((candidate_key.clone(), last_used))
        })
        .min_by_key(|(_, last_used)| *last_used)
        .map(|(candidate_key, _)| candidate_key)
        .or_else(|| entries.keys().next().cloned());
      if let Some(oldest_key) = oldest_key {
        entries.remove(&oldest_key);
      }
    }

    let slot = Arc::new(H3PoolSlot {
      connection: Mutex::new(None),
    });
    entries.insert(key, slot.clone());
    slot
  }

  async fn remove_entry(&self, key: &H3PoolKey) {
    let slot = self.entries.lock().await.remove(key);
    if let Some(slot) = slot {
      *slot.connection.lock().await = None;
    }
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
  let _http3_connection_guard =
    snapshot.runtime_introspection_guard(RuntimeCounter::Http3Connection);
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
  let mut request_admission = request_tasks::RequestAdmission::new(&snapshot.config);
  let mut request_tasks = request_tasks::RequestTaskSet::new(&snapshot.config);
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = snapshot.request_path_features.stage_timing_metrics;
  let request_task_timing = request_tasks::RequestTaskTiming::new(snapshot.clone(), timing_enabled);
  let downstream_request_context = H3DownstreamRequestContext {
    peer_addr,
    udp_connection_id: udp_connection_id.clone(),
    tls_metadata: tls_metadata.clone(),
    connection_limit_context: connection_limit_context.clone(),
    state: snapshot.clone(),
    drain: drain.clone(),
  };
  let mut h3_connection = h3::server::builder()
    .enable_extended_connect(true)
    .enable_datagram(true)
    .enable_webtransport(true)
    .max_webtransport_sessions(max_webtransport_sessions_per_connection as u64)
    .build(quic_connection)
    .await
    .context("failed to establish downstream HTTP/3 connection")?;

  loop {
    let reap_started = timing::start(timing_enabled);
    request_tasks.reap_completed();
    if timing_enabled {
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_REQUEST_TASK_REAP,
        timing::OUTCOME_OK,
        reap_started,
      );
    }
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      request_tasks.abort_all().await;
      return Ok(());
    }
    let receive_started = timing::start(timing_enabled);
    let resolver = tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          request_tasks.abort_all().await;
          return Ok(());
        }
        continue;
      }
      changed = data_plane_drain.changed() => {
        if changed.is_ok() && *data_plane_drain.borrow() {
          request_tasks.abort_all().await;
          return Ok(());
        }
        continue;
      }
      accepted = h3_connection.accept() => {
        match accepted {
          Ok(resolver) => resolver,
          Err(error) if downstream_h3_accept_closed_normally(&error) => {
            request_tasks.wait_all().await;
            return Ok(());
          }
          Err(error) => {
            request_tasks.abort_all().await;
            return Err(error).context("failed to accept downstream HTTP/3 request");
          }
        }
      }
    };
    let Some(resolver) = resolver else {
      request_tasks.wait_all().await;
      return Ok(());
    };

    let (mut request, stream) = match resolver.resolve_request().await {
      Ok(resolved) => {
        if timing_enabled {
          timing::record(
            snapshot.as_ref(),
            timing::PATH_H3_DOWNSTREAM,
            metric_protocol,
            timing::STAGE_DOWNSTREAM_PROTOCOL_RECEIVE,
            timing::OUTCOME_OK,
            receive_started,
          );
        }
        resolved
      }
      Err(error) => {
        if timing_enabled {
          timing::record(
            snapshot.as_ref(),
            timing::PATH_H3_DOWNSTREAM,
            metric_protocol,
            timing::STAGE_DOWNSTREAM_PROTOCOL_RECEIVE,
            timing::OUTCOME_ERROR,
            receive_started,
          );
        }
        request_tasks.abort_all().await;
        return Err(error).context("failed to resolve downstream HTTP/3 request");
      }
    };
    let is_early_data = early_data.take(stream.id());
    if is_early_data {
      http_proxy::early_data::mark_verified(&mut request);
    }
    http_proxy::early_data::strip_untrusted_header(request.headers_mut());

    if is_webtransport_request(&request) {
      request_tasks.wait_all().await;
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
        request_admission,
      )
      .await?;
      return Ok(());
    }

    if !request_admission.try_admit() {
      respond_to_h3_request(stream, request_tasks::too_many_requests_response()).await?;
      continue;
    }

    let permit_started = timing::start(timing_enabled);
    let request_task_permit = if let Some(permit) = request_tasks.try_acquire_permit() {
      permit
    } else {
      match request_tasks::acquire_permit_or_stop(
        &mut request_tasks,
        &mut shutdown,
        &mut data_plane_drain,
        Some(&request_task_timing),
      )
      .await
      {
        Ok(Some(permit)) => permit,
        Ok(None) => return Ok(()),
        Err(error) => {
          if timing_enabled {
            timing::record(
              snapshot.as_ref(),
              timing::PATH_H3_DOWNSTREAM,
              metric_protocol,
              timing::STAGE_H3_REQUEST_PERMIT_ACQUIRE,
              timing::OUTCOME_ERROR,
              permit_started,
            );
          }
          return Err(error);
        }
      }
    };
    if timing_enabled {
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_REQUEST_PERMIT_ACQUIRE,
        timing::OUTCOME_OK,
        permit_started,
      );
    }

    if h3_inline_fast_path_candidate(&request, &downstream_request_context) {
      let (send_stream, recv_stream) = stream.split();
      let ingress_started = timing::start(timing_enabled);
      let prepared =
        request_body::prepare_h3_request_body_with_verification(request, recv_stream).await;
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_INGRESS_PREPARE,
        timing::OUTCOME_OK,
        ingress_started,
      );
      if prepared.verified_empty {
        debug_assert_eq!(
          prepared.inline_readiness,
          request_body::PreparedH3RequestBodyReadiness::InlineReady
        );
      }
      let inline_spawn_started = timing::start(timing_enabled);
      if prepared.inline_readiness == request_body::PreparedH3RequestBodyReadiness::Spawn {
        request_tasks.spawn_prepared(
          prepared.request,
          send_stream,
          downstream_request_context.clone(),
          request_task_permit,
        );
        if timing_enabled {
          timing::record(
            snapshot.as_ref(),
            timing::PATH_H3_DOWNSTREAM,
            metric_protocol,
            timing::STAGE_H3_REQUEST_TASK_SPAWN,
            timing::OUTCOME_OK,
            inline_spawn_started,
          );
        }
        continue;
      }
      if timing_enabled {
        timing::record(
          snapshot.as_ref(),
          timing::PATH_H3_DOWNSTREAM,
          metric_protocol,
          timing::STAGE_H3_REQUEST_TASK_SPAWN,
          timing::OUTCOME_FALLBACK,
          inline_spawn_started,
        );
      }
      let inline = request_tasks::handle_inline_prepared(
        prepared.request,
        send_stream,
        downstream_request_context.clone(),
        request_task_permit,
      );
      if !run_h3_inline_until_blocked_or_stop(
        inline,
        &mut request_tasks,
        &mut shutdown,
        &mut data_plane_drain,
      )
      .await
      {
        return Ok(());
      }
      continue;
    }

    let spawn_started = timing::start(timing_enabled);
    request_tasks.spawn(
      request,
      stream,
      downstream_request_context.clone(),
      request_task_permit,
    );
    if timing_enabled {
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_REQUEST_TASK_SPAWN,
        timing::OUTCOME_OK,
        spawn_started,
      );
    }
  }
}

async fn run_h3_inline_until_blocked_or_stop<F>(
  inline: F,
  request_tasks: &mut request_tasks::RequestTaskSet,
  shutdown: &mut tokio::sync::watch::Receiver<bool>,
  data_plane_drain: &mut tokio::sync::watch::Receiver<bool>,
) -> bool
where
  F: Future<Output = ()> + Send + 'static,
{
  let mut inline = Box::pin(inline);
  enum InlinePollOutcome {
    Complete,
    Blocked,
    Stop,
  }

  let outcome = tokio::select! {
    biased;
    changed = shutdown.changed() => {
      if changed.is_ok() && *shutdown.borrow() {
        InlinePollOutcome::Stop
      } else {
        InlinePollOutcome::Blocked
      }
    }
    changed = data_plane_drain.changed() => {
      if changed.is_ok() && *data_plane_drain.borrow() {
        InlinePollOutcome::Stop
      } else {
        InlinePollOutcome::Blocked
      }
    }
    completed_inline = poll_fn(|cx| {
      match inline.as_mut().poll(cx) {
        Poll::Ready(()) => Poll::Ready(true),
        Poll::Pending => Poll::Ready(false),
      }
    }) => {
      if completed_inline {
        InlinePollOutcome::Complete
      } else {
        InlinePollOutcome::Blocked
      }
    }
  };
  match outcome {
    InlinePollOutcome::Complete => true,
    InlinePollOutcome::Blocked => {
      request_tasks.spawn_inline_future(inline);
      true
    }
    InlinePollOutcome::Stop => {
      request_tasks.abort_all().await;
      false
    }
  }
}

fn h3_inline_fast_path_candidate(
  request: &Request<()>,
  context: &H3DownstreamRequestContext,
) -> bool {
  if !context.state.config.proxy.http3.inline_bodyless_fast_path {
    return false;
  }
  if request.version() != ::http::Version::HTTP_3 {
    return false;
  }
  if !http_proxy::request_framing::h2_or_h3_safe_method_empty_probe_allowed(
    request.method(),
    ::http::Version::HTTP_3,
    request.headers(),
  ) {
    return false;
  }
  if http_proxy::headers::validate_authority_host_consistency(request).is_err() {
    return false;
  }
  let path = request.uri().path();
  if http_proxy::validate_request_limits(request, &context.state.config.limits).is_err()
    || http_proxy::uri::validate_downstream_path(path).is_err()
  {
    return false;
  }
  let client_addr = match crate::identity::resolve_client_addr(
    request.headers(),
    context.peer_addr,
    &context.state.config.proxy.real_ip,
  ) {
    Ok(client_addr) => client_addr,
    Err(_) => return false,
  };
  let host_snapshot = http_proxy::headers::extract_host_snapshot(request);
  let host = host_snapshot.as_str();
  let resolved = context
    .state
    .route_table
    .try_resolve_simple_exact_host(host, path, &context.state.upstreams)
    .or_else(|| {
      context
        .state
        .route_table
        .resolve_normalized_host_with_context(
          host,
          RouteMatchContext {
            path,
            method: Some(request.method()),
            headers: Some(request.headers()),
            query: request.uri().query(),
            source_ip: Some(client_addr.ip()),
            protocol: Some(RouteRequestProtocol::from_http(
              ::http::Version::HTTP_3,
              WafProtocol::Http,
            )),
            tls: Some(context.tls_metadata.as_ref()),
          },
          &context.state.upstreams,
        )
    });
  let Some(resolved) = resolved else {
    return false;
  };
  http_proxy::fast_path::plain_proxy_fast_path_decision(request, context.state.as_ref(), &resolved)
    .is_ok()
}

pub(crate) async fn forward_request(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  if let Some(pool) = state.h3_clients.for_upstream(&upstream.name) {
    return pool
      .forward_request(request, upstream, timeouts, &state.metrics)
      .await;
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
  state
    .metrics
    .record_http_upstream_client_request("h3", "https", "primary");
  state
    .metrics
    .record_http_upstream_client_pool_miss("h3", "https", "primary");
  let quic_config = tls::build_upstream_quic_client_config_with_crypto_resumption_and_revocation(
    &state.config.crypto,
    &state.config.proxy.trusted_ca_certs,
    &upstream.tls.ech,
    &state.config.quic,
    &upstream.tls.resumption,
    Some(&state.tls_resumption),
    &upstream.name,
    Some((
      &state.outbound_revocation,
      state.outbound_revocation.policy_for_upstream(upstream),
    )),
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
  state
    .metrics
    .record_http_upstream_client_connection_created("h3", "https", "primary");
  let guard = OneShotH3Connection {
    _endpoint: connected.endpoint,
    connection: connected.connection,
    driver_task: connected.driver_task,
  };

  let response = send_h3_request(connected.send_request, request, &uri, timeouts).await?;
  let (parts, body) = response.into_parts();
  let close_body =
    crate::proxy::http::body::with_drop_guard(body, Arc::new(std::sync::Mutex::new(Some(guard))));
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
  let body = response_body::upstream_h3_response_body(stream, timeouts.upstream_read);
  Ok(Response::from_parts(parts, body))
}

async fn handle_h3_request(
  request: Request<()>,
  stream: H3RequestStream,
  context: H3DownstreamRequestContext,
) -> anyhow::Result<StatusCode> {
  let (send_stream, recv_stream) = stream.split();
  let state = context.state.clone();
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = state.request_path_features.stage_timing_metrics;
  let ingress_started = timing::start(timing_enabled);
  let request = request_body::prepare_h3_request_body(request, recv_stream).await;
  timing::record(
    state.as_ref(),
    timing::PATH_H3_DOWNSTREAM,
    metric_protocol,
    timing::STAGE_H3_INGRESS_PREPARE,
    timing::OUTCOME_OK,
    ingress_started,
  );
  handle_prepared_h3_request(request, send_stream, context).await
}

async fn handle_prepared_h3_request(
  request: Request<ProxyBody>,
  send_stream: H3RequestSendStream,
  context: H3DownstreamRequestContext,
) -> anyhow::Result<StatusCode> {
  let state = context.state.clone();
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = state.request_path_features.stage_timing_metrics;
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
  if is_silent_close_response(&response) {
    reset_silent_h3_request(send_stream);
    return Ok(StatusCode::NO_CONTENT);
  }
  let status = response.status();
  let send_started = timing::start(timing_enabled);
  let response_timing = timing_enabled.then(|| fast_response::H3ResponseTiming::from_state(&state));
  let send_result =
    fast_response::respond_to_h3_request_with_timing(send_stream, response, response_timing).await;
  timing::record(
    state.as_ref(),
    timing::PATH_H3_DOWNSTREAM,
    metric_protocol,
    timing::STAGE_H3_DOWNSTREAM_SEND,
    if send_result.is_ok() {
      timing::OUTCOME_OK
    } else {
      timing::OUTCOME_ERROR
    },
    send_started,
  );
  send_result?;
  Ok(status)
}

fn reset_silent_h3_request<S>(mut stream: h3::server::RequestStream<S, Bytes>)
where
  S: h3::quic::SendStream<Bytes>,
{
  stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
}

pub(crate) async fn respond_to_h3_request<S>(
  stream: h3::server::RequestStream<S, Bytes>,
  response: Response<ProxyBody>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  fast_response::respond_to_h3_request(stream, response).await
}

async fn connect_upstream_webtransport(
  prepared: &http_proxy::PreparedWebTransport,
  state: &AppSnapshot,
) -> anyhow::Result<web_transport_quinn::Session> {
  let quic_config = tls::build_upstream_quic_client_config_with_crypto_resumption_and_revocation(
    &state.config.crypto,
    &state.config.proxy.trusted_ca_certs,
    &prepared.upstream.tls.ech,
    &state.config.quic,
    &prepared.upstream.tls.resumption,
    Some(&state.tls_resumption),
    &prepared.upstream.name,
    Some((
      &state.outbound_revocation,
      state
        .outbound_revocation
        .policy_for_upstream(&prepared.upstream),
    )),
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

#[cfg(any(test, feature = "fuzzing"))]
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
