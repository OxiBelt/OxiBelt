//! Logical-origin HTTP/3 clients and contention-safe pooled connection state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant as StdInstant;

use ::http::{Request, Response};
use anyhow::Context;
use tokio::sync::{Mutex, Notify};

use super::upstream_connection::{
  H3RequestDeadlines, WebTransportConnectionGuard, send_h3_request,
};
use super::upstream_endpoints::{AdmittedUpstream, H3EndpointRuntime, SharedConnectFailure};
use crate::circuit_breakers::CircuitBreakerRuntime;
use crate::config::{Config, HttpVersion, UpstreamConfig};
use crate::metrics::Metrics;
use crate::metrics::http3_upstream::{H3PoolEvent, H3PoolWaitOutcome, H3PoolWaitScope};
use crate::overload::{OverloadRuntime, WorkKind};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::ProxyBody;
use crate::tls;

mod connection;
use connection::{OneShotH3Connection, PooledConnectionStatus, PooledH3Connection, PooledH3Lease};
#[cfg(test)]
mod tests;

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
    circuit_breakers: Arc<CircuitBreakerRuntime>,
  ) -> anyhow::Result<Self> {
    let mut by_upstream = HashMap::new();
    for upstream in upstreams {
      if upstream.max_http_version != HttpVersion::H3 {
        continue;
      }
      let inherited_roots = config
        .proxy
        .trusted_ca_certs
        .iter()
        .chain(&upstream.extra_trusted_ca_certs)
        .cloned()
        .collect::<Vec<_>>();
      let client_config = tls::build_upstream_quic_client_config_with_policy(
        &config.crypto,
        &inherited_roots,
        &upstream.tls,
        &config.quic,
        Some(tls_resumption),
        &upstream.name,
        Some((
          outbound_revocation,
          outbound_revocation.policy_for_upstream(upstream),
        )),
      )
      .with_context(|| {
        format!(
          "failed to build upstream HTTP/3 client for {}",
          upstream.name
        )
      })?;
      let logical_origin = LogicalH3Origin::new(upstream, inherited_roots)?;
      let endpoints = Arc::new(H3EndpointRuntime::new(
        &logical_origin,
        client_config,
        config.quic.clone(),
        config.source_paths.cert_dir.clone(),
        circuit_breakers.clone(),
      )?);
      let pool = config.quic.upstream_pool.enabled.then(|| {
        Arc::new(H3PoolRuntime::new(
          config.quic.upstream_pool.max_connections_per_upstream,
          logical_origin.generation.clone(),
        ))
      });
      by_upstream.insert(
        upstream.name.clone(),
        Arc::new(UpstreamH3Pool {
          logical_origin,
          quic_config: config.quic.clone(),
          endpoints,
          pool,
        }),
      );
    }
    Ok(Self { by_upstream })
  }

  pub(super) fn for_upstream(&self, upstream_name: &str) -> Option<Arc<UpstreamH3Pool>> {
    self.by_upstream.get(upstream_name).cloned()
  }
}

#[derive(Clone, Debug)]
pub(super) struct H3ClientGeneration(Arc<()>);

impl H3ClientGeneration {
  fn new() -> Self {
    Self(Arc::new(()))
  }

  fn same_as(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.0, &other.0)
  }
}

#[derive(Clone)]
pub(super) struct LogicalH3Origin {
  pub(super) upstream_name: String,
  pub(super) scheme: String,
  pub(super) host: String,
  pub(super) port: u16,
  pub(super) server_name: String,
  pub(super) discovery_identity: String,
  security_identity: H3SecurityIdentity,
  generation: H3ClientGeneration,
}

#[derive(Clone)]
struct H3SecurityIdentity {
  upstream: UpstreamConfig,
  inherited_roots: Vec<PathBuf>,
}

impl LogicalH3Origin {
  fn new(upstream: &UpstreamConfig, inherited_roots: Vec<PathBuf>) -> anyhow::Result<Self> {
    let host = upstream
      .origin
      .host_str()
      .context("upstream HTTP/3 origin has no host")?
      .to_ascii_lowercase();
    let port = upstream
      .origin
      .port_or_known_default()
      .context("upstream HTTP/3 origin has no port")?;
    let server_name = upstream
      .tls
      .server_name
      .clone()
      .unwrap_or_else(|| host.clone())
      .to_ascii_lowercase();
    Ok(Self {
      upstream_name: upstream.name.clone(),
      scheme: upstream.origin.scheme().to_ascii_lowercase(),
      discovery_identity: format!("{}:{host}:{port}", upstream.name),
      host,
      port,
      server_name,
      security_identity: H3SecurityIdentity {
        upstream: upstream.clone(),
        inherited_roots,
      },
      generation: H3ClientGeneration::new(),
    })
  }

  fn matches(&self, upstream: &UpstreamConfig, global_roots: &[PathBuf]) -> bool {
    let Some(host) = upstream.origin.host_str() else {
      return false;
    };
    let Some(port) = upstream.origin.port_or_known_default() else {
      return false;
    };
    let server_name = upstream.tls.server_name.as_deref().unwrap_or(host);
    self.upstream_name == upstream.name
      && self.scheme.eq_ignore_ascii_case(upstream.origin.scheme())
      && self.host.eq_ignore_ascii_case(host)
      && self.port == port
      && self.server_name.eq_ignore_ascii_case(server_name)
      && self.security_identity.upstream.eq(upstream)
      && self
        .security_identity
        .inherited_roots
        .iter()
        .eq(global_roots.iter().chain(&upstream.extra_trusted_ca_certs))
  }
}

pub(super) struct UpstreamH3Pool {
  logical_origin: LogicalH3Origin,
  quic_config: crate::config::QuicConfig,
  endpoints: Arc<H3EndpointRuntime>,
  pool: Option<Arc<H3PoolRuntime>>,
}

struct H3PoolRuntime {
  max_connections: usize,
  generation: H3ClientGeneration,
  slots: Mutex<Vec<Arc<H3PoolSlot>>>,
  changed: Arc<Notify>,
  retired: AtomicBool,
}

impl H3PoolRuntime {
  fn new(max_connections: usize, generation: H3ClientGeneration) -> Self {
    Self {
      max_connections,
      generation,
      slots: Mutex::new(Vec::new()),
      changed: Arc::new(Notify::new()),
      retired: AtomicBool::new(false),
    }
  }
}

impl Drop for H3PoolRuntime {
  fn drop(&mut self) {
    self.retired.store(true, Ordering::Release);
    self.changed.notify_waiters();
  }
}

struct H3PoolSlot {
  state: Mutex<H3PoolSlotState>,
}

impl H3PoolSlot {
  fn new() -> Self {
    Self {
      state: Mutex::new(H3PoolSlotState::Empty),
    }
  }
}

enum H3PoolSlotState {
  Empty,
  Resolving(H3PoolAttempt),
  Connecting(H3PoolAttempt),
  Ready(Arc<PooledH3Connection>),
  CoolingDown {
    failure: Arc<SharedConnectFailure>,
    retry_at: tokio::time::Instant,
  },
  Draining(Arc<PooledH3Connection>),
  Retired,
}

#[derive(Clone)]
struct H3PoolAttempt {
  generation: H3ClientGeneration,
  operation: Arc<()>,
}

impl H3PoolAttempt {
  fn new(generation: H3ClientGeneration) -> Self {
    Self {
      generation,
      operation: Arc::new(()),
    }
  }

  fn same_as(&self, other: &Self) -> bool {
    self.generation.same_as(&other.generation) && Arc::ptr_eq(&self.operation, &other.operation)
  }
}

impl UpstreamH3Pool {
  pub(super) async fn forward_request(
    self: Arc<Self>,
    request: Request<ProxyBody>,
    upstream: &UpstreamConfig,
    timeouts: EffectiveTimeouts,
    global_roots: &[PathBuf],
    metrics: &Arc<Metrics>,
    overload: &Arc<OverloadRuntime>,
  ) -> anyhow::Result<Response<ProxyBody>> {
    if !self.logical_origin.matches(upstream, global_roots) {
      anyhow::bail!(
        "upstream HTTP/3 logical-origin identity changed for {}",
        upstream.name
      );
    }
    let _pending = overload.lease(WorkKind::PendingUpstreamRequests, 1);
    let uri = request.uri().clone();
    let deadlines = H3RequestDeadlines::from_timeouts(timeouts)?;
    metrics.record_http_upstream_client_request("h3", "https", "primary");

    let Some(pool) = self.pool.as_ref() else {
      metrics.record_http_upstream_client_pool_miss("h3", "https", "primary");
      let admitted = self
        .endpoints
        .resolve_and_connect_h3(deadlines.connect, metrics)
        .await
        .map_err(|failure| failure.into_error())?;
      metrics.record_http_upstream_client_connection_created("h3", "https", "primary");
      let send_request = admitted.connected.send_request.clone();
      let guard = OneShotH3Connection {
        _connected: admitted.connected,
        _connection_admission: admitted.admission,
      };
      let response =
        send_h3_request(send_request, request, &uri, timeouts, deadlines.request).await?;
      let (parts, body) = response.into_parts();
      let body = crate::proxy::http::body::with_drop_guard(
        body,
        Arc::new(std::sync::Mutex::new(Some(guard))),
      );
      return Ok(Response::from_parts(parts, body));
    };

    let lease = self
      .clone()
      .pooled_lease(pool, upstream, deadlines, metrics.clone())
      .await?;
    let entry = Arc::clone(&lease.connection);
    match send_h3_request(
      entry.connected.send_request.clone(),
      request,
      &uri,
      timeouts,
      deadlines.request,
    )
    .await
    {
      Ok(response) => {
        let (parts, body) = response.into_parts();
        let body = crate::proxy::http::body::with_drop_guard(body, lease);
        Ok(Response::from_parts(parts, body))
      }
      Err(error) => {
        let connection_closed = entry.connected.connection.close_reason().is_some();
        let slot = Arc::clone(&lease.slot);
        drop(lease);
        if connection_closed {
          self
            .invalidate_connection(pool, &slot, &entry, metrics)
            .await;
        }
        // Never select another address or connection after send_h3_request has
        // crossed the request-observability boundary.
        Err(error)
      }
    }
  }

  pub(super) async fn connect_webtransport(
    &self,
    prepared: &crate::proxy::http::PreparedWebTransport,
    global_roots: &[PathBuf],
    metrics: &Arc<Metrics>,
  ) -> anyhow::Result<(
    super::webtransport_bridge::UpstreamWebTransportSession,
    WebTransportConnectionGuard,
  )> {
    if !self
      .logical_origin
      .matches(&prepared.upstream, global_roots)
    {
      anyhow::bail!(
        "upstream WebTransport logical-origin identity changed for {}",
        prepared.upstream.name
      );
    }
    let deadlines = H3RequestDeadlines::from_timeouts(prepared.timeouts)?;
    let admitted = self
      .endpoints
      .resolve_and_connect_quinn(deadlines.connect, metrics)
      .await
      .map_err(|failure| failure.into_error())?;
    let AdmittedUpstream {
      connected,
      admission,
    } = admitted;
    let (endpoint, connection) = connected.into_parts()?;
    // Only the QUIC/H3 transport candidates race. A single winner sends the
    // WebTransport CONNECT so long-lived sessions are never duplicated.
    let session = tokio::time::timeout_at(
      deadlines.request,
      super::webtransport_bridge::UpstreamWebTransportSession::connect(
        connection,
        prepared.target_url.clone(),
        prepared.headers.clone(),
        prepared.protocols.clone(),
      ),
    )
    .await
    .context("upstream WebTransport CONNECT timed out")?
    .context("upstream WebTransport CONNECT failed")?;
    Ok((
      session,
      WebTransportConnectionGuard::new(endpoint, admission),
    ))
  }

  async fn pooled_lease(
    self: Arc<Self>,
    pool: &Arc<H3PoolRuntime>,
    upstream: &UpstreamConfig,
    deadlines: H3RequestDeadlines,
    metrics: Arc<Metrics>,
  ) -> anyhow::Result<PooledH3Lease> {
    let mut coalesced_recorded = false;
    let mut saturation_recorded = false;
    loop {
      if tokio::time::Instant::now() >= deadlines.request {
        anyhow::bail!("upstream HTTP/3 pool wait timed out");
      }
      if pool.retired.load(Ordering::Acquire) {
        metrics.record_h3_pool_event(H3PoolEvent::Shutdown);
        anyhow::bail!("upstream HTTP/3 pool is retired");
      }

      let changed = pool.changed.notified();
      tokio::pin!(changed);
      let _ = changed.as_mut().enable();
      let map_wait_started = StdInstant::now();
      let slots = pool.slots.lock().await.clone();
      metrics.observe_h3_pool_wait(
        H3PoolWaitScope::MapLock,
        H3PoolWaitOutcome::Immediate,
        map_wait_started.elapsed(),
      );

      let mut empty_slot = None;
      let mut pending = false;
      let mut cooling_failure = None;
      let mut retired_slots = Vec::new();
      for slot in &slots {
        let state_wait_started = StdInstant::now();
        let mut state = slot.state.lock().await;
        metrics.observe_h3_pool_wait(
          H3PoolWaitScope::SlotState,
          H3PoolWaitOutcome::Immediate,
          state_wait_started.elapsed(),
        );

        if let H3PoolSlotState::Ready(connection) = &*state {
          let connection = Arc::clone(connection);
          match connection.status(upstream, &self.quic_config) {
            PooledConnectionStatus::Ready => {
              let lease = PooledH3Connection::reserve(
                &connection,
                Arc::clone(slot),
                Arc::clone(&pool.changed),
              );
              drop(state);
              metrics.record_h3_pool_event(H3PoolEvent::Reuse);
              self
                .endpoints
                .refresh_if_expired(deadlines.connect, metrics.clone());
              return Ok(lease);
            }
            status => {
              let event = match status {
                PooledConnectionStatus::Closed => H3PoolEvent::Closed,
                PooledConnectionStatus::Expired => H3PoolEvent::Expired,
                PooledConnectionStatus::Idle => H3PoolEvent::Idle,
                PooledConnectionStatus::Ready => continue,
              };
              metrics.record_h3_pool_event(event);
              if connection.streams.is_active() {
                *state = H3PoolSlotState::Draining(connection);
              } else {
                *state = H3PoolSlotState::Retired;
                retired_slots.push(Arc::clone(slot));
              }
            }
          }
        }

        if let H3PoolSlotState::Draining(connection) = &*state
          && !connection.streams.is_active()
        {
          *state = H3PoolSlotState::Retired;
          retired_slots.push(Arc::clone(slot));
        }

        if let H3PoolSlotState::CoolingDown { retry_at, .. } = &*state
          && *retry_at <= tokio::time::Instant::now()
        {
          *state = H3PoolSlotState::Empty;
        }

        match &*state {
          H3PoolSlotState::Empty => {
            empty_slot.get_or_insert_with(|| Arc::clone(slot));
          }
          H3PoolSlotState::Resolving(_) | H3PoolSlotState::Connecting(_) => pending = true,
          H3PoolSlotState::CoolingDown { failure, .. } => {
            cooling_failure.get_or_insert_with(|| Arc::clone(failure));
          }
          H3PoolSlotState::Retired => retired_slots.push(Arc::clone(slot)),
          H3PoolSlotState::Ready(_) | H3PoolSlotState::Draining(_) => {}
        }
      }

      if !retired_slots.is_empty() {
        let map_wait_started = StdInstant::now();
        let mut current = pool.slots.lock().await;
        metrics.observe_h3_pool_wait(
          H3PoolWaitScope::MapLock,
          H3PoolWaitOutcome::Immediate,
          map_wait_started.elapsed(),
        );
        current.retain(|candidate| {
          !retired_slots
            .iter()
            .any(|retired| Arc::ptr_eq(candidate, retired))
        });
        pool.changed.notify_waiters();
        continue;
      }

      if let Some(slot) = empty_slot {
        if self
          .clone()
          .start_pool_attempt(pool, slot, deadlines, metrics.clone())
          .await
        {
          continue;
        }
      } else if !pending && slots.len() < pool.max_connections {
        let map_wait_started = StdInstant::now();
        let mut current = pool.slots.lock().await;
        metrics.observe_h3_pool_wait(
          H3PoolWaitScope::MapLock,
          H3PoolWaitOutcome::Immediate,
          map_wait_started.elapsed(),
        );
        if current.len() < pool.max_connections {
          current.push(Arc::new(H3PoolSlot::new()));
          pool.changed.notify_waiters();
        }
        continue;
      }

      if pending && !coalesced_recorded {
        metrics.record_h3_pool_event(H3PoolEvent::ConnectCoalesced);
        coalesced_recorded = true;
      }
      if let Some(failure) = cooling_failure
        && !pending
      {
        return Err(failure.to_error());
      }
      if !pending && !saturation_recorded {
        metrics.record_h3_pool_event(H3PoolEvent::Saturated);
        saturation_recorded = true;
      }

      let wait_started = StdInstant::now();
      match tokio::time::timeout_at(deadlines.request, &mut changed).await {
        Ok(()) => metrics.observe_h3_pool_wait(
          H3PoolWaitScope::SlotState,
          H3PoolWaitOutcome::Ready,
          wait_started.elapsed(),
        ),
        Err(_) => {
          metrics.observe_h3_pool_wait(
            H3PoolWaitScope::SlotState,
            H3PoolWaitOutcome::Timeout,
            wait_started.elapsed(),
          );
          anyhow::bail!("upstream HTTP/3 pool wait timed out");
        }
      }
    }
  }

  async fn start_pool_attempt(
    self: Arc<Self>,
    pool: &Arc<H3PoolRuntime>,
    slot: Arc<H3PoolSlot>,
    deadlines: H3RequestDeadlines,
    metrics: Arc<Metrics>,
  ) -> bool {
    let attempt = H3PoolAttempt::new(pool.generation.clone());
    {
      let mut state = slot.state.lock().await;
      if !matches!(*state, H3PoolSlotState::Empty) {
        return false;
      }
      *state = H3PoolSlotState::Resolving(attempt.clone());
    }
    metrics.record_h3_pool_event(H3PoolEvent::ConnectLeader);
    metrics.record_http_upstream_client_pool_miss("h3", "https", "primary");
    pool.changed.notify_waiters();
    let pool = Arc::clone(pool);
    tokio::spawn(async move {
      self
        .run_pool_attempt(pool, slot, attempt, deadlines, metrics)
        .await;
    });
    true
  }

  async fn run_pool_attempt(
    self: Arc<Self>,
    pool: Arc<H3PoolRuntime>,
    slot: Arc<H3PoolSlot>,
    attempt: H3PoolAttempt,
    deadlines: H3RequestDeadlines,
    metrics: Arc<Metrics>,
  ) {
    let resolved = match self.endpoints.resolve(deadlines.connect, &metrics).await {
      Ok(resolved) => resolved,
      Err(failure) => {
        self
          .finish_pool_attempt_failure(&pool, &slot, &attempt, failure, &metrics)
          .await;
        return;
      }
    };
    if !self
      .publish_connecting(&pool, &slot, &attempt, &metrics)
      .await
    {
      return;
    }
    let connection_wait_started = StdInstant::now();
    let result = self
      .endpoints
      .connect_h3(resolved, deadlines.connect, &metrics)
      .await;
    metrics.observe_h3_pool_wait(
      H3PoolWaitScope::Connection,
      if result.is_ok() {
        H3PoolWaitOutcome::Ready
      } else {
        H3PoolWaitOutcome::Error
      },
      connection_wait_started.elapsed(),
    );
    match result {
      Ok(AdmittedUpstream {
        connected,
        admission,
      }) => {
        let entry = Arc::new(PooledH3Connection::new(connected, admission));
        let mut state = slot.state.lock().await;
        let current = matches!(
          &*state,
          H3PoolSlotState::Connecting(current) if current.same_as(&attempt)
        ) && pool.generation.same_as(&attempt.generation)
          && !pool.retired.load(Ordering::Acquire);
        if current {
          *state = H3PoolSlotState::Ready(entry);
          metrics.record_h3_pool_event(H3PoolEvent::Created);
          metrics.record_http_upstream_client_connection_created("h3", "https", "primary");
        } else {
          metrics.record_h3_pool_event(H3PoolEvent::StaleGenerationDiscard);
        }
      }
      Err(failure) => {
        self
          .finish_pool_attempt_failure(&pool, &slot, &attempt, failure, &metrics)
          .await;
      }
    }
    pool.changed.notify_waiters();
  }

  async fn publish_connecting(
    &self,
    pool: &H3PoolRuntime,
    slot: &H3PoolSlot,
    attempt: &H3PoolAttempt,
    metrics: &Metrics,
  ) -> bool {
    let mut state = slot.state.lock().await;
    let current = matches!(
      &*state,
      H3PoolSlotState::Resolving(current) if current.same_as(attempt)
    ) && pool.generation.same_as(&attempt.generation)
      && !pool.retired.load(Ordering::Acquire);
    if current {
      *state = H3PoolSlotState::Connecting(attempt.clone());
      pool.changed.notify_waiters();
      true
    } else {
      metrics.record_h3_pool_event(H3PoolEvent::StaleGenerationDiscard);
      false
    }
  }

  async fn finish_pool_attempt_failure(
    &self,
    pool: &H3PoolRuntime,
    slot: &H3PoolSlot,
    attempt: &H3PoolAttempt,
    failure: SharedConnectFailure,
    metrics: &Metrics,
  ) {
    let mut state = slot.state.lock().await;
    let current = match &*state {
      H3PoolSlotState::Resolving(current) | H3PoolSlotState::Connecting(current) => {
        current.same_as(attempt)
      }
      _ => false,
    } && pool.generation.same_as(&attempt.generation)
      && !pool.retired.load(Ordering::Acquire);
    if current {
      let retry_at = failure.retry_at();
      *state = H3PoolSlotState::CoolingDown {
        failure: Arc::new(failure),
        retry_at,
      };
      metrics.record_h3_pool_event(H3PoolEvent::ConnectError);
    } else {
      metrics.record_h3_pool_event(H3PoolEvent::StaleGenerationDiscard);
    }
    pool.changed.notify_waiters();
  }

  async fn invalidate_connection(
    &self,
    pool: &H3PoolRuntime,
    slot: &H3PoolSlot,
    target: &Arc<PooledH3Connection>,
    metrics: &Metrics,
  ) {
    let mut state = slot.state.lock().await;
    if let H3PoolSlotState::Ready(connection) = &*state
      && Arc::ptr_eq(connection, target)
    {
      *state = if target.streams.is_active() {
        H3PoolSlotState::Draining(Arc::clone(target))
      } else {
        H3PoolSlotState::Retired
      };
      metrics.record_h3_pool_event(H3PoolEvent::Closed);
      pool.changed.notify_waiters();
    }
  }
}
