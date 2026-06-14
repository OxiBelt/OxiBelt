//! Listener supervision and control-plane orchestration for the running proxy.
//! This module binds transports together without owning protocol-specific policy.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::{Response, StatusCode};
use anyhow::{Context, bail};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ring::digest;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::admin_audit::AdminAuditHandle;
use crate::config::{AdminTransportMode, Config, ConnectionLimitIdentityMode, RuntimeOverrides};
use crate::identity::Cidr;
use crate::lifecycle::{ConnectionDrain, TaskRegistry, wait_for_listener_or_data_plane_drain};
use crate::limits::{ConnectionLimitContext, ConnectionPermit};
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
use crate::pool_health;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::proxy::{http, http3};
use crate::proxy_protocol;
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::{BoundStreamListener, StreamListenerTask};
use crate::tcp_hop;
use crate::telemetry::TelemetryRuntime;
use crate::turn::{BoundTurnListener, TurnListenerTask};
use crate::waf::{WafTlsMetadata, WafTransportMetadataInput};
mod admin;
mod admin_audit_endpoint;
mod admin_audit_gate;
mod admin_auth;
mod admin_body;
mod admin_config_diff;
mod admin_control;
mod admin_diagnostics;
mod admin_error;
mod admin_h3;
mod admin_ipm;
mod admin_ipm_list;
mod admin_ipm_simulation;
#[cfg(test)]
mod admin_ipm_simulation_security_tests;
mod admin_metadata;
mod admin_operations;
#[cfg(test)]
mod admin_operations_tests;
mod admin_ops;
mod admin_person_proof;
#[cfg(test)]
mod admin_person_proof_scope_tests;
mod admin_resource;
#[cfg(test)]
mod admin_resource_scope_tests;
mod admin_rulepacks;
#[cfg(test)]
mod admin_stream_pool_scope_tests;
mod admin_stream_pools;
mod admin_upstream_pools;
mod connection_errors;
mod file_sync_path;
mod plain_http;
#[cfg(test)]
mod reload_tests;
use admin_auth::{AdminActor, AdminAuthorization, admin_actor, admin_request_context};
use admin_control::{AdminControlCommand, AdminControlHandle, RollbackSnapshot};
use admin_operations::AdminOperationRuntime;
use admin_stream_pools::admin_stream_pools_response;
use admin_upstream_pools::admin_upstream_pools_response;

pub const ADMIN_CAPABILITY_FEATURE_KEYS: &[&str] = &[
  "config_load",
  "file_sync",
  "dynamic_policy",
  "ipm_store",
  "waf_devtools",
  "runtime_introspection",
  "cache_admin",
  "person_proof_admin",
  "upstream_pool_runtime_control",
  "stream_pool_runtime_control",
  "admin_operations",
  "admin_http3",
  "admin_operation_webtransport",
  "admin_audit",
];
pub const ADMIN_OPERATION_KIND_WIRE_VALUES: &[&str] = &[
  "cache_warm",
  "oxirule_replay",
  "diagnostics_preflight",
  "support_bundle",
  "dynamic_policy_import",
  "webtransport_snapshot",
  "webtransport_drain",
];
pub const ADMIN_OPERATION_STATE_WIRE_VALUES: &[&str] = &[
  "queued",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "expired",
];

const TCP_TLS_FINGERPRINT_SCHEME: &str = "rustls-tcp-negotiated-v2";
const QUIC_TLS_FINGERPRINT_SCHEME: &str = "quinn-rustls-quic-v2";
pub async fn serve(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  let (error_tx, mut error_rx) = mpsc::unbounded_channel();
  let effective_config = config_path
    .as_ref()
    .and_then(|path| Config::load_effective_toml_redacted(path).ok())
    .and_then(|value| toml::to_string_pretty(&value).ok());
  let (admin_control, mut admin_control_rx) = AdminControlHandle::new(effective_config);
  let admin_operations =
    AdminOperationRuntime::new(state.snapshot().config.admin.operations.clone());
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx.clone(),
    admin_control.clone(),
    admin_operations.clone(),
  )
  .await?;
  let _ops = OpsTasks::start(state.clone(), error_tx.clone()).await?;
  let reload = if state.snapshot().config.runtime.hot_reload.mode.enabled() {
    match config_path {
      Some(config_path) => Some(ReloadManager::new(
        config_path,
        runtime_overrides.clone(),
        state.snapshot().as_ref(),
      )?),
      None => {
        warn!("hot reload is enabled but no configuration path is available; reload disabled");
        None
      }
    }
  } else {
    None
  };
  drop(error_tx);
  if let Some(reload) = reload {
    serve_with_reload(
      state,
      &mut listeners,
      &mut error_rx,
      &mut admin_control_rx,
      admin_control,
      runtime_overrides,
      reload,
    )
    .await
  } else {
    serve_until_shutdown(
      state,
      &mut listeners,
      &mut error_rx,
      &mut admin_control_rx,
      admin_control,
      runtime_overrides,
    )
    .await
  }
}

struct OpsTasks {
  shutdown: Vec<watch::Sender<bool>>,
  tasks: Vec<JoinHandle<()>>,
}

impl OpsTasks {
  async fn start(
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    let mut shutdown = Vec::new();
    let mut tasks = Vec::new();
    if snapshot.config.metrics.enabled {
      let listener = TcpListener::bind(snapshot.config.metrics.bind)
        .await
        .with_context(|| {
          format!(
            "failed to bind metrics listener to {}",
            snapshot.config.metrics.bind
          )
        })?;
      let (tx, rx) = watch::channel(false);
      shutdown.push(tx);
      let task_state = state.clone();
      let task_error = error_tx.clone();
      tasks.push(tokio::spawn(async move {
        if let Err(error) = serve_ops_listener(listener, task_state, rx, OpsKind::Metrics).await {
          let _ = task_error.send(error.context("metrics listener failed"));
        }
      }));
    }
    if snapshot.config.health.enabled {
      let listener = TcpListener::bind(snapshot.config.health.bind)
        .await
        .with_context(|| {
          format!(
            "failed to bind health listener to {}",
            snapshot.config.health.bind
          )
        })?;
      let (tx, rx) = watch::channel(false);
      shutdown.push(tx);
      let task_state = state.clone();
      let task_error = error_tx.clone();
      tasks.push(tokio::spawn(async move {
        if let Err(error) = serve_ops_listener(listener, task_state, rx, OpsKind::Health).await {
          let _ = task_error.send(error.context("health listener failed"));
        }
      }));
    }
    let (tx, rx) = watch::channel(false);
    shutdown.push(tx);
    let task_state = state.clone();
    tasks.push(tokio::spawn(async move {
      pool_health::run_pool_health_checks(task_state, rx).await;
    }));
    let (tx, rx) = watch::channel(false);
    shutdown.push(tx);
    let task_state = state;
    tasks.push(tokio::spawn(async move {
      crate::upstream_discovery::run_dynamic_upstream_discovery(task_state, rx).await;
    }));
    Ok(Self { shutdown, tasks })
  }
}

impl Drop for OpsTasks {
  fn drop(&mut self) {
    for tx in &self.shutdown {
      let _ = tx.send(true);
    }
    for task in &self.tasks {
      task.abort();
    }
  }
}

#[derive(Clone, Copy)]
enum OpsKind {
  Metrics,
  Health,
}

async fn serve_ops_listener(
  listener: TcpListener,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  kind: OpsKind,
) -> anyhow::Result<()> {
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          return Ok(());
        }
      }
      accepted = listener.accept() => {
        let (stream, peer_addr) = match accepted {
          Ok(value) => value,
          Err(error) => {
            warn!(error = %error, "failed to accept ops connection");
            continue;
          }
        };
        crate::tcp_socket::enable_tcp_nodelay(&stream, peer_addr, "ops listener");
        let state = state.clone();
        tokio::spawn(async move {
          let service = service_fn(move |request: hyper::Request<Incoming>| {
            let state = state.clone();
            async move { Ok::<_, Infallible>(ops_response(request, state, kind)) }
          });
          if let Err(error) = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
          {
            warn!(peer = %peer_addr, error = %error, "ops connection failed");
          }
        });
      }
    }
  }
}

fn ops_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  kind: OpsKind,
) -> Response<ProxyBody> {
  match kind {
    OpsKind::Metrics => {
      let snapshot = state.snapshot();
      let body = snapshot.metrics.prometheus(
        &snapshot.config.metrics,
        snapshot.cache.stats(),
        snapshot.tls_resumption.server_session_storage_stats(),
      );
      text_response(StatusCode::OK, &body)
    }
    OpsKind::Health => {
      let snapshot = state.snapshot();
      let path = request.uri().path();
      if path == snapshot.config.health.ready_path {
        if snapshot.lifecycle.is_draining() {
          text_response(StatusCode::SERVICE_UNAVAILABLE, "draining")
        } else {
          text_response(StatusCode::OK, "ready")
        }
      } else if path == snapshot.config.health.live_path {
        text_response(StatusCode::OK, "live")
      } else {
        text_response(StatusCode::NOT_FOUND, "not found")
      }
    }
  }
}

async fn serve_admin_listener(
  listener: TcpListener,
  configured_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read admin listener address")?;
  info!(bind = %bind, "admin listener started");
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(bind = %bind, "admin listener stopped");
        }
        return Ok(());
      }
      accepted = listener.accept() => {
        let (stream, peer_addr) = match accepted {
          Ok(value) => value,
          Err(error) => {
            warn!(error = %error, "failed to accept admin connection");
            continue;
          }
        };
        crate::tcp_socket::enable_tcp_nodelay(&stream, peer_addr, "admin listener");
        let state = state.clone();
        let admin_control = admin_control.clone();
        let admin_operations = admin_operations.clone();
        tokio::spawn(async move {
          if let Err(error) =
            handle_admin_connection(
              stream,
              peer_addr,
              configured_bind,
              state,
              admin_control,
              admin_operations,
            )
            .await
          {
            warn!(peer = %peer_addr, error = %error, "admin connection failed");
          }
        });
      }
    }
  }
}

async fn handle_admin_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  if !admin_listener_current(&snapshot, listener_bind) {
    bail!("admin listener is no longer current");
  }
  let plaintext_allowed = admin_plaintext_allowed(&snapshot, peer_addr);
  let transport = snapshot.config.admin.transport;
  drop(snapshot);
  match transport {
    AdminTransportMode::Tls => {
      handle_admin_tls_connection(
        stream,
        peer_addr,
        listener_bind,
        state,
        admin_control,
        admin_operations,
      )
      .await
    }
    AdminTransportMode::Plaintext => {
      handle_admin_plaintext_connection(
        stream,
        peer_addr,
        listener_bind,
        state,
        admin_control,
        admin_operations,
      )
      .await
    }
    AdminTransportMode::PlaintextAllowlist if plaintext_allowed => {
      handle_admin_plaintext_connection(
        stream,
        peer_addr,
        listener_bind,
        state,
        admin_control,
        admin_operations,
      )
      .await
    }
    AdminTransportMode::PlaintextAllowlist => {
      bail!("admin plaintext connection from {peer_addr} is not allowlisted");
    }
    AdminTransportMode::Auto => {
      if plaintext_allowed && !tcp_stream_starts_with_tls(&stream).await {
        handle_admin_plaintext_connection(
          stream,
          peer_addr,
          listener_bind,
          state,
          admin_control,
          admin_operations,
        )
        .await
      } else {
        handle_admin_tls_connection(
          stream,
          peer_addr,
          listener_bind,
          state,
          admin_control,
          admin_operations,
        )
        .await
      }
    }
  }
}

fn admin_listener_current(snapshot: &AppSnapshot, listener_bind: SocketAddr) -> bool {
  snapshot.config.admin.enabled && snapshot.config.admin.bind == listener_bind
}

async fn tcp_stream_starts_with_tls(stream: &TcpStream) -> bool {
  let mut byte = [0_u8; 1];
  matches!(stream.peek(&mut byte).await, Ok(1..) if byte[0] == 22)
}

fn admin_plaintext_allowed(snapshot: &AppSnapshot, peer_addr: SocketAddr) -> bool {
  snapshot
    .config
    .admin
    .plaintext_allowed_source_cidrs
    .iter()
    .filter_map(|raw| Cidr::parse(raw).ok())
    .any(|cidr| cidr.contains(peer_addr.ip()))
}

async fn handle_admin_tls_connection(
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
  serve_admin_http1(
    TokioIo::new(tls_stream),
    peer_addr,
    listener_bind,
    state,
    admin_control,
    admin_operations,
    "https",
  )
  .await
}

async fn handle_admin_plaintext_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
) -> anyhow::Result<()> {
  serve_admin_http1(
    TokioIo::new(stream),
    peer_addr,
    listener_bind,
    state,
    admin_control,
    admin_operations,
    "http",
  )
  .await
}

async fn serve_admin_http1<I>(
  io: TokioIo<I>,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  scheme: &'static str,
) -> anyhow::Result<()>
where
  I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
  let snapshot = state.snapshot();
  let header_timeout_ms = snapshot.config.limits.client_header_timeout_ms;
  let max_headers = snapshot.config.limits.max_headers;
  let max_total_header_bytes = snapshot.config.limits.max_total_header_bytes.max(8192);
  drop(snapshot);

  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    let admin_control = admin_control.clone();
    let admin_operations = admin_operations.clone();
    async move {
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
  builder
    .serve_connection(io, service)
    .with_upgrades()
    .await
    .map_err(|error| anyhow::anyhow!(error))
}

async fn admin_response(
  mut request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  scheme: &'static str,
) -> Response<ProxyBody> {
  let (audit, audit_reservation) =
    match admin_audit_gate::reserve_or_reject(&mut request, &state, peer_addr, scheme) {
      Ok(reservation) => reservation,
      Err(response) => return *response,
    };
  let response = admin_error::finalize_response(
    admin_response_inner(
      request,
      state.clone(),
      admin_control,
      admin_operations,
      peer_addr,
      listener_bind,
      scheme,
    )
    .await,
    &audit,
  )
  .await;
  let event = audit.finish(response.status());
  audit_reservation.commit(event);
  response
}

async fn admin_response_inner(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  scheme: &'static str,
) -> Response<ProxyBody> {
  let snapshot = state.snapshot();
  if !admin_listener_current(&snapshot, listener_bind) {
    return text_response(StatusCode::NOT_FOUND, "not found");
  }
  let method = request.method().clone();
  let uri = request.uri().clone();
  let query = uri.query().unwrap_or_default();
  let params = url::form_urlencoded::parse(query.as_bytes())
    .into_owned()
    .collect::<std::collections::HashMap<_, _>>();
  let path = uri.path().to_string();
  let admin_context = admin_request_context(&request, peer_addr);
  let audit = AdminAuditHandle::from_request(&request);
  let actor = admin_actor(&request, &snapshot.config, &snapshot.ipm).await;

  if path == "/cache/purge" || path == "/cache/purge-prefix" || path == "/cache/purge-tag" {
    if method != ::http::Method::POST {
      return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let signed_actor = if actor.is_none() {
      match admin::signed_cache_purge_actor(&request, snapshot.as_ref(), &method) {
        Ok(actor) => Some(actor),
        Err(error) => {
          warn!(error = %error, "rejected unsigned admin cache purge request");
          return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
      }
    } else {
      None
    };
    let actor = match actor.or(signed_actor) {
      Some(actor) => actor,
      None => return text_response(StatusCode::UNAUTHORIZED, "unauthorized"),
    };
    if let Some(audit) = &audit {
      audit.set_actor(&actor.name, &actor.principal, &actor.subject, &actor.groups);
    }
    let authorization = if let Some(audit) = audit.clone() {
      AdminAuthorization::new_with_audit(&actor, &snapshot.ipm, &admin_context, audit)
    } else {
      AdminAuthorization::new(&actor, &snapshot.ipm, &admin_context)
    };
    let response =
      admin::cache_purge_response(&snapshot, &params, &path, scheme, peer_addr, &authorization);
    return response;
  }

  let Some(actor) = actor else {
    return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
  };
  if let Some(audit) = &audit {
    audit.set_actor(&actor.name, &actor.principal, &actor.subject, &actor.groups);
  }
  let authorization = if let Some(audit) = audit.clone() {
    AdminAuthorization::new_with_audit(&actor, &snapshot.ipm, &admin_context, audit)
  } else {
    AdminAuthorization::new(&actor, &snapshot.ipm, &admin_context)
  };

  if path == "/admin/v1/audit" {
    return admin_audit_endpoint::admin_audit_response(
      snapshot.as_ref(),
      &authorization,
      &method,
      uri.query(),
    )
    .await;
  }

  if let Some(response) =
    admin_metadata::admin_metadata_response(snapshot.as_ref(), &authorization, &method, &path)
  {
    return response;
  }

  if path == "/admin/v1/operations" || path.starts_with("/admin/v1/operations/") {
    return admin_operations::admin_operations_response(
      request,
      admin_operations::AdminOperationRouteContext {
        state: state.clone(),
        admin_control: admin_control.clone(),
        operations: admin_operations.clone(),
        peer_addr,
      },
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/config/status"
    || path == "/admin/v1/config/effective"
    || path == "/admin/v1/config/validate"
    || path == "/admin/v1/config/diff"
    || path == "/admin/v1/config/load"
    || path == "/admin/v1/config/rollback"
  {
    return admin_ops::admin_config_response(
      request,
      state.clone(),
      admin_control.clone(),
      &authorization,
      &method,
      &path,
    )
    .await;
  }

  if let Some(response) = admin_ops::admin_tls_response(
    &request,
    snapshot.as_ref(),
    admin_control.clone(),
    &authorization,
    &method,
    &path,
  )
  .await
  {
    return response;
  }

  if path == "/admin/v1/files/sync" {
    return admin_ops::admin_files_response(
      request,
      admin_control.clone(),
      &authorization,
      &method,
      &path,
    )
    .await;
  }
  if path == "/admin/v1/cache/key-explain" {
    return admin::cache_key_explain_response(request, snapshot.as_ref(), &authorization, &method)
      .await;
  }
  if path == "/admin/v1/cache/warm" {
    return admin::cache_warm_response(
      request,
      state.clone(),
      admin_operations.clone(),
      &authorization,
      &method,
      peer_addr,
    )
    .await;
  }
  if path == "/admin/v1/cache/purge" {
    return admin::cache_purge_json_response(
      request,
      snapshot.as_ref(),
      &authorization,
      &method,
      scheme,
      peer_addr,
    )
    .await;
  }

  if path.starts_with("/admin/v1/waf/person-proof") {
    return admin_person_proof::admin_person_proof_response(
      request,
      snapshot.as_ref(),
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path.starts_with("/admin/v1/waf/oxirule/") {
    return admin_ops::admin_waf_devtools_response(
      request,
      snapshot.as_ref(),
      admin_operations.clone(),
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if let Some(response) =
    admin_ops::admin_waf_response(snapshot.as_ref(), &authorization, &method, &path)
  {
    return response;
  }
  if let Some(response) =
    admin_ops::admin_lifecycle_response(snapshot.as_ref(), &authorization, &method, &path)
  {
    return response;
  }
  if path == "/admin/v1/diagnostics/preflight"
    || path == "/admin/v1/diagnostics/support-bundle"
    || path == "/admin/v1/runtime/snapshot"
    || path == "/admin/v1/runtime/introspection"
  {
    return admin_diagnostics::admin_diagnostics_response(
      request,
      state.clone(),
      admin_control.clone(),
      admin_operations.clone(),
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }
  let ipm_path = path.starts_with("/admin/v1/ipm/");
  let dynamic_policy_path = path == "/admin/v1/dynamic-policies"
    || path == "/admin/v1/dynamic-policies/export"
    || path == "/admin/v1/dynamic-policies/import"
    || path.starts_with("/admin/v1/dynamic-policies/");
  if ipm_path || dynamic_policy_path {
    let response = if ipm_path {
      admin_ipm::ipm_response(request, state.clone(), &authorization, &method, &path).await
    } else {
      admin::dynamic_policy_response(
        request,
        state.clone(),
        admin_operations.clone(),
        &authorization,
        &method,
        &path,
      )
      .await
    };
    return response.unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/upstream-pools"
    || path == "/admin/v1/upstream-pools/status"
    || path.starts_with("/admin/v1/upstream-pools/")
  {
    return admin_upstream_pools_response(
      request,
      state,
      snapshot.as_ref(),
      peer_addr,
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  if path == "/admin/v1/stream-pools"
    || path == "/admin/v1/stream-pools/status"
    || path.starts_with("/admin/v1/stream-pools/")
  {
    return admin_stream_pools_response(
      request,
      state,
      snapshot.as_ref(),
      peer_addr,
      &authorization,
      &method,
      &path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }

  text_response(StatusCode::NOT_FOUND, "not found")
}

#[derive(Debug, Clone, Copy)]
enum AdminAuditOutcome {
  Applied,
  Rejected,
}

impl AdminAuditOutcome {
  fn as_str(self) -> &'static str {
    match self {
      Self::Applied => "applied",
      Self::Rejected => "rejected",
    }
  }
}

fn admin_audit(
  peer_addr: SocketAddr,
  actor: &AdminActor,
  operation: &'static str,
  pool: Option<&str>,
  server: Option<&str>,
  outcome: AdminAuditOutcome,
  error: Option<&str>,
) {
  info!(
    event = "oxibelt.admin.audit",
    peer = %peer_addr,
    actor = %actor.name,
    principal = %actor.principal,
    groups = ?actor.groups,
    operation,
    pool,
    server,
    outcome = outcome.as_str(),
    error,
    "admin operation audit"
  );
}

async fn serve_until_shutdown(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  admin_control_rx: &mut mpsc::UnboundedReceiver<AdminControlCommand>,
  admin_control: AdminControlHandle,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  let mut rollback: Option<RollbackSnapshot> = None;
  loop {
    tokio::select! {
      result = shutdown_signal() => {
          result?;
          return graceful_process_shutdown(&state, listeners).await;
      }
      Some(error) = error_rx.recv() => return Err(error),
      Some(command) = admin_control_rx.recv() => {
        admin_control::handle_admin_control_command(
          command,
          &state,
          listeners,
          &admin_control,
          &runtime_overrides,
          &mut rollback,
        ).await;
      }
    }
  }
}

async fn serve_with_reload(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  admin_control_rx: &mut mpsc::UnboundedReceiver<AdminControlCommand>,
  admin_control: AdminControlHandle,
  runtime_overrides: RuntimeOverrides,
  mut reload: ReloadManager,
) -> anyhow::Result<()> {
  #[cfg(unix)]
  let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    .context("failed to install SIGHUP listener")?;

  let mut rollback: Option<RollbackSnapshot> = None;
  loop {
    let poll_sleep = tokio::time::sleep(reload.poll_interval());
    tokio::pin!(poll_sleep);
    tokio::select! {
        result = shutdown_signal() => {
            result?;
            return graceful_process_shutdown(&state, listeners).await;
        }
        Some(error) = error_rx.recv() => return Err(error),
        Some(command) = admin_control_rx.recv() => {
            admin_control::handle_admin_control_command(
              command,
              &state,
              listeners,
              &admin_control,
              &runtime_overrides,
              &mut rollback,
            ).await;
        }
        _ = &mut poll_sleep => {
            reload.reload_if_changed(ReloadTrigger::Poll, &state, listeners).await;
        }
        _ = hup.recv() => {
            reload.reload_if_changed(ReloadTrigger::Signal, &state, listeners).await;
        }
    }
  }
}

async fn shutdown_signal() -> anyhow::Result<()> {
  #[cfg(unix)]
  {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
      .context("failed to install SIGTERM listener")?;
    tokio::select! {
      result = tokio::signal::ctrl_c() => {
        result.context("failed to wait for ctrl_c signal")?;
      }
      _ = term.recv() => {}
    }
  }
  #[cfg(not(unix))]
  {
    tokio::signal::ctrl_c()
      .await
      .context("failed to wait for ctrl_c signal")?;
  }
  info!("shutdown signal received");
  Ok(())
}

async fn graceful_process_shutdown(
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  snapshot.lifecycle.start_shutdown();
  let shutdown_delay = Duration::from_millis(snapshot.config.runtime.drain.shutdown_delay_ms);
  if !shutdown_delay.is_zero() {
    tokio::time::sleep(shutdown_delay).await;
  }
  listeners.shutdown(snapshot.as_ref()).await;
  Ok(())
}

pub(crate) struct ListenerSupervisor {
  tcp: Option<TcpListenerTask>,
  http: Option<TcpListenerTask>,
  http3: Option<Http3ListenerTask>,
  admin: Option<AdminListenerTask>,
  admin_h3: Option<admin_h3::AdminHttp3ListenerTask>,
  streams: Vec<StreamListenerTask>,
  turns: Vec<TurnListenerTask>,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
}

struct TcpListenerTask {
  bind: SocketAddr,
  options: TcpListenOptions,
  shutdown: watch::Sender<bool>,
  connections: TaskRegistry,
  drain_timeouts: DrainTimeouts,
  tasks: Vec<JoinHandle<()>>,
}

struct BoundTcpListener {
  bind: SocketAddr,
  options: TcpListenOptions,
  accept_error_backoff: Duration,
  kind: TcpListenerKind,
  listeners: Vec<TcpListener>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpListenerKind {
  Https,
  PlainHttp,
}

struct Http3ListenerTask {
  bind: SocketAddr,
  socket: crate::config::QuicSocketConfig,
  transport: crate::config::QuicTransportConfig,
  endpoints: Vec<h3_quinn::quinn::Endpoint>,
  shutdown: watch::Sender<bool>,
  connections: TaskRegistry,
  drain_timeouts: DrainTimeouts,
  tasks: Vec<JoinHandle<()>>,
}

struct BoundHttp3Listener {
  bind: SocketAddr,
  socket: crate::config::QuicSocketConfig,
  transport: crate::config::QuicTransportConfig,
  endpoints: Vec<h3_quinn::quinn::Endpoint>,
  sni_forward_quic: Vec<crate::sni_forward::quic::BoundQuicForwardSocket>,
}

struct AdminListenerTask {
  bind: SocketAddr,
  shutdown: watch::Sender<bool>,
  drain_timeouts: DrainTimeouts,
  task: JoinHandle<()>,
}

struct BoundAdminListener {
  bind: SocketAddr,
  listener: TcpListener,
}

pub(crate) struct PendingListenerUpdate {
  tcp: Option<Option<BoundTcpListener>>,
  http: Option<Option<BoundTcpListener>>,
  http3: Option<Option<BoundHttp3Listener>>,
  admin: Option<Option<BoundAdminListener>>,
  admin_h3: Option<Option<admin_h3::BoundAdminHttp3Listener>>,
  streams: Option<Vec<BoundStreamListener>>,
  turns: Option<Vec<BoundTurnListener>>,
  refresh_http3_config: bool,
  refresh_admin_h3_config: bool,
}

#[derive(Clone, Copy)]
struct DrainTimeouts {
  graceful: Duration,
  long_connection_close_delay: Duration,
}

impl DrainTimeouts {
  fn from_snapshot(snapshot: &AppSnapshot) -> Self {
    Self {
      graceful: Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms),
      long_connection_close_delay: Duration::from_millis(
        snapshot.config.runtime.drain.long_connection_close_delay_ms,
      ),
    }
  }
}

impl ListenerSupervisor {
  async fn start(
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    admin_control: AdminControlHandle,
    admin_operations: AdminOperationRuntime,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    let mut supervisor = Self {
      tcp: None,
      http: None,
      http3: None,
      admin: None,
      admin_h3: None,
      streams: Vec::new(),
      turns: Vec::new(),
      error_tx,
      admin_control,
      admin_operations,
    };
    let pending = supervisor.prepare(&snapshot).await?;
    supervisor.commit(pending, &snapshot, state);
    Ok(supervisor)
  }

  pub(crate) async fn prepare(
    &self,
    snapshot: &AppSnapshot,
  ) -> anyhow::Result<PendingListenerUpdate> {
    let tcp_options = TcpListenOptions::from(&snapshot.config.runtime.accept);
    let tcp = if snapshot.config.needs_https_listener() {
      let bind = snapshot.config.listeners.https_bind;
      if self
        .tcp
        .as_ref()
        .is_some_and(|task| task.bind == bind && task.options == tcp_options)
      {
        None
      } else {
        Some(Some(bind_tcp_listener(
          bind,
          tcp_options,
          snapshot.config.runtime.accept.accept_error_backoff_ms,
          TcpListenerKind::Https,
        )?))
      }
    } else if self.tcp.is_some() {
      Some(None)
    } else {
      None
    };

    let http = if snapshot.config.listeners.http_mode != crate::config::HttpListenerMode::Off {
      let bind = snapshot
        .config
        .listeners
        .http_bind
        .expect("validated http_bind");
      if self
        .http
        .as_ref()
        .is_some_and(|task| task.bind == bind && task.options == tcp_options)
      {
        None
      } else {
        Some(Some(bind_tcp_listener(
          bind,
          tcp_options,
          snapshot.config.runtime.accept.accept_error_backoff_ms,
          TcpListenerKind::PlainHttp,
        )?))
      }
    } else if self.http.is_some() {
      Some(None)
    } else {
      None
    };

    let (http3, refresh_http3_config) = if snapshot.config.listeners.http3 {
      let bind = snapshot.config.listeners.https_bind;
      if self.http3.as_ref().is_some_and(|task| {
        task.bind == bind
          && task.socket == snapshot.config.quic.socket
          && task.transport == snapshot.config.quic.downstream.transport
      }) {
        (None, true)
      } else {
        (Some(Some(bind_http3_listener(bind, snapshot)?)), false)
      }
    } else if self.http3.is_some() {
      (Some(None), false)
    } else {
      (None, false)
    };

    let admin = if snapshot.config.admin.enabled {
      let bind = snapshot.config.admin.bind;
      if self.admin.as_ref().map(|task| task.bind) == Some(bind) {
        None
      } else {
        Some(Some(bind_admin_listener(bind).await?))
      }
    } else if self.admin.is_some() {
      Some(None)
    } else {
      None
    };

    let (admin_h3, refresh_admin_h3_config) =
      if snapshot.config.admin.enabled && snapshot.config.admin.http3.enabled {
        let bind = admin_h3::configured_bind(snapshot);
        if self.admin_h3.as_ref().is_some_and(|task| {
          task.matches(
            bind,
            &snapshot.config.quic.socket,
            &snapshot.config.quic.downstream.transport,
          )
        }) {
          (None, true)
        } else {
          (
            Some(Some(admin_h3::BoundAdminHttp3Listener::bind(
              bind, snapshot,
            )?)),
            false,
          )
        }
      } else if self.admin_h3.is_some() {
        (Some(None), false)
      } else {
        (None, false)
      };

    let desired_streams = snapshot
      .config
      .stream_listeners
      .iter()
      .map(|listener| (listener.clone(), tcp_options))
      .collect::<Vec<_>>();
    let current_streams = self
      .streams
      .iter()
      .map(|listener| (listener.config.clone(), listener.options))
      .collect::<Vec<_>>();
    let streams = if desired_streams != current_streams {
      let mut bound = Vec::with_capacity(snapshot.config.stream_listeners.len());
      for listener in &snapshot.config.stream_listeners {
        bound.push(BoundStreamListener::bind(
          listener.clone(),
          tcp_options,
          Duration::from_millis(snapshot.config.runtime.accept.accept_error_backoff_ms),
        )?);
      }
      Some(bound)
    } else {
      None
    };

    let desired_turns = snapshot
      .config
      .webrtc_turn_listeners
      .iter()
      .map(|listener| {
        (
          listener.name.clone(),
          listener.bind_udp,
          listener.bind_tcp,
          listener.bind_tls,
          listener.stream_outbound_queue_capacity,
          tcp_options,
        )
      })
      .collect::<Vec<_>>();
    let current_turns = self
      .turns
      .iter()
      .map(|listener| {
        let key = listener.listener_key();
        (
          key.name.clone(),
          key.bind_udp,
          key.bind_tcp,
          key.bind_tls,
          key.stream_outbound_queue_capacity,
          key.tcp_options,
        )
      })
      .collect::<Vec<_>>();
    let turns = if desired_turns != current_turns {
      let mut bound = Vec::with_capacity(snapshot.config.webrtc_turn_listeners.len());
      for listener in &snapshot.config.webrtc_turn_listeners {
        bound.push(BoundTurnListener::bind(
          listener.clone(),
          tcp_options,
          Duration::from_millis(snapshot.config.runtime.accept.accept_error_backoff_ms),
          &snapshot.config.tls,
          &snapshot.tls_resumption,
        )?);
      }
      Some(bound)
    } else {
      None
    };

    Ok(PendingListenerUpdate {
      tcp,
      http,
      http3,
      admin,
      admin_h3,
      streams,
      turns,
      refresh_http3_config,
      refresh_admin_h3_config,
    })
  }

  pub(crate) fn commit(
    &mut self,
    pending: PendingListenerUpdate,
    snapshot: &AppSnapshot,
    state: AppHandle,
  ) {
    let drain_timeouts = DrainTimeouts::from_snapshot(snapshot);
    match pending.tcp {
      Some(Some(tcp)) => {
        let tcp = tcp.start(state.clone(), self.error_tx.clone(), drain_timeouts);
        if let Some(old) = self.tcp.replace(tcp) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.tcp.take() {
          old.drain_background();
        }
      }
      None => {}
    }
    match pending.http {
      Some(Some(http)) => {
        let http = http.start(state.clone(), self.error_tx.clone(), drain_timeouts);
        if let Some(old) = self.http.replace(http) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.http.take() {
          old.drain_background();
        }
      }
      None => {}
    }
    match pending.http3 {
      Some(Some(http3)) => {
        let http3 = http3.start(state.clone(), self.error_tx.clone(), drain_timeouts);
        if let Some(old) = self.http3.replace(http3) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.http3.take() {
          old.drain_background();
        }
      }
      None if pending.refresh_http3_config => {
        if let (Some(task), Some(config)) = (&self.http3, &snapshot.quic_server_config) {
          for endpoint in &task.endpoints {
            endpoint.set_server_config(Some(config.clone()));
          }
          info!(bind = %task.bind, "downstream HTTP/3 TLS config refreshed");
        }
      }
      None => {}
    }
    match pending.admin {
      Some(Some(admin)) => {
        let admin = admin.start(
          state.clone(),
          self.error_tx.clone(),
          self.admin_control.clone(),
          self.admin_operations.clone(),
          drain_timeouts,
        );
        if let Some(old) = self.admin.replace(admin) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.admin.take() {
          old.drain_background();
        }
      }
      None => {}
    }
    match pending.admin_h3 {
      Some(Some(admin_h3)) => {
        let admin_h3 = admin_h3.start(
          state.clone(),
          self.error_tx.clone(),
          self.admin_operations.clone(),
          drain_timeouts.graceful,
        );
        if let Some(old) = self.admin_h3.replace(admin_h3) {
          old.drain_background();
        }
      }
      Some(None) => {
        if let Some(old) = self.admin_h3.take() {
          old.drain_background();
        }
      }
      None if pending.refresh_admin_h3_config => {
        if let (Some(task), Some(config)) = (&self.admin_h3, &snapshot.admin_quic_server_config) {
          task.refresh_server_config(config.clone());
        }
      }
      None => {}
    }
    if let Some(streams) = pending.streams {
      let old = std::mem::take(&mut self.streams);
      for task in old {
        task.drain_background();
      }
      self.streams = streams
        .into_iter()
        .map(|stream| stream.start(state.clone(), self.error_tx.clone()))
        .collect();
    }
    if let Some(turns) = pending.turns {
      let old = std::mem::take(&mut self.turns);
      for task in old {
        task.drain_background();
      }
      self.turns = turns
        .into_iter()
        .map(|turn| turn.start(state.clone(), self.error_tx.clone()))
        .collect();
    }
  }

  async fn shutdown(&mut self, snapshot: &AppSnapshot) {
    let drain_timeouts = DrainTimeouts::from_snapshot(snapshot);
    let mut tasks = Vec::new();
    if let Some(task) = self.tcp.take() {
      tasks.push(task.drain());
    }
    if let Some(task) = self.http.take() {
      tasks.push(task.drain());
    }
    if let Some(task) = self.http3.take() {
      tasks.push(task.drain());
    }
    if let Some(task) = self.admin.take() {
      tasks.push(task.drain());
    }
    if let Some(task) = self.admin_h3.take() {
      tasks.push(task.drain());
    }
    for task in std::mem::take(&mut self.streams) {
      tasks.push(task.drain());
    }
    for task in std::mem::take(&mut self.turns) {
      tasks.push(task.drain());
    }
    if tasks.is_empty() {
      tokio::time::sleep(drain_timeouts.graceful.min(Duration::from_millis(1))).await;
      return;
    }
    let _ = futures_util::future::join_all(tasks).await;
  }
}

impl Drop for ListenerSupervisor {
  fn drop(&mut self) {
    if let Some(task) = self.tcp.take() {
      task.drain_background();
    }
    if let Some(task) = self.http.take() {
      task.drain_background();
    }
    if let Some(task) = self.http3.take() {
      task.drain_background();
    }
    if let Some(task) = self.admin.take() {
      task.drain_background();
    }
    if let Some(task) = self.admin_h3.take() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.streams) {
      task.drain_background();
    }
  }
}

impl TcpListenerTask {
  fn drain_background(self) {
    drop(self.drain());
  }

  fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let TcpListenerTask {
        shutdown,
        connections,
        drain_timeouts,
        tasks,
        ..
      } = self;
      let _ = shutdown.send(true);
      let wait_connections = connections.clone();
      let wait = async {
        for task in tasks {
          let _ = task.await;
        }
        wait_connections.wait_idle().await;
      };
      if tokio::time::timeout(drain_timeouts.graceful, wait)
        .await
        .is_err()
      {
        connections.abort_all();
      }
    })
  }
}

impl BoundTcpListener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    drain_timeouts: DrainTimeouts,
  ) -> TcpListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let options = self.options;
    let kind = self.kind;
    let accept_error_backoff = self.accept_error_backoff;
    let connections = TaskRegistry::default();
    let tasks = self
      .listeners
      .into_iter()
      .enumerate()
      .map(|(worker_index, listener)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        let worker_connections = connections.clone();
        tokio::spawn(async move {
          if let Err(error) = serve_tcp(
            listener,
            kind,
            worker_state,
            worker_shutdown,
            worker_index,
            accept_error_backoff,
            worker_connections,
            drain_timeouts.long_connection_close_delay,
          )
          .await
          {
            let _ = worker_error_tx.send(error.context("downstream TCP HTTP listener failed"));
          }
        })
      })
      .collect();
    TcpListenerTask {
      bind,
      options,
      shutdown,
      connections,
      drain_timeouts,
      tasks,
    }
  }
}

impl Http3ListenerTask {
  fn drain_background(self) {
    drop(self.drain());
  }

  fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let Http3ListenerTask {
        endpoints,
        shutdown,
        connections,
        drain_timeouts,
        tasks,
        ..
      } = self;
      let _ = shutdown.send(true);
      let wait_endpoints = endpoints.clone();
      let wait_connections = connections.clone();
      let wait = async {
        for task in tasks {
          let _ = task.await;
        }
        wait_connections.wait_idle().await;
        for endpoint in wait_endpoints {
          endpoint.wait_idle().await;
        }
      };
      if tokio::time::timeout(drain_timeouts.graceful, wait)
        .await
        .is_err()
      {
        for endpoint in endpoints {
          endpoint.close(0u32.into(), b"listener drain timeout");
        }
        connections.abort_all();
      }
    })
  }
}

impl BoundHttp3Listener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    drain_timeouts: DrainTimeouts,
  ) -> Http3ListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let socket = self.socket;
    let transport = self.transport;
    let connections = TaskRegistry::default();
    let mut tasks = crate::sni_forward::quic::spawn_demux_tasks(
      self.sni_forward_quic,
      shutdown_rx.clone(),
      state.clone(),
      error_tx.clone(),
    );
    tasks.extend(
      self
        .endpoints
        .iter()
        .cloned()
        .enumerate()
        .map(|(worker_index, endpoint)| {
          let worker_shutdown = shutdown_rx.clone();
          let worker_state = state.clone();
          let worker_error_tx = error_tx.clone();
          let worker_connections = connections.clone();
          tokio::spawn(async move {
            if let Err(error) = serve_http3(
              endpoint,
              worker_state,
              worker_shutdown,
              worker_index,
              worker_connections,
              drain_timeouts.long_connection_close_delay,
            )
            .await
            {
              let _ = worker_error_tx.send(error.context("downstream HTTP/3 listener failed"));
            }
          })
        }),
    );
    Http3ListenerTask {
      bind,
      socket,
      transport,
      endpoints: self.endpoints,
      shutdown,
      connections,
      drain_timeouts,
      tasks,
    }
  }
}

impl AdminListenerTask {
  fn drain_background(self) {
    drop(self.drain());
  }

  fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let AdminListenerTask {
        shutdown,
        drain_timeouts,
        mut task,
        ..
      } = self;
      let _ = shutdown.send(true);
      tokio::select! {
        _ = &mut task => {}
        _ = tokio::time::sleep(drain_timeouts.graceful) => {
          task.abort();
        }
      }
    })
  }
}

impl BoundAdminListener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    admin_control: AdminControlHandle,
    admin_operations: AdminOperationRuntime,
    drain_timeouts: DrainTimeouts,
  ) -> AdminListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let task = tokio::spawn(async move {
      if let Err(error) = serve_admin_listener(
        self.listener,
        bind,
        state,
        admin_control,
        admin_operations,
        shutdown_rx,
      )
      .await
      {
        let _ = error_tx.send(error.context("admin listener failed"));
      }
    });
    AdminListenerTask {
      bind,
      shutdown,
      drain_timeouts,
      task,
    }
  }
}

fn bind_tcp_listener(
  bind: SocketAddr,
  options: TcpListenOptions,
  accept_error_backoff_ms: u64,
  kind: TcpListenerKind,
) -> anyhow::Result<BoundTcpListener> {
  let listeners = bind_tcp_listeners(bind, options, kind.bind_purpose())
    .with_context(|| format!("failed to bind downstream listener to {bind}"))?;
  Ok(BoundTcpListener {
    bind,
    options,
    accept_error_backoff: Duration::from_millis(accept_error_backoff_ms),
    kind,
    listeners,
  })
}

impl TcpListenerKind {
  fn bind_purpose(self) -> &'static str {
    match self {
      Self::Https => "downstream HTTPS",
      Self::PlainHttp => "downstream plain HTTP",
    }
  }
}

async fn bind_admin_listener(bind: SocketAddr) -> anyhow::Result<BoundAdminListener> {
  let listener = TcpListener::bind(bind)
    .await
    .with_context(|| format!("failed to bind admin listener to {bind}"))?;
  Ok(BoundAdminListener { bind, listener })
}

#[cfg(test)]
fn test_admin_control() -> AdminControlHandle {
  AdminControlHandle::new(None).0
}

#[cfg(test)]
fn test_admin_operations() -> AdminOperationRuntime {
  AdminOperationRuntime::new(crate::config::AdminOperationsConfig::default())
}

#[allow(clippy::too_many_arguments)]
async fn serve_tcp(
  listener: TcpListener,
  kind: TcpListenerKind,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  accept_error_backoff: Duration,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read TCP listener address")?;
  info!(bind = %bind, ?kind, worker = worker_index, "downstream TCP listener started");

  loop {
    tokio::select! {
        biased;
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream TCP listener stopped");
            }
            return Ok(());
        }
        accepted = listener.accept() => {
            let (stream, peer_addr) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, worker = worker_index, "failed to accept downstream connection");
                    tokio::time::sleep(accept_error_backoff).await;
                    continue;
                }
            };
            crate::tcp_socket::enable_tcp_nodelay(&stream, peer_addr, "downstream listener");

            let connection_state = state.connection_snapshot();
            let connection_shutdown = shutdown.clone();
            let connection_snapshot = connection_state.snapshot;
            let data_plane_drain = connection_state.data_plane_drain;
            let connection_drain = ConnectionDrain::with_data_plane(
              connection_shutdown.clone(),
              connection_snapshot.lifecycle.subscribe(),
              data_plane_drain.clone(),
              long_connection_close_delay,
            );
            connections.spawn(async move {
                let result = match kind {
                  TcpListenerKind::Https => handle_connection(
                    stream,
                    peer_addr,
                    connection_snapshot,
                    connection_shutdown,
                    data_plane_drain,
                    connection_drain,
                  ).await,
                  TcpListenerKind::PlainHttp => plain_http::handle_connection(
                    stream,
                    peer_addr,
                    connection_snapshot,
                    connection_shutdown,
                    data_plane_drain,
                    connection_drain,
                  ).await,
                };
                if let Err(error) = result {
                    connection_errors::log_tcp(peer_addr, &error);
                }
            });
        }
    }
  }
}

fn bind_http3_listener(
  bind: SocketAddr,
  snapshot: &AppSnapshot,
) -> anyhow::Result<BoundHttp3Listener> {
  let server_config = snapshot
    .quic_server_config
    .clone()
    .ok_or_else(|| anyhow::anyhow!("HTTP/3 listener is enabled without QUIC server config"))?;
  let (endpoints, sni_forward_quic) =
    crate::sni_forward::quic::bind_sni_or_plain_server_endpoints(bind, server_config, snapshot)?;
  Ok(BoundHttp3Listener {
    bind,
    socket: snapshot.config.quic.socket.clone(),
    transport: snapshot.config.quic.downstream.transport.clone(),
    endpoints,
    sni_forward_quic,
  })
}

async fn serve_http3(
  endpoint: h3_quinn::quinn::Endpoint,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
) -> anyhow::Result<()> {
  let bind = endpoint
    .local_addr()
    .context("failed to read HTTP/3 listener address")?;
  info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener started");

  loop {
    tokio::select! {
        biased;
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener stopped");
            }
            return Ok(());
        }
        connecting = endpoint.accept() => {
            let Some(connecting) = connecting else {
                return Ok(());
            };
            let connection_state = state.connection_snapshot();
            let connection_snapshot = connection_state.snapshot;
            let data_plane_drain = connection_state.data_plane_drain;
            if connection_snapshot.config.quic.retry && !connecting.remote_address_validated() && connecting.may_retry() {
                if let Err(error) = connecting.retry() {
                    connection_snapshot.metrics.record_quic_retry("error");
                    warn!(error = %error, "failed to send QUIC Retry packet");
                } else {
                    connection_snapshot.metrics.record_quic_retry("sent");
                }
                continue;
            }
            let connection_shutdown = shutdown.clone();
            let connection_drain = ConnectionDrain::with_data_plane(
              connection_shutdown.clone(),
              connection_snapshot.lifecycle.subscribe(),
              data_plane_drain.clone(),
              long_connection_close_delay,
            );
            let peer_addr = connecting.remote_address();
            connections.spawn(async move {
                match connecting.await {
                    Ok(connection) => {
                        if let Err(error) = http3::handle_downstream_connection(
                          connection,
                          connection_snapshot,
                          connection_shutdown,
                          data_plane_drain,
                          connection_drain,
                        ).await {
                            connection_errors::log_http3(peer_addr, &error);
                        }
                    }
                    Err(error) => {
                        warn!(error = %error, "failed to accept downstream HTTP/3 connection");
                    }
                }
            });
        }
    }
  }
}

pub(crate) fn downstream_quic_tls_metadata(
  connection: &h3_quinn::quinn::Connection,
) -> WafTlsMetadata {
  let handshake_data = connection.handshake_data().and_then(|data| {
    data
      .downcast::<h3_quinn::quinn::crypto::rustls::HandshakeData>()
      .ok()
  });
  let (alpn, sni) = handshake_data
    .map(|data| {
      (
        data
          .protocol
          .as_ref()
          .map(|value| String::from_utf8_lossy(value).into_owned()),
        data.server_name.clone(),
      )
    })
    .unwrap_or_default();
  let version = Some("TLSv1_3".to_string());
  // Quinn's stable rustls handshake data exposes ALPN and SNI for QUIC, but not the
  // negotiated cipher suite or key-exchange group. Keep explicit empty payload
  // slots so future metadata additions can move the QUIC scheme forward cleanly.
  let fingerprint = Some(quic_tls_fingerprint(QuicTlsFingerprintInput {
    version: version.as_deref(),
    cipher_suite: None,
    key_exchange_group: None,
    data_integrity_group: None,
    sni: sni.as_deref(),
    alpn: alpn.as_deref(),
  }));

  WafTlsMetadata {
    enabled: true,
    version,
    cipher_suite: None,
    sni,
    alpn,
    fingerprint,
    fingerprint_scheme: Some(QUIC_TLS_FINGERPRINT_SCHEME.to_string()),
    client_certificate: None,
  }
}

async fn handle_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  handshake_state: Arc<AppSnapshot>,
  mut shutdown: watch::Receiver<bool>,
  mut data_plane_drain: watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let _global_permit = acquire_global_connection_permit(&handshake_state)?;
  let _https_connection_guard =
    handshake_state.runtime_introspection_guard(RuntimeCounter::DownstreamHttpsTcpConnection);
  let (stream, peer_addr) = proxy_protocol::accept_proxy_header(
    stream,
    peer_addr,
    &handshake_state.config.listeners.proxy_protocol,
  )
  .await?;
  let connection_limit_identity = handshake_state.config.limits.connection_limit_identity;
  let _ip_permit = if connection_limit_identity == ConnectionLimitIdentityMode::ProxyProtocol {
    Some(acquire_ip_connection_permit(&handshake_state, peer_addr)?)
  } else {
    None
  };
  let connection_limit_context = (connection_limit_identity
    == ConnectionLimitIdentityMode::FirstRequestRealIp)
    .then(ConnectionLimitContext::default);
  let tcp_max_hop = handshake_state.waf.person_proof_tcp_max_hop();
  if let Some(max_hop) = tcp_max_hop {
    tcp_hop::apply_tcp_max_hop(&stream, peer_addr.ip(), max_hop)
      .with_context(|| format!("failed to apply TCP max hop {max_hop} for {peer_addr}"))?;
  }

  let Some(stream) = crate::sni_forward::tcp::local_stream_or_forwarded(
    stream,
    peer_addr,
    handshake_state.clone(),
    drain.clone(),
  )
  .await?
  else {
    return Ok(());
  };

  let handshake_started_at = TelemetryRuntime::start();
  let start = tokio::time::timeout(
    Duration::from_millis(handshake_state.config.limits.tls_handshake_timeout_ms),
    LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream),
  )
  .await
  .context("TLS ClientHello timed out")?
  .context("TLS ClientHello failed")?;
  let client_hello_metadata = client_hello_fingerprint_metadata(start.client_hello());
  let tls_stream = tokio::time::timeout(
    Duration::from_millis(handshake_state.config.limits.tls_handshake_timeout_ms),
    start.into_stream(handshake_state.tls_server_config.clone()),
  )
  .await
  .context("TLS handshake timed out")?
  .context("TLS handshake failed")?;

  let negotiated = tls_stream
    .get_ref()
    .1
    .alpn_protocol()
    .map(|proto| proto.to_vec())
    .unwrap_or_else(|| b"http/1.1".to_vec());
  let alpn = String::from_utf8_lossy(&negotiated).to_string();
  handshake_state.metrics.record_tls_handshake(
    &handshake_state.config.metrics,
    "tcp",
    &alpn,
    "success",
    handshake_started_at.elapsed_ms(),
  );
  let tls_metadata = Arc::new(downstream_tls_metadata(
    tls_stream.get_ref().1,
    &client_hello_metadata,
  ));
  let tcp_metadata = tcp_hop::transport_metadata(tls_stream.get_ref().0);
  let transport_metadata = WafTransportMetadataInput {
    tcp_mss: tcp_metadata.mss,
    tcp_rtt_ms: tcp_metadata.rtt_ms,
    ..WafTransportMetadataInput::default()
  };

  let request_count = Arc::new(AtomicUsize::new(0));
  let request_counter = if negotiated == b"h2" {
    RuntimeCounter::Http2Stream
  } else {
    RuntimeCounter::Http1Request
  };
  let forwarded_header_cache = http::headers::build_forwarded_header_cache(
    peer_addr,
    "https",
    &handshake_state.config.proxy.forwarded_headers,
    &handshake_state.config.proxy.real_ip,
  );
  let request_state = handshake_state.clone();
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = request_state.clone();
    let tls_metadata = tls_metadata.clone();
    let forwarded_header_cache = forwarded_header_cache.clone();
    let request_index = request_count.fetch_add(1, Ordering::Relaxed);
    let connection_limit_context = connection_limit_context.clone();
    let drain = drain.clone();
    async move {
      let _request_guard = state.runtime_introspection_guard(request_counter);
      Ok::<_, Infallible>(
        if request_index >= state.config.limits.max_requests_per_connection {
          text_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests on this connection",
          )
        } else {
          http::handle_with_forwarded_header_cache(
            request,
            peer_addr,
            tcp_max_hop,
            transport_metadata,
            tls_metadata,
            connection_limit_context.clone(),
            forwarded_header_cache,
            state,
            "https",
            drain,
          )
          .await
        },
      )
    }
  });

  if negotiated == b"h2" {
    let _http2_connection_guard =
      handshake_state.runtime_introspection_guard(RuntimeCounter::Http2Connection);
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    crate::h2_tuning::apply_server_defaults(&mut builder, &handshake_state.config.proxy.http2);
    builder.max_header_list_size(handshake_state.config.limits.max_total_header_bytes as u32);
    let connection = builder.serve_connection(TokioIo::new(tls_stream), service);
    tokio::pin!(connection);
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      connection.as_mut().graceful_shutdown();
    }
    let result = tokio::select! {
      result = &mut connection => result,
      _ = wait_for_listener_or_data_plane_drain(&mut shutdown, &mut data_plane_drain) => {
        connection.as_mut().graceful_shutdown();
        (&mut connection).await
      }
    };
    result.map_err(|error| anyhow::anyhow!(error))?;
  } else {
    let _http1_connection_guard =
      handshake_state.runtime_introspection_guard(RuntimeCounter::Http1Connection);
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
      .timer(TokioTimer::new())
      .header_read_timeout(Duration::from_millis(
        handshake_state.config.limits.client_header_timeout_ms,
      ))
      .max_headers(handshake_state.config.limits.max_headers)
      .max_buf_size(
        handshake_state
          .config
          .limits
          .max_total_header_bytes
          .max(8192),
      )
      .keep_alive(true);
    let connection = builder.serve_connection(TokioIo::new(tls_stream), service);
    let result = if handshake_state.http1_upgrades_possible {
      let connection = connection.with_upgrades();
      tokio::pin!(connection);
      if *shutdown.borrow() || *data_plane_drain.borrow() {
        connection.as_mut().graceful_shutdown();
      }
      tokio::select! {
        result = &mut connection => result,
        _ = wait_for_listener_or_data_plane_drain(&mut shutdown, &mut data_plane_drain) => {
          connection.as_mut().graceful_shutdown();
          (&mut connection).await
        }
      }
    } else {
      tokio::pin!(connection);
      if *shutdown.borrow() || *data_plane_drain.borrow() {
        connection.as_mut().graceful_shutdown();
      }
      tokio::select! {
        result = &mut connection => result,
        _ = wait_for_listener_or_data_plane_drain(&mut shutdown, &mut data_plane_drain) => {
          connection.as_mut().graceful_shutdown();
          (&mut connection).await
        }
      }
    };
    result.map_err(|error| anyhow::anyhow!(error))?;
  }

  Ok(())
}

fn redirect_to_https(request: &hyper::Request<Incoming>) -> Response<ProxyBody> {
  let host = request
    .headers()
    .get(::http::header::HOST)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  let path = request
    .uri()
    .path_and_query()
    .map(|value| value.as_str())
    .unwrap_or("/");
  let location = format!("https://{host}{path}");
  let mut response = text_response(StatusCode::PERMANENT_REDIRECT, "");
  if let Ok(value) = ::http::HeaderValue::from_str(&location) {
    response
      .headers_mut()
      .insert(::http::header::LOCATION, value);
  }
  response
}

fn acquire_global_connection_permit(snapshot: &AppSnapshot) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_global_connection(&snapshot.config.limits)
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))
}

fn acquire_ip_connection_permit(
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_ip_connection(
      peer_addr.ip(),
      &snapshot.config.limits,
      &snapshot.config.connection_limits,
    )
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))
}

#[derive(Debug, Clone, Default)]
struct ClientHelloFingerprintMetadata {
  cipher_suites: String,
  key_exchange_groups: String,
  signature_schemes: String,
  data_integrity_groups: String,
}

fn client_hello_fingerprint_metadata(
  client_hello: rustls::server::ClientHello<'_>,
) -> ClientHelloFingerprintMetadata {
  let cipher_suites = client_hello
    .cipher_suites()
    .iter()
    .map(|suite| format!("{suite:?}"))
    .collect::<Vec<_>>();
  let key_exchange_groups = client_hello
    .named_groups()
    .unwrap_or_default()
    .iter()
    .map(|group| format!("{group:?}"))
    .collect::<Vec<_>>();
  let signature_schemes = client_hello
    .signature_schemes()
    .iter()
    .map(|scheme| format!("{scheme:?}"))
    .collect::<Vec<_>>();
  let data_integrity_groups = unique_nonempty(
    cipher_suites
      .iter()
      .filter_map(|suite| cipher_suite_data_integrity_group(suite))
      .map(str::to_string),
  );

  ClientHelloFingerprintMetadata {
    cipher_suites: cipher_suites.join(","),
    key_exchange_groups: key_exchange_groups.join(","),
    signature_schemes: signature_schemes.join(","),
    data_integrity_groups: data_integrity_groups.join(","),
  }
}

fn downstream_tls_metadata(
  connection: &rustls::ServerConnection,
  client_hello: &ClientHelloFingerprintMetadata,
) -> WafTlsMetadata {
  let version = connection
    .protocol_version()
    .map(|version| format!("{version:?}"));
  let cipher_suite = connection
    .negotiated_cipher_suite()
    .map(|suite| format!("{:?}", suite.suite()));
  let key_exchange_group = connection
    .negotiated_key_exchange_group()
    .map(|group| format!("{:?}", group.name()));
  let data_integrity_group = connection
    .negotiated_cipher_suite()
    .map(|suite| negotiated_cipher_suite_data_integrity_group(suite).to_string());
  let sni = connection.server_name().map(str::to_string);
  let alpn = connection
    .alpn_protocol()
    .map(|proto| String::from_utf8_lossy(proto).into_owned());
  let fingerprint = Some(tls_fingerprint(
    client_hello,
    version.as_deref(),
    cipher_suite.as_deref(),
    key_exchange_group.as_deref(),
    data_integrity_group.as_deref(),
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
    fingerprint_scheme: Some(TCP_TLS_FINGERPRINT_SCHEME.to_string()),
    client_certificate: crate::tls::client_certificate_metadata(
      connection.peer_certificates().unwrap_or_default(),
    ),
  }
}

fn tls_fingerprint(
  client_hello: &ClientHelloFingerprintMetadata,
  version: Option<&str>,
  cipher_suite: Option<&str>,
  key_exchange_group: Option<&str>,
  data_integrity_group: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  let payload = tls_fingerprint_payload(
    client_hello,
    version,
    cipher_suite,
    key_exchange_group,
    data_integrity_group,
    sni,
    alpn,
  );
  let hash = digest::digest(&digest::SHA256, payload.as_bytes());
  hex_encode(hash.as_ref())
}

fn tls_fingerprint_payload(
  client_hello: &ClientHelloFingerprintMetadata,
  version: Option<&str>,
  cipher_suite: Option<&str>,
  key_exchange_group: Option<&str>,
  data_integrity_group: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  format!(
    "{TCP_TLS_FINGERPRINT_SCHEME}\nclient_hello_cipher_suites={}\nclient_hello_key_exchange_groups={}\nclient_hello_signature_schemes={}\nclient_hello_data_integrity_groups={}\nselected_version={}\nselected_cipher_suite={}\nselected_key_exchange_group={}\nselected_data_integrity_group={}\nsni={}\nalpn={}",
    client_hello.cipher_suites,
    client_hello.key_exchange_groups,
    client_hello.signature_schemes,
    client_hello.data_integrity_groups,
    version.unwrap_or_default(),
    cipher_suite.unwrap_or_default(),
    key_exchange_group.unwrap_or_default(),
    data_integrity_group.unwrap_or_default(),
    sni.unwrap_or_default(),
    alpn.unwrap_or_default()
  )
}

#[derive(Debug, Clone, Copy)]
struct QuicTlsFingerprintInput<'a> {
  version: Option<&'a str>,
  cipher_suite: Option<&'a str>,
  key_exchange_group: Option<&'a str>,
  data_integrity_group: Option<&'a str>,
  sni: Option<&'a str>,
  alpn: Option<&'a str>,
}

fn quic_tls_fingerprint(input: QuicTlsFingerprintInput<'_>) -> String {
  let payload = quic_tls_fingerprint_payload(input);
  let hash = digest::digest(&digest::SHA256, payload.as_bytes());
  hex_encode(hash.as_ref())
}

fn quic_tls_fingerprint_payload(input: QuicTlsFingerprintInput<'_>) -> String {
  format!(
    "{QUIC_TLS_FINGERPRINT_SCHEME}\nselected_version={}\nselected_cipher_suite={}\nselected_key_exchange_group={}\nselected_data_integrity_group={}\nsni={}\nalpn={}\nmetadata_source=quinn-rustls-handshake-data",
    input.version.unwrap_or_default(),
    input.cipher_suite.unwrap_or_default(),
    input.key_exchange_group.unwrap_or_default(),
    input.data_integrity_group.unwrap_or_default(),
    input.sni.unwrap_or_default(),
    input.alpn.unwrap_or_default()
  )
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

fn negotiated_cipher_suite_data_integrity_group(
  suite: rustls::SupportedCipherSuite,
) -> &'static str {
  match suite {
    rustls::SupportedCipherSuite::Tls12(suite) => {
      hash_algorithm_name(format!("{:?}", suite.common.hash_provider.algorithm()).as_str())
    }
    rustls::SupportedCipherSuite::Tls13(suite) => {
      hash_algorithm_name(format!("{:?}", suite.common.hash_provider.algorithm()).as_str())
    }
  }
}

fn cipher_suite_data_integrity_group(cipher_suite: &str) -> Option<&'static str> {
  if cipher_suite.ends_with("_SHA512") {
    Some("SHA512")
  } else if cipher_suite.ends_with("_SHA384") {
    Some("SHA384")
  } else if cipher_suite.ends_with("_SHA256") {
    Some("SHA256")
  } else if cipher_suite.ends_with("_SHA") {
    Some("SHA")
  } else if cipher_suite.ends_with("_MD5") {
    Some("MD5")
  } else {
    None
  }
}

fn hash_algorithm_name(name: &str) -> &'static str {
  match name {
    "SHA512" => "SHA512",
    "SHA384" => "SHA384",
    "SHA256" => "SHA256",
    "SHA1" => "SHA",
    "MD5" => "MD5",
    _ => "unknown",
  }
}

fn unique_nonempty(values: impl IntoIterator<Item = String>) -> Vec<String> {
  let mut unique = Vec::new();
  for value in values {
    if !value.is_empty() && !unique.contains(&value) {
      unique.push(value);
    }
  }
  unique
}

#[cfg(test)]
mod admin_audit_tests;

#[cfg(test)]
mod admin_diagnostics_tests;

#[cfg(test)]
mod admin_diagnostics_async_tests;

#[cfg(test)]
mod admin_diagnostics_probe_tests;

#[cfg(test)]
mod admin_json_tests;

#[cfg(test)]
mod admin_runtime_introspection_tests;

#[cfg(test)]
mod tests {
  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  use std::path::Path;
  use std::time::Instant;

  use crate::config::Config;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  const ADMIN_TOKEN_ENV: &str = "PATH";

  #[tokio::test]
  async fn admin_listener_disabled_config_does_not_serve_stale_requests() {
    let temp_dir = common::TempDir::new("admin-listener-disabled");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "admin-listener-disabled");
    let config = admin_listener_config(&cert_path, &key_path, false, None);
    let state = AppHandle::new(
      AppSnapshot::new(config)
        .await
        .expect("snapshot should initialize"),
    );
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("admin listener should bind");
    let addr = listener
      .local_addr()
      .expect("admin listener address should be available");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(serve_admin_listener(
      listener,
      addr,
      state,
      test_admin_control(),
      test_admin_operations(),
      shutdown_rx,
    ));

    match admin_purge_response(addr).await {
      Ok(response) => assert!(
        !response.contains("purged="),
        "disabled admin listener must not serve purge requests: {}",
        log_safe_test_text(&response)
      ),
      Err(error)
        if matches!(
          error.kind(),
          std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::UnexpectedEof
        ) => {}
      Err(error) => panic!(
        "unexpected stale admin connection error kind: {:?}",
        error.kind()
      ),
    }
    let _ = shutdown.send(true);
    task.abort();
  }

  #[tokio::test]
  async fn admin_listener_supervisor_rebinds_admin_port_on_reload() {
    let temp_dir = common::TempDir::new("admin-listener-rebind");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "admin-listener-rebind");
    let (old_admin, new_admin) = unused_loopback_ports().await;
    let initial_config = admin_listener_config(&cert_path, &key_path, true, Some(old_admin));
    let state = AppHandle::new(
      AppSnapshot::new(initial_config)
        .await
        .expect("initial snapshot should initialize"),
    );
    let (error_tx, _error_rx) = mpsc::unbounded_channel();
    let mut supervisor = ListenerSupervisor::start(
      state.clone(),
      error_tx,
      test_admin_control(),
      test_admin_operations(),
    )
    .await
    .expect("listener supervisor should start");

    let response = admin_purge_response_with_retry(old_admin).await;
    assert!(
      response.starts_with("HTTP/1.1 200 OK"),
      "old admin listener should serve before reload: {}",
      log_safe_test_text(&response)
    );
    let mut stale_connection = TcpStream::connect(old_admin)
      .await
      .expect("stale admin connection should open before reload");
    write_admin_purge_request_headers(&mut stale_connection)
      .await
      .expect("stale admin request headers should write before reload");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let active = state.snapshot();
    let reloaded_config = admin_listener_config(&cert_path, &key_path, true, Some(new_admin));
    let reloaded = AppSnapshot::new_with_previous(reloaded_config, Some(active.as_ref()))
      .await
      .expect("reloaded snapshot should initialize");
    let pending = supervisor
      .prepare(&reloaded)
      .await
      .expect("admin rebind should prepare");
    state.replace(reloaded);
    let active = state.snapshot();
    supervisor.commit(pending, active.as_ref(), state.clone());

    let response = admin_purge_response_with_retry(new_admin).await;
    assert!(
      response.starts_with("HTTP/1.1 200 OK"),
      "new admin listener should serve after reload: {}",
      log_safe_test_text(&response)
    );
    let stale_response = finish_admin_purge_response_on_stream(stale_connection)
      .await
      .expect("stale admin connection should receive a response after rebind");
    assert!(
      stale_response.starts_with("HTTP/1.1 404 Not Found"),
      "stale admin connection should stop serving after rebind: {}",
      log_safe_test_text(&stale_response)
    );
    assert_tcp_connect_fails(old_admin).await;
  }

  #[tokio::test]
  async fn admin_listener_supervisor_stops_admin_port_when_disabled() {
    let temp_dir = common::TempDir::new("admin-listener-disable-reload");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "admin-listener-disable-reload");
    let admin_addr = unused_loopback_port().await;
    let initial_config = admin_listener_config(&cert_path, &key_path, true, Some(admin_addr));
    let state = AppHandle::new(
      AppSnapshot::new(initial_config)
        .await
        .expect("initial snapshot should initialize"),
    );
    let (error_tx, _error_rx) = mpsc::unbounded_channel();
    let mut supervisor = ListenerSupervisor::start(
      state.clone(),
      error_tx,
      test_admin_control(),
      test_admin_operations(),
    )
    .await
    .expect("listener supervisor should start");

    let response = admin_purge_response_with_retry(admin_addr).await;
    assert!(
      response.starts_with("HTTP/1.1 200 OK"),
      "admin listener should serve before disable reload: {}",
      log_safe_test_text(&response)
    );

    let active = state.snapshot();
    let disabled_config = admin_listener_config(&cert_path, &key_path, false, Some(admin_addr));
    let reloaded = AppSnapshot::new_with_previous(disabled_config, Some(active.as_ref()))
      .await
      .expect("disabled snapshot should initialize");
    let pending = supervisor
      .prepare(&reloaded)
      .await
      .expect("admin disable should prepare");
    state.replace(reloaded);
    let active = state.snapshot();
    supervisor.commit(pending, active.as_ref(), state.clone());

    assert_tcp_connect_fails(admin_addr).await;
  }

  #[tokio::test]
  async fn listener_supervisor_rebind_drains_delayed_plain_http_request() {
    let temp_dir = common::TempDir::new("plain-http-drain-rebind");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "plain-http-drain-rebind");
    let (old_http, new_http) = unused_loopback_ports().await;
    let https_bind = unused_loopback_port().await;
    let (upstream_addr, upstream_task, first_upstream_request) =
      start_delayed_http_upstream(Duration::from_millis(200), 2).await;
    let initial_config =
      plain_http_listener_config(&cert_path, &key_path, https_bind, old_http, upstream_addr);
    let state = AppHandle::new(
      AppSnapshot::new(initial_config)
        .await
        .expect("initial snapshot should initialize"),
    );
    let (error_tx, _error_rx) = mpsc::unbounded_channel();
    let mut supervisor = ListenerSupervisor::start(
      state.clone(),
      error_tx,
      test_admin_control(),
      test_admin_operations(),
    )
    .await
    .expect("listener supervisor should start");

    let held_request = tokio::spawn(raw_http_response(old_http, "/slow"));
    tokio::time::timeout(Duration::from_secs(2), first_upstream_request)
      .await
      .expect("upstream should receive held request before reload")
      .expect("upstream signal should be sent");

    let active = state.snapshot();
    let reloaded_config =
      plain_http_listener_config(&cert_path, &key_path, https_bind, new_http, upstream_addr);
    let reloaded = AppSnapshot::new_with_previous(reloaded_config, Some(active.as_ref()))
      .await
      .expect("reloaded snapshot should initialize");
    let pending = supervisor
      .prepare(&reloaded)
      .await
      .expect("plain HTTP rebind should prepare");
    state.replace(reloaded);
    let active = state.snapshot();
    supervisor.commit(pending, active.as_ref(), state.clone());

    let held_response = held_request
      .await
      .expect("held request task should not panic")
      .expect("held request should finish across listener drain");
    assert!(
      held_response.starts_with("HTTP/1.1 200 OK") && held_response.contains("delayed-0"),
      "held request should complete on old listener generation: {}",
      log_safe_test_text(&held_response)
    );
    assert_tcp_connect_fails(old_http).await;

    let new_response = raw_http_response(new_http, "/after")
      .await
      .expect("new listener should serve after reload");
    assert!(
      new_response.starts_with("HTTP/1.1 200 OK") && new_response.contains("delayed-1"),
      "new listener generation should serve after reload: {}",
      log_safe_test_text(&new_response)
    );

    supervisor.shutdown(state.snapshot().as_ref()).await;
    upstream_task
      .await
      .expect("delayed upstream task should not panic");
  }

  fn admin_listener_config(
    cert_path: &Path,
    key_path: &Path,
    enabled: bool,
    admin_bind: Option<SocketAddr>,
  ) -> Config {
    let mut raw = common::minimal_config_toml(cert_path, key_path)
      .replace("unprivileged_mode = true", "unprivileged_mode = false")
      .replace(
        "https_bind = \"127.0.0.1:8443\"",
        "https_bind = \"127.0.0.1:0\"",
      );
    raw.push_str(&format!(
      r#"

[admin]
enabled = {enabled}
bearer_token_env = "{ADMIN_TOKEN_ENV}"
transport = "plaintext_allowlist"
"#
    ));
    if let Some(admin_bind) = admin_bind {
      raw.push_str(&format!("bind = \"{admin_bind}\"\n"));
    }
    parse_test_config(&raw)
  }

  fn plain_http_listener_config(
    cert_path: &Path,
    key_path: &Path,
    https_bind: SocketAddr,
    http_bind: SocketAddr,
    upstream_addr: SocketAddr,
  ) -> Config {
    let mut raw = common::minimal_config_toml(cert_path, key_path)
      .replace("unprivileged_mode = true", "unprivileged_mode = false")
      .replace(
        "https_bind = \"127.0.0.1:8443\"",
        &format!(
          "https_bind = \"{https_bind}\"\nhttp_bind = \"{http_bind}\"\nhttp_mode = \"proxy\""
        ),
      )
      .replace(
        "origin = \"https://app.internal.example\"",
        &format!("origin = \"http://{upstream_addr}/origin\""),
      )
      .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"");
    raw.push_str(
      r#"

[runtime.drain]
graceful_timeout_ms = 1000
long_connection_close_delay_ms = 1000
shutdown_delay_ms = 0
"#,
    );
    parse_test_config(&raw)
  }

  async fn start_delayed_http_upstream(
    response_delay: Duration,
    request_count: usize,
  ) -> (
    SocketAddr,
    JoinHandle<()>,
    tokio::sync::oneshot::Receiver<()>,
  ) {
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("delayed upstream should bind");
    let addr = listener
      .local_addr()
      .expect("delayed upstream address should be available");
    let (first_request_tx, first_request_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
      let mut first_request_tx = Some(first_request_tx);
      for index in 0..request_count {
        let (mut stream, _) = listener
          .accept()
          .await
          .expect("delayed upstream should accept connection");
        read_http_request_headers(&mut stream)
          .await
          .expect("delayed upstream should read request headers");
        if let Some(tx) = first_request_tx.take() {
          let _ = tx.send(());
        }
        tokio::time::sleep(response_delay).await;
        let body = format!("delayed-{index}");
        let response = format!(
          "HTTP/1.1 200 OK\r\n\
           Content-Type: text/plain\r\n\
           Content-Length: {}\r\n\
           Connection: close\r\n\
           \r\n\
           {body}",
          body.len()
        );
        stream
          .write_all(response.as_bytes())
          .await
          .expect("delayed upstream should write response");
      }
    });
    (addr, task, first_request_rx)
  }

  async fn read_http_request_headers(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
      let read = stream.read(&mut chunk).await?;
      if read == 0 {
        return Err(std::io::Error::new(
          std::io::ErrorKind::UnexpectedEof,
          "connection closed before request headers completed",
        ));
      }
      buffer.extend_from_slice(&chunk[..read]);
      if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
        return Ok(());
      }
    }
  }

  async fn raw_http_response(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!(
      "GET {path} HTTP/1.1\r\n\
       Host: example.com\r\n\
       Content-Length: 0\r\n\
       Connection: close\r\n\
       \r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
      .await
      .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response timed out")
      })??;
    Ok(String::from_utf8_lossy(&response).into_owned())
  }

  fn parse_test_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  async fn unused_loopback_ports() -> (SocketAddr, SocketAddr) {
    let first = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("first ephemeral port should bind");
    let second = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("second ephemeral port should bind");
    let first_addr = first
      .local_addr()
      .expect("first ephemeral address should be available");
    let second_addr = second
      .local_addr()
      .expect("second ephemeral address should be available");
    (first_addr, second_addr)
  }

  async fn unused_loopback_port() -> SocketAddr {
    unused_loopback_ports().await.0
  }

  async fn admin_purge_response_with_retry(addr: SocketAddr) -> String {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match admin_purge_response(addr).await {
        Ok(response) if response.starts_with("HTTP/1.1 200 OK") => return response,
        Ok(response) if Instant::now() >= deadline => {
          panic!(
            "admin listener did not return 200 before deadline: {}",
            log_safe_test_text(&response)
          )
        }
        Err(error) if Instant::now() >= deadline => {
          panic!(
            "admin listener did not become ready before deadline with error kind: {:?}",
            error.kind()
          )
        }
        Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
      }
    }
  }

  async fn admin_purge_response(addr: SocketAddr) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr).await?;
    admin_purge_response_on_stream(stream).await
  }

  async fn admin_purge_response_on_stream(mut stream: TcpStream) -> std::io::Result<String> {
    write_admin_purge_request_headers(&mut stream).await?;
    finish_admin_purge_response_on_stream(stream).await
  }

  async fn write_admin_purge_request_headers(stream: &mut TcpStream) -> std::io::Result<()> {
    let token = admin_test_token()?;
    let request_headers = format!(
      "POST /cache/purge?policy=default&scheme=http&host=example.com&uri=/ HTTP/1.1\r\n\
       Host: admin\r\n\
       Authorization: Bearer {token}\r\n\
       Content-Length: 0\r\n\
       Connection: close\r\n"
    );
    stream.write_all(request_headers.as_bytes()).await
  }

  async fn finish_admin_purge_response_on_stream(mut stream: TcpStream) -> std::io::Result<String> {
    stream.write_all(b"\r\n").await?;
    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
      .await
      .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "admin response timed out")
      })??;
    let _ = read;
    Ok(String::from_utf8_lossy(&response).into_owned())
  }

  fn log_safe_test_text(input: &str) -> String {
    input.replace('\n', "\\n").replace('\r', "\\r")
  }

  #[test]
  fn log_safe_test_text_escapes_line_breaks() {
    assert_eq!(
      log_safe_test_text("HTTP/1.1 500\r\nforged: true\nbody"),
      "HTTP/1.1 500\\r\\nforged: true\\nbody"
    );
  }

  fn admin_test_token() -> std::io::Result<String> {
    std::env::var(ADMIN_TOKEN_ENV).map_err(|error| {
      std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{ADMIN_TOKEN_ENV} is required for admin listener tests: {error}"),
      )
    })
  }

  async fn assert_tcp_connect_fails(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      match tokio::time::timeout(Duration::from_millis(100), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
          drop(stream);
          if Instant::now() >= deadline {
            panic!("TCP listener at {addr} stayed reachable");
          }
          tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok(Err(_)) | Err(_) => return,
      }
    }
  }

  #[test]
  fn tls_fingerprint_payload_includes_client_hello_and_selected_tls_metadata() {
    let client_hello = ClientHelloFingerprintMetadata {
      cipher_suites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384".to_string(),
      key_exchange_groups: "X25519,X25519MLKEM768".to_string(),
      signature_schemes: "ECDSA_NISTP256_SHA256,RSA_PSS_SHA256".to_string(),
      data_integrity_groups: "SHA256,SHA384".to_string(),
    };

    let payload = tls_fingerprint_payload(
      &client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_128_GCM_SHA256"),
      Some("X25519MLKEM768"),
      Some("SHA256"),
      Some("example.com"),
      Some("h2"),
    );

    assert!(payload.starts_with("rustls-tcp-negotiated-v2\n"));
    assert!(
      payload.contains("client_hello_cipher_suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384")
    );
    assert!(payload.contains("client_hello_key_exchange_groups=X25519,X25519MLKEM768"));
    assert!(
      payload.contains("client_hello_signature_schemes=ECDSA_NISTP256_SHA256,RSA_PSS_SHA256")
    );
    assert!(payload.contains("client_hello_data_integrity_groups=SHA256,SHA384"));
    assert!(payload.contains("selected_cipher_suite=TLS_AES_128_GCM_SHA256"));
    assert!(payload.contains("selected_key_exchange_group=X25519MLKEM768"));
    assert!(payload.contains("selected_data_integrity_group=SHA256"));
  }

  #[test]
  fn tls_fingerprint_changes_when_client_hello_or_selection_changes() {
    let client_hello = ClientHelloFingerprintMetadata {
      cipher_suites: "TLS_AES_128_GCM_SHA256".to_string(),
      key_exchange_groups: "X25519".to_string(),
      signature_schemes: "ECDSA_NISTP256_SHA256".to_string(),
      data_integrity_groups: "SHA256".to_string(),
    };
    let different_client_hello = ClientHelloFingerprintMetadata {
      cipher_suites: "TLS_AES_256_GCM_SHA384".to_string(),
      key_exchange_groups: "X25519".to_string(),
      signature_schemes: "ECDSA_NISTP256_SHA256".to_string(),
      data_integrity_groups: "SHA384".to_string(),
    };

    let base = tls_fingerprint(
      &client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_128_GCM_SHA256"),
      Some("X25519"),
      Some("SHA256"),
      Some("example.com"),
      Some("h2"),
    );
    let changed_client_hello = tls_fingerprint(
      &different_client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_128_GCM_SHA256"),
      Some("X25519"),
      Some("SHA256"),
      Some("example.com"),
      Some("h2"),
    );
    let changed_selection = tls_fingerprint(
      &client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_256_GCM_SHA384"),
      Some("X25519"),
      Some("SHA384"),
      Some("example.com"),
      Some("h2"),
    );

    assert_eq!(base.len(), 64);
    assert_ne!(base, changed_client_hello);
    assert_ne!(base, changed_selection);
  }

  #[test]
  fn quic_tls_fingerprint_payload_uses_exposed_quic_scheme() {
    let payload = quic_tls_fingerprint_payload(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("example.com"),
      alpn: Some("h3"),
    });

    assert!(payload.starts_with("quinn-rustls-quic-v2\n"));
    assert!(payload.contains("selected_version=TLSv1_3"));
    assert!(payload.contains("selected_cipher_suite="));
    assert!(payload.contains("selected_key_exchange_group="));
    assert!(payload.contains("selected_data_integrity_group="));
    assert!(payload.contains("sni=example.com"));
    assert!(payload.contains("alpn=h3"));
    assert!(payload.contains("metadata_source=quinn-rustls-handshake-data"));
  }

  #[test]
  fn quic_tls_fingerprint_changes_when_exposed_handshake_metadata_changes() {
    let base = quic_tls_fingerprint(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("example.com"),
      alpn: Some("h3"),
    });
    let changed_sni = quic_tls_fingerprint(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("alt.example.com"),
      alpn: Some("h3"),
    });
    let changed_alpn = quic_tls_fingerprint(QuicTlsFingerprintInput {
      version: Some("TLSv1_3"),
      cipher_suite: None,
      key_exchange_group: None,
      data_integrity_group: None,
      sni: Some("example.com"),
      alpn: Some("h3-29"),
    });

    assert_eq!(base.len(), 64);
    assert_ne!(base, changed_sni);
    assert_ne!(base, changed_alpn);
  }

  #[test]
  fn cipher_suite_data_integrity_groups_are_deduplicated_in_order() {
    let groups = unique_nonempty(
      [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
      ]
      .iter()
      .filter_map(|suite| cipher_suite_data_integrity_group(suite))
      .map(str::to_string),
    );

    assert_eq!(groups, vec!["SHA256".to_string(), "SHA384".to_string()]);
  }
}
