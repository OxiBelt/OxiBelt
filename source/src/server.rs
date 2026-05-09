use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::{Response, StatusCode};
use anyhow::{Context, bail};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ring::digest;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::config::{
  AdminConfig, AdminRole, AdminTransportMode, ConnectionLimitIdentityMode, HttpListenerMode,
  RuntimeOverrides, UpstreamPoolServerConfig, UpstreamPoolServerSource, UpstreamPoolServerState,
};
use crate::identity::Cidr;
use crate::limits::{ConnectionLimitContext, ConnectionPermit};
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
use crate::pool_health;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::proxy::{http, http3};
use crate::proxy_protocol;
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::{BoundStreamListener, StreamListenerTask};
use crate::tcp_hop;
use crate::upstream_control;
use crate::waf::WafTlsMetadata;

const TCP_TLS_FINGERPRINT_SCHEME: &str = "rustls-tcp-negotiated-v2";
const QUIC_TLS_FINGERPRINT_SCHEME: &str = "quinn-rustls-quic-v2";

pub async fn serve(
  state: AppHandle,
  config_path: Option<PathBuf>,
  runtime_overrides: RuntimeOverrides,
) -> anyhow::Result<()> {
  let (error_tx, mut error_rx) = mpsc::unbounded_channel();
  let mut listeners = ListenerSupervisor::start(state.clone(), error_tx.clone()).await?;
  let _ops = OpsTasks::start(state.clone(), error_tx.clone()).await?;
  let reload = if state.snapshot().config.runtime.hot_reload.mode.enabled() {
    match config_path {
      Some(config_path) => Some(ReloadManager::new(
        config_path,
        runtime_overrides,
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
    serve_with_reload(state, &mut listeners, &mut error_rx, reload).await
  } else {
    serve_until_shutdown(&mut error_rx).await
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
      let body = snapshot.metrics.prometheus(snapshot.cache.stats());
      text_response(StatusCode::OK, &body)
    }
    OpsKind::Health => {
      let snapshot = state.snapshot();
      let path = request.uri().path();
      if path == snapshot.config.health.ready_path {
        text_response(StatusCode::OK, "ready")
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
        let state = state.clone();
        tokio::spawn(async move {
          if let Err(error) = handle_admin_connection(stream, peer_addr, configured_bind, state).await {
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
      handle_admin_tls_connection(stream, peer_addr, listener_bind, state).await
    }
    AdminTransportMode::Plaintext => {
      handle_admin_plaintext_connection(stream, peer_addr, listener_bind, state).await
    }
    AdminTransportMode::PlaintextAllowlist if plaintext_allowed => {
      handle_admin_plaintext_connection(stream, peer_addr, listener_bind, state).await
    }
    AdminTransportMode::PlaintextAllowlist => {
      bail!("admin plaintext connection from {peer_addr} is not allowlisted");
    }
    AdminTransportMode::Auto => {
      if plaintext_allowed && !tcp_stream_starts_with_tls(&stream).await {
        handle_admin_plaintext_connection(stream, peer_addr, listener_bind, state).await
      } else {
        handle_admin_tls_connection(stream, peer_addr, listener_bind, state).await
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
    "https",
  )
  .await
}

async fn handle_admin_plaintext_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
) -> anyhow::Result<()> {
  serve_admin_http1(
    TokioIo::new(stream),
    peer_addr,
    listener_bind,
    state,
    "http",
  )
  .await
}

async fn serve_admin_http1<I>(
  io: TokioIo<I>,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  state: AppHandle,
  scheme: &'static str,
) -> anyhow::Result<()>
where
  I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    async move {
      Ok::<_, Infallible>(admin_response(request, state, peer_addr, listener_bind, scheme).await)
    }
  });
  hyper::server::conn::http1::Builder::new()
    .serve_connection(io, service)
    .await
    .map_err(|error| anyhow::anyhow!(error))
}

async fn admin_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  scheme: &'static str,
) -> Response<ProxyBody> {
  let snapshot = state.snapshot();
  if !admin_listener_current(&snapshot, listener_bind) {
    return text_response(StatusCode::NOT_FOUND, "not found");
  }
  let Some(actor) = admin_actor(&request, &snapshot.config.admin) else {
    return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
  };
  let method = request.method().clone();
  let uri = request.uri().clone();
  let query = uri.query().unwrap_or_default();
  let params = url::form_urlencoded::parse(query.as_bytes())
    .into_owned()
    .collect::<std::collections::HashMap<_, _>>();
  let path = uri.path().to_string();

  if path == "/cache/purge" || path == "/cache/purge-prefix" {
    if !admin_actor_has_role(&actor, AdminRole::CacheOperator) {
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
    if method != ::http::Method::POST {
      return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let response = admin_cache_purge_response(&snapshot, &params, &path, scheme, peer_addr, &actor);
    return response;
  }

  if let Some(response) = admin_waf_response(snapshot.as_ref(), &actor, &method, &path) {
    return response;
  }

  if let Some(response) = admin_upstream_pools_response(
    request,
    state,
    snapshot.as_ref(),
    peer_addr,
    &actor,
    &method,
    &path,
  )
  .await
  {
    return response;
  }

  text_response(StatusCode::NOT_FOUND, "not found")
}

fn admin_waf_response(
  snapshot: &AppSnapshot,
  actor: &AdminActor,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/waf/rule-hits" {
    return None;
  }
  if !admin_actor_has_role(actor, AdminRole::Viewer) {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  if *method != ::http::Method::GET {
    return Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    ));
  }
  Some(json_response(
    StatusCode::OK,
    &json!({ "rules": snapshot.waf.rule_hit_snapshots() }),
  ))
}

#[derive(Debug, Clone)]
struct AdminActor {
  name: String,
  roles: Vec<AdminRole>,
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

fn admin_cache_purge_response(
  snapshot: &AppSnapshot,
  params: &std::collections::HashMap<String, String>,
  path: &str,
  scheme: &'static str,
  peer_addr: SocketAddr,
  actor: &AdminActor,
) -> Response<ProxyBody> {
  let policy = params
    .get("policy")
    .map(String::as_str)
    .unwrap_or("default");
  let purge_scheme = params.get("scheme").map(String::as_str).unwrap_or(scheme);
  let Some(host) = params.get("host").map(String::as_str) else {
    admin_audit(
      peer_addr,
      actor,
      "cache_purge",
      None,
      None,
      AdminAuditOutcome::Rejected,
      Some("missing host"),
    );
    return text_response(StatusCode::BAD_REQUEST, "missing host");
  };
  let purged = match path {
    "/cache/purge" => {
      let Some(uri) = params.get("uri").map(String::as_str) else {
        admin_audit(
          peer_addr,
          actor,
          "cache_purge",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing uri"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing uri");
      };
      snapshot.cache.purge_exact(policy, purge_scheme, host, uri)
    }
    "/cache/purge-prefix" => {
      let Some(path_prefix) = params.get("path_prefix").map(String::as_str) else {
        admin_audit(
          peer_addr,
          actor,
          "cache_purge_prefix",
          None,
          None,
          AdminAuditOutcome::Rejected,
          Some("missing path_prefix"),
        );
        return text_response(StatusCode::BAD_REQUEST, "missing path_prefix");
      };
      snapshot
        .cache
        .purge_prefix(policy, purge_scheme, host, path_prefix)
    }
    _ => unreachable!("admin cache purge path checked before dispatch"),
  };
  snapshot.metrics.record_cache_purge();
  admin_audit(
    peer_addr,
    actor,
    if path == "/cache/purge" {
      "cache_purge"
    } else {
      "cache_purge_prefix"
    },
    None,
    None,
    AdminAuditOutcome::Applied,
    None,
  );
  info!(peer = %peer_addr, actor = %actor.name, policy, purged, "admin cache purge completed");
  text_response(StatusCode::OK, &format!("purged={purged}\n"))
}

async fn admin_upstream_pools_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path == "/admin/v1/upstream-pools" {
    if !admin_actor_has_any_role(
      actor,
      &[
        AdminRole::Viewer,
        AdminRole::UpstreamOperator,
        AdminRole::Admin,
      ],
    ) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    return Some(json_response(StatusCode::OK, &snapshot.pools.snapshots()));
  }

  let rest = path.strip_prefix("/admin/v1/upstream-pools/")?;
  let segments = rest.split('/').collect::<Vec<_>>();
  if segments.len() == 1 {
    if !admin_actor_has_any_role(
      actor,
      &[
        AdminRole::Viewer,
        AdminRole::UpstreamOperator,
        AdminRole::Admin,
      ],
    ) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::GET {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    let Some(pool) = snapshot.pools.snapshot(segments[0]) else {
      return Some(text_response(StatusCode::NOT_FOUND, "not found"));
    };
    return Some(json_response(StatusCode::OK, &pool));
  }

  if segments.len() == 2 && segments[1] == "servers" {
    if !admin_actor_has_role(actor, AdminRole::UpstreamOperator) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    if *method != ::http::Method::POST {
      return Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ));
    }
    return Some(
      admin_add_pool_server(request, &state, peer_addr, actor, segments[0].to_string()).await,
    );
  }

  if segments.len() == 3 && segments[1] == "servers" {
    if !admin_actor_has_role(actor, AdminRole::UpstreamOperator) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
    return Some(
      admin_mutate_pool_server(
        request,
        &state,
        peer_addr,
        actor,
        method,
        segments[0].to_string(),
        segments[2].to_string(),
      )
      .await,
    );
  }

  Some(text_response(StatusCode::NOT_FOUND, "not found"))
}

#[derive(Debug, Deserialize)]
struct AdminAddPoolServerRequest {
  id: String,
  origin: url::Url,
  #[serde(default = "default_admin_pool_server_weight")]
  weight: u32,
  #[serde(default)]
  max_conns: usize,
  #[serde(default)]
  backup: bool,
  #[serde(default)]
  state: UpstreamPoolServerState,
}

fn default_admin_pool_server_weight() -> u32 {
  1
}

#[derive(Debug, Deserialize)]
struct AdminPatchPoolServerRequest {
  #[serde(default)]
  state: Option<UpstreamPoolServerState>,
  #[serde(default)]
  weight: Option<u32>,
  #[serde(default)]
  max_conns: Option<usize>,
  #[serde(default)]
  backup: Option<bool>,
}

async fn admin_add_pool_server(
  request: hyper::Request<Incoming>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
) -> Response<ProxyBody> {
  let body = match collect_admin_json::<AdminAddPoolServerRequest>(request).await {
    Ok(body) => body,
    Err(response) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_add",
        Some(&pool_name),
        None,
        AdminAuditOutcome::Rejected,
        Some("invalid request body"),
      );
      return response;
    }
  };
  let server_id = body.id.clone();
  let result = upstream_control::apply_runtime_pool_update(state, |config| {
    let pool = upstream_control::find_pool_mut(config, &pool_name)?;
    upstream_control::ensure_unique_server_id(pool, &server_id)?;
    let mut server = UpstreamPoolServerConfig {
      id: Some(server_id.clone()),
      origin: body.origin,
      weight: body.weight,
      max_conns: body.max_conns,
      backup: body.backup,
      state: body.state,
      source: UpstreamPoolServerSource::Admin,
    };
    if server.weight == 0 {
      bail!("upstream pool server weight must be greater than 0");
    }
    server.source = UpstreamPoolServerSource::Admin;
    pool.servers.push(server);
    Ok(())
  })
  .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_add",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Applied,
        None,
      );
      json_response(StatusCode::CREATED, &json!({ "ok": true }))
    }
    Err(error) => {
      let message = error.to_string();
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_add",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      text_response(StatusCode::BAD_REQUEST, &message)
    }
  }
}

async fn admin_mutate_pool_server(
  request: hyper::Request<Incoming>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  method: &::http::Method,
  pool_name: String,
  server_id: String,
) -> Response<ProxyBody> {
  if *method == ::http::Method::PATCH {
    return admin_patch_pool_server(request, state, peer_addr, actor, pool_name, server_id).await;
  }
  if *method == ::http::Method::DELETE {
    return admin_delete_pool_server(state, peer_addr, actor, pool_name, server_id).await;
  }
  text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

async fn admin_patch_pool_server(
  request: hyper::Request<Incoming>,
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  server_id: String,
) -> Response<ProxyBody> {
  let body = match collect_admin_json::<AdminPatchPoolServerRequest>(request).await {
    Ok(body) => body,
    Err(response) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some("invalid request body"),
      );
      return response;
    }
  };
  let result = upstream_control::apply_runtime_pool_update(state, |config| {
    let pool = upstream_control::find_pool_mut(config, &pool_name)?;
    let (_, server) = upstream_control::find_server_mut(pool, &server_id)?;
    if let Some(state) = body.state {
      server.state = state;
    }
    if let Some(weight) = body.weight {
      if weight == 0 {
        bail!("upstream pool server weight must be greater than 0");
      }
      server.weight = weight;
    }
    if let Some(max_conns) = body.max_conns {
      server.max_conns = max_conns;
    }
    if let Some(backup) = body.backup {
      server.backup = backup;
    }
    Ok(())
  })
  .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Applied,
        None,
      );
      json_response(StatusCode::OK, &json!({ "ok": true }))
    }
    Err(error) => {
      let message = error.to_string();
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_patch",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      text_response(StatusCode::BAD_REQUEST, &message)
    }
  }
}

async fn admin_delete_pool_server(
  state: &AppHandle,
  peer_addr: SocketAddr,
  actor: &AdminActor,
  pool_name: String,
  server_id: String,
) -> Response<ProxyBody> {
  let result = upstream_control::apply_runtime_pool_update(state, |config| {
    let pool = upstream_control::find_pool_mut(config, &pool_name)?;
    let index = pool
      .servers
      .iter()
      .enumerate()
      .find(|(index, server)| crate::config::upstream_pool_server_id(*index, server) == server_id)
      .map(|(index, _)| index)
      .with_context(|| format!("unknown upstream pool server {server_id}"))?;
    if pool.servers[index].source != UpstreamPoolServerSource::Admin {
      bail!("only admin-managed upstream pool servers can be deleted");
    }
    pool.servers.remove(index);
    Ok(())
  })
  .await;
  match result {
    Ok(()) => {
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_delete",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Applied,
        None,
      );
      json_response(StatusCode::OK, &json!({ "ok": true }))
    }
    Err(error) => {
      let message = error.to_string();
      admin_audit(
        peer_addr,
        actor,
        "upstream_server_delete",
        Some(&pool_name),
        Some(&server_id),
        AdminAuditOutcome::Rejected,
        Some(&message),
      );
      text_response(StatusCode::BAD_REQUEST, &message)
    }
  }
}

async fn collect_admin_json<T>(request: hyper::Request<Incoming>) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> Deserialize<'de>,
{
  let bytes = request
    .into_body()
    .collect()
    .await
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "failed to read request body"))?
    .to_bytes();
  if bytes.len() > 64 * 1024 {
    return Err(text_response(
      StatusCode::PAYLOAD_TOO_LARGE,
      "request body is too large",
    ));
  }
  serde_json::from_slice(&bytes)
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid JSON request body"))
}

fn admin_actor(request: &hyper::Request<Incoming>, config: &AdminConfig) -> Option<AdminActor> {
  let actual = request
    .headers()
    .get(::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Bearer "))?;
  if std::env::var(&config.bearer_token_env)
    .ok()
    .is_some_and(|expected| !expected.is_empty() && expected == actual)
  {
    return Some(AdminActor {
      name: "admin".to_string(),
      roles: vec![AdminRole::Admin],
    });
  }
  for token in &config.rbac.tokens {
    if std::env::var(&token.bearer_token_env)
      .ok()
      .is_some_and(|expected| !expected.is_empty() && expected == actual)
    {
      return Some(AdminActor {
        name: token.name.clone(),
        roles: token.roles.clone(),
      });
    }
  }
  None
}

fn admin_actor_has_role(actor: &AdminActor, role: AdminRole) -> bool {
  actor.roles.contains(&AdminRole::Admin) || actor.roles.contains(&role)
}

fn admin_actor_has_any_role(actor: &AdminActor, roles: &[AdminRole]) -> bool {
  actor.roles.contains(&AdminRole::Admin) || roles.iter().any(|role| actor.roles.contains(role))
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
    roles = ?actor.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
    operation,
    pool,
    server,
    outcome = outcome.as_str(),
    error,
    "admin operation audit"
  );
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<ProxyBody> {
  match serde_json::to_vec(value) {
    Ok(bytes) => {
      let body = http_body_util::Full::new(bytes::Bytes::from(bytes))
        .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
        .boxed();
      let mut response = Response::new(body);
      *response.status_mut() = status;
      response.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        ::http::HeaderValue::from_static("application/json"),
      );
      response
    }
    Err(error) => text_response(
      StatusCode::INTERNAL_SERVER_ERROR,
      &format!("failed to encode JSON response: {error}"),
    ),
  }
}

async fn serve_until_shutdown(
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
) -> anyhow::Result<()> {
  tokio::select! {
      result = tokio::signal::ctrl_c() => {
          result.context("failed to wait for ctrl_c signal")?;
          info!("shutdown signal received");
          Ok(())
      }
      Some(error) = error_rx.recv() => Err(error),
  }
}

async fn serve_with_reload(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  mut reload: ReloadManager,
) -> anyhow::Result<()> {
  #[cfg(unix)]
  let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    .context("failed to install SIGHUP listener")?;

  loop {
    let poll_sleep = tokio::time::sleep(reload.poll_interval());
    tokio::pin!(poll_sleep);
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("failed to wait for ctrl_c signal")?;
            info!("shutdown signal received");
            return Ok(());
        }
        Some(error) = error_rx.recv() => return Err(error),
        _ = &mut poll_sleep => {
            reload.reload_if_changed(ReloadTrigger::Poll, &state, listeners).await;
        }
        _ = hup.recv() => {
            reload.reload_if_changed(ReloadTrigger::Signal, &state, listeners).await;
        }
    }
  }
}

pub(crate) struct ListenerSupervisor {
  tcp: Option<TcpListenerTask>,
  http: Option<TcpListenerTask>,
  http3: Option<Http3ListenerTask>,
  admin: Option<AdminListenerTask>,
  streams: Vec<StreamListenerTask>,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
}

struct TcpListenerTask {
  bind: SocketAddr,
  options: TcpListenOptions,
  shutdown: watch::Sender<bool>,
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
  endpoints: Vec<h3_quinn::quinn::Endpoint>,
  shutdown: watch::Sender<bool>,
  tasks: Vec<JoinHandle<()>>,
}

struct BoundHttp3Listener {
  bind: SocketAddr,
  socket: crate::config::QuicSocketConfig,
  endpoints: Vec<h3_quinn::quinn::Endpoint>,
}

struct AdminListenerTask {
  bind: SocketAddr,
  shutdown: watch::Sender<bool>,
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
  streams: Option<Vec<BoundStreamListener>>,
  refresh_http3_config: bool,
}

impl ListenerSupervisor {
  async fn start(
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    let mut supervisor = Self {
      tcp: None,
      http: None,
      http3: None,
      admin: None,
      streams: Vec::new(),
      error_tx,
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
    let tcp = if snapshot.config.listeners.http1 || snapshot.config.listeners.http2 {
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
      if self
        .http3
        .as_ref()
        .is_some_and(|task| task.bind == bind && task.socket == snapshot.config.quic.socket)
      {
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

    let desired_streams = snapshot
      .config
      .stream_listeners
      .iter()
      .map(|listener| (listener.name.clone(), listener.bind))
      .collect::<Vec<_>>();
    let current_streams = self
      .streams
      .iter()
      .map(|listener| (listener.name.clone(), listener.bind, listener.options))
      .collect::<Vec<_>>();
    let desired_streams_with_options = desired_streams
      .iter()
      .map(|(name, bind)| (name.clone(), *bind, tcp_options))
      .collect::<Vec<_>>();
    let streams = if desired_streams_with_options != current_streams {
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

    Ok(PendingListenerUpdate {
      tcp,
      http,
      http3,
      admin,
      streams,
      refresh_http3_config,
    })
  }

  pub(crate) fn commit(
    &mut self,
    pending: PendingListenerUpdate,
    snapshot: &AppSnapshot,
    state: AppHandle,
  ) {
    match pending.tcp {
      Some(Some(tcp)) => {
        let tcp = tcp.start(state.clone(), self.error_tx.clone());
        if let Some(old) = self.tcp.replace(tcp) {
          old.shutdown();
        }
      }
      Some(None) => {
        if let Some(old) = self.tcp.take() {
          old.shutdown();
        }
      }
      None => {}
    }
    match pending.http {
      Some(Some(http)) => {
        let http = http.start(state.clone(), self.error_tx.clone());
        if let Some(old) = self.http.replace(http) {
          old.shutdown();
        }
      }
      Some(None) => {
        if let Some(old) = self.http.take() {
          old.shutdown();
        }
      }
      None => {}
    }
    match pending.http3 {
      Some(Some(http3)) => {
        let http3 = http3.start(state.clone(), self.error_tx.clone());
        if let Some(old) = self.http3.replace(http3) {
          old.shutdown();
        }
      }
      Some(None) => {
        if let Some(old) = self.http3.take() {
          old.shutdown();
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
        let admin = admin.start(state.clone(), self.error_tx.clone());
        if let Some(old) = self.admin.replace(admin) {
          old.shutdown();
        }
      }
      Some(None) => {
        if let Some(old) = self.admin.take() {
          old.shutdown();
        }
      }
      None => {}
    }
    if let Some(streams) = pending.streams {
      let old = std::mem::take(&mut self.streams);
      for task in old {
        task.shutdown();
      }
      self.streams = streams
        .into_iter()
        .map(|stream| stream.start(state.clone(), self.error_tx.clone()))
        .collect();
    }
  }
}

impl Drop for ListenerSupervisor {
  fn drop(&mut self) {
    if let Some(task) = self.tcp.take() {
      task.shutdown();
    }
    if let Some(task) = self.http.take() {
      task.shutdown();
    }
    if let Some(task) = self.http3.take() {
      task.shutdown();
    }
    if let Some(task) = self.admin.take() {
      task.shutdown();
    }
    for task in std::mem::take(&mut self.streams) {
      task.shutdown();
    }
  }
}

impl TcpListenerTask {
  fn shutdown(self) {
    let _ = self.shutdown.send(true);
    for task in self.tasks {
      task.abort();
    }
  }
}

impl BoundTcpListener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> TcpListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let options = self.options;
    let kind = self.kind;
    let accept_error_backoff = self.accept_error_backoff;
    let tasks = self
      .listeners
      .into_iter()
      .enumerate()
      .map(|(worker_index, listener)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        tokio::spawn(async move {
          if let Err(error) = serve_tcp(
            listener,
            kind,
            worker_state,
            worker_shutdown,
            worker_index,
            accept_error_backoff,
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
      tasks,
    }
  }
}

impl Http3ListenerTask {
  fn shutdown(self) {
    let _ = self.shutdown.send(true);
    for endpoint in self.endpoints {
      endpoint.close(0u32.into(), b"listener reload");
    }
    for task in self.tasks {
      task.abort();
    }
  }
}

impl BoundHttp3Listener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> Http3ListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let socket = self.socket;
    let tasks = self
      .endpoints
      .iter()
      .cloned()
      .enumerate()
      .map(|(worker_index, endpoint)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        tokio::spawn(async move {
          if let Err(error) =
            serve_http3(endpoint, worker_state, worker_shutdown, worker_index).await
          {
            let _ = worker_error_tx.send(error.context("downstream HTTP/3 listener failed"));
          }
        })
      })
      .collect();
    Http3ListenerTask {
      bind,
      socket,
      endpoints: self.endpoints,
      shutdown,
      tasks,
    }
  }
}

impl AdminListenerTask {
  fn shutdown(self) {
    let _ = self.shutdown.send(true);
    self.task.abort();
  }
}

impl BoundAdminListener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> AdminListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let task = tokio::spawn(async move {
      if let Err(error) = serve_admin_listener(self.listener, bind, state, shutdown_rx).await {
        let _ = error_tx.send(error.context("admin listener failed"));
      }
    });
    AdminListenerTask {
      bind,
      shutdown,
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
  let listeners = bind_tcp_listeners(bind, options, "downstream")
    .with_context(|| format!("failed to bind downstream listener to {bind}"))?;
  Ok(BoundTcpListener {
    bind,
    options,
    accept_error_backoff: Duration::from_millis(accept_error_backoff_ms),
    kind,
    listeners,
  })
}

async fn bind_admin_listener(bind: SocketAddr) -> anyhow::Result<BoundAdminListener> {
  let listener = TcpListener::bind(bind)
    .await
    .with_context(|| format!("failed to bind admin listener to {bind}"))?;
  Ok(BoundAdminListener { bind, listener })
}

async fn serve_tcp(
  listener: TcpListener,
  kind: TcpListenerKind,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  accept_error_backoff: Duration,
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

            let connection_state = state.clone();
            tokio::spawn(async move {
                let result = match kind {
                  TcpListenerKind::Https => handle_connection(stream, peer_addr, connection_state).await,
                  TcpListenerKind::PlainHttp => handle_plain_http_connection(stream, peer_addr, connection_state).await,
                };
                if let Err(error) = result {
                    warn!(peer = %peer_addr, error = %error, "downstream connection closed with error");
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
  let endpoints = crate::quic::bind_server_endpoints(
    bind,
    server_config,
    &snapshot.config.quic,
    snapshot.config.source_paths.cert_dir.as_deref(),
  )?;
  Ok(BoundHttp3Listener {
    bind,
    socket: snapshot.config.quic.socket.clone(),
    endpoints,
  })
}

async fn serve_http3(
  endpoint: h3_quinn::quinn::Endpoint,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
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
            if state.snapshot().config.quic.retry && !connecting.remote_address_validated() && connecting.may_retry() {
                if let Err(error) = connecting.retry() {
                    warn!(error = %error, "failed to send QUIC Retry packet");
                }
                continue;
            }
            let connection_state = state.clone();
            tokio::spawn(async move {
                match connecting.await {
                    Ok(connection) => {
                        if let Err(error) = http3::handle_downstream_connection(connection, connection_state).await {
                            warn!(error = %error, "HTTP/3 downstream connection closed with error");
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
  }
}

async fn handle_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  state: AppHandle,
) -> anyhow::Result<()> {
  let handshake_state = state.snapshot();
  let _global_permit = acquire_global_connection_permit(&handshake_state)?;
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
  let tls_metadata = Arc::new(downstream_tls_metadata(
    tls_stream.get_ref().1,
    &client_hello_metadata,
  ));

  let request_count = Arc::new(AtomicUsize::new(0));
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    let tls_metadata = tls_metadata.clone();
    let request_count = request_count.clone();
    let connection_limit_context = connection_limit_context.clone();
    async move {
      Ok::<_, Infallible>(
        if request_count.fetch_add(1, Ordering::Relaxed)
          >= state.snapshot().config.limits.max_requests_per_connection
        {
          text_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests on this connection",
          )
        } else {
          http::handle(
            request,
            peer_addr,
            tcp_max_hop,
            tls_metadata,
            connection_limit_context.clone(),
            state,
            "https",
          )
          .await
        },
      )
    }
  });

  if negotiated == b"h2" {
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    builder.max_header_list_size(handshake_state.config.limits.max_total_header_bytes as u32);
    builder.keep_alive_timeout(Duration::from_millis(
      handshake_state.config.limits.client_idle_timeout_ms,
    ));
    builder
      .serve_connection(TokioIo::new(tls_stream), service)
      .await
      .map_err(|error| {
        error!(peer = %peer_addr, error = %error, "HTTP/2 downstream connection failed");
        anyhow::anyhow!(error)
      })?;
  } else {
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
    builder
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

async fn handle_plain_http_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  state: AppHandle,
) -> anyhow::Result<()> {
  let snapshot = state.snapshot();
  let _global_permit = acquire_global_connection_permit(&snapshot)?;
  let connection_limit_identity = snapshot.config.limits.connection_limit_identity;
  let proxy_mode = snapshot.config.listeners.http_mode == HttpListenerMode::Proxy;
  let _ip_permit =
    if connection_limit_identity == ConnectionLimitIdentityMode::ProxyProtocol || !proxy_mode {
      Some(acquire_ip_connection_permit(&snapshot, peer_addr)?)
    } else {
      None
    };
  let connection_limit_context =
    (connection_limit_identity == ConnectionLimitIdentityMode::FirstRequestRealIp && proxy_mode)
      .then(ConnectionLimitContext::default);
  let request_count = Arc::new(AtomicUsize::new(0));
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    let request_count = request_count.clone();
    let connection_limit_context = connection_limit_context.clone();
    async move {
      let response = match state.snapshot().config.listeners.http_mode {
        crate::config::HttpListenerMode::RedirectToHttps => redirect_to_https(&request),
        crate::config::HttpListenerMode::Proxy => {
          if request_count.fetch_add(1, Ordering::Relaxed)
            >= state.snapshot().config.limits.max_requests_per_connection
          {
            text_response(
              StatusCode::TOO_MANY_REQUESTS,
              "too many requests on this connection",
            )
          } else {
            http::handle(
              request,
              peer_addr,
              None,
              Arc::new(WafTlsMetadata::default()),
              connection_limit_context.clone(),
              state,
              "http",
            )
            .await
          }
        }
        crate::config::HttpListenerMode::Off => {
          text_response(StatusCode::NOT_FOUND, "HTTP listener is disabled")
        }
      };
      Ok::<_, Infallible>(response)
    }
  });
  let mut builder = hyper::server::conn::http1::Builder::new();
  builder
    .timer(TokioTimer::new())
    .header_read_timeout(Duration::from_millis(
      snapshot.config.limits.client_header_timeout_ms,
    ))
    .max_headers(snapshot.config.limits.max_headers)
    .max_buf_size(snapshot.config.limits.max_total_header_bytes.max(8192))
    .keep_alive(true);
  builder
    .serve_connection(TokioIo::new(stream), service)
    .with_upgrades()
    .await
    .map_err(|error| {
      error!(peer = %peer_addr, error = %error, "plain HTTP downstream connection failed");
      anyhow::anyhow!(error)
    })?;
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

  #[test]
  fn admin_rbac_role_checks_match_endpoint_scopes() {
    let viewer = AdminActor {
      name: "viewer".to_string(),
      roles: vec![AdminRole::Viewer],
    };
    let upstream_operator = AdminActor {
      name: "upstream".to_string(),
      roles: vec![AdminRole::UpstreamOperator],
    };
    let admin = AdminActor {
      name: "admin".to_string(),
      roles: vec![AdminRole::Admin],
    };

    assert!(admin_actor_has_any_role(
      &viewer,
      &[
        AdminRole::Viewer,
        AdminRole::UpstreamOperator,
        AdminRole::Admin
      ]
    ));
    assert!(!admin_actor_has_role(&viewer, AdminRole::UpstreamOperator));
    assert!(admin_actor_has_role(
      &upstream_operator,
      AdminRole::UpstreamOperator
    ));
    assert!(admin_actor_has_role(&admin, AdminRole::CacheOperator));
    assert!(admin_actor_has_role(&admin, AdminRole::UpstreamOperator));
  }

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
    let task = tokio::spawn(serve_admin_listener(listener, addr, state, shutdown_rx));

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
    let mut supervisor = ListenerSupervisor::start(state.clone(), error_tx)
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
    let mut supervisor = ListenerSupervisor::start(state.clone(), error_tx)
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
