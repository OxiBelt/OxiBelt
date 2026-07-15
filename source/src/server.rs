//! Listener supervision and control-plane orchestration for the running proxy.
//! This module binds transports together without owning protocol-specific policy.

use std::collections::BTreeMap;
use std::io::Read as _;
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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{info, warn};

use crate::admin_audit::AdminAuditHandle;
use crate::config::{
  AdminTransportMode, Config, ConnectionLimitIdentityMode, IpmBreakGlassAccessMode,
  RuntimeOverrides,
};
use crate::identity::Cidr;
use crate::lifecycle::{ConnectionDrain, TaskRegistry};
use crate::limits::{ConnectionLimitContext, ConnectionPermit};
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
use crate::overload::ControlPlane;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::{SilentClose, is_silent_close_response, text_response};
use crate::proxy::{http, http3};
use crate::proxy_protocol;
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::runtime_health::RuntimeTaskKind;
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
mod admin_listener;
mod admin_metadata;
mod admin_mutation_resources;
mod admin_mutations;
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
mod h1_fast_proxy;
mod http_io;
mod listener_sets;
mod ops;
mod plain_http;
#[cfg(test)]
mod pod_lifecycle_tests;
mod prefixed_io;
mod process_signals;
#[cfg(test)]
mod reload_tests;
mod rollout_identity;
use admin_auth::{
  AdminActor, AdminAuthentication, AdminAuthorization, admin_authentication, admin_request_context,
};
use admin_control::{AdminControlCommand, AdminControlHandle, RollbackSnapshot};
use admin_operations::AdminOperationRuntime;
use admin_stream_pools::admin_stream_pools_response;
use admin_upstream_pools::admin_upstream_pools_response;
use ops::OpsTasks;
use process_signals::{
  ProcessSignal, ProcessSignals, begin_process_predrain, graceful_process_shutdown,
};
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
  "admin_mutation_replay",
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
  let (admin_control, admin_control_rx) = AdminControlHandle::new(effective_config);
  let admin_operations =
    AdminOperationRuntime::new(state.snapshot().config.admin.operations.clone());
  let mut listeners = ListenerSupervisor::start(
    state.clone(),
    error_tx.clone(),
    admin_control.clone(),
    admin_operations.clone(),
  )
  .await?;
  let mut process_signals = ProcessSignals::new()?;
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
  let admin_control = AdminControlContext {
    receiver: admin_control_rx,
    handle: admin_control,
    runtime_overrides,
  };
  drop(error_tx);
  if let Some(reload) = reload {
    serve_with_reload(
      state,
      &mut listeners,
      &mut error_rx,
      admin_control,
      reload,
      &mut process_signals,
    )
    .await
  } else {
    serve_until_shutdown(
      state,
      &mut listeners,
      &mut error_rx,
      admin_control,
      &mut process_signals,
    )
    .await
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
  let connections = TaskRegistry::new(
    RuntimeTaskKind::AdminConnection,
    state.snapshot().runtime_health.clone(),
  );
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
        let Some(control_connection) = state
          .snapshot()
          .overload
          .try_admit_control_connection(ControlPlane::Admin)
        else {
          continue;
        };
        let admin_control = admin_control.clone();
        let admin_operations = admin_operations.clone();
        connections.spawn(async move {
          let _control_connection = control_connection;
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
  if !admin_audit_gate::listener_current(&snapshot, listener_bind) {
    bail!("admin listener is no longer current");
  }
  let plaintext_allowed = admin_plaintext_allowed(&snapshot, peer_addr);
  let transport = snapshot.config.admin.transport;
  drop(snapshot);
  match transport {
    AdminTransportMode::Tls => {
      admin_listener::handle_admin_tls_connection(
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
      admin_listener::handle_admin_plaintext_connection(
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
      admin_listener::handle_admin_plaintext_connection(
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
      if plaintext_allowed && !admin_listener::tcp_stream_starts_with_tls(&stream).await {
        admin_listener::handle_admin_plaintext_connection(
          stream,
          peer_addr,
          listener_bind,
          state,
          admin_control,
          admin_operations,
        )
        .await
      } else {
        admin_listener::handle_admin_tls_connection(
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

fn admin_plaintext_allowed(snapshot: &AppSnapshot, peer_addr: SocketAddr) -> bool {
  snapshot
    .config
    .admin
    .plaintext_allowed_source_cidrs
    .iter()
    .filter_map(|raw| Cidr::parse(raw).ok())
    .any(|cidr| cidr.contains(peer_addr.ip()))
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
  let Some(_control_request) = state
    .snapshot()
    .overload
    .try_admit_control_request(ControlPlane::Admin)
  else {
    return text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "control capacity exhausted",
    );
  };
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
  admin_audit_gate::commit_response(audit, audit_reservation, response, &state).await
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
  if !admin_audit_gate::listener_current(&snapshot, listener_bind) {
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
  if path == "/cache/purge" || path == "/cache/purge-prefix" || path == "/cache/purge-tag" {
    if method != ::http::Method::POST {
      return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let authentication = match admin_authentication(&request, &snapshot.config, &snapshot.ipm).await
    {
      Ok(authentication) => authentication,
      Err(failure) if snapshot.config.admin.workload_identity.enabled => {
        if !failure.supports_signed_cache_purge() {
          snapshot
            .metrics
            .record_admin_workload_identity_authentication("rejected", failure.reason());
          if let Some(audit) = &audit {
            failure.record_audit(audit);
          }
          return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        match admin::signed_cache_purge_actor(&request, snapshot.as_ref(), &method) {
          Ok(_) => match failure.clone().into_signed_cache_purge_authentication() {
            Some(authentication) => authentication,
            None => {
              snapshot
                .metrics
                .record_admin_workload_identity_authentication("rejected", failure.reason());
              if let Some(audit) = &audit {
                failure.record_audit(audit);
              }
              return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
            }
          },
          Err(error) => {
            snapshot
              .metrics
              .record_admin_workload_identity_authentication("rejected", failure.reason());
            if let Some(audit) = &audit {
              failure.record_audit(audit);
            }
            warn!(error = %error, "rejected unsigned bound admin cache purge request");
            return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
          }
        }
      }
      Err(failure) => match admin::signed_cache_purge_actor(&request, snapshot.as_ref(), &method) {
        Ok(actor) => AdminAuthentication::legacy_signed_cache_purge(actor),
        Err(error) => {
          if let Some(audit) = &audit {
            failure.record_audit(audit);
          }
          warn!(error = %error, "rejected unsigned admin cache purge request");
          return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
      },
    };
    if snapshot.config.admin.workload_identity.enabled {
      snapshot
        .metrics
        .record_admin_workload_identity_authentication("accepted", authentication.reason());
    }
    if let Some(audit) = &audit {
      authentication.record_audit(audit);
    }
    let actor = &authentication.actor;
    let authorization = if let Some(audit) = audit.clone() {
      AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &admin_context, audit)
    } else {
      AdminAuthorization::new(actor, &snapshot.ipm, &admin_context)
    };
    if let Err(response) =
      admin_audit_gate::begin_authenticated_mutation(audit.as_ref(), &state, &method, &path, false)
        .await
    {
      return *response;
    }
    let response =
      admin::cache_purge_response(&snapshot, &params, &path, scheme, peer_addr, &authorization)
        .await;
    return response;
  }

  let authentication = match admin_authentication(&request, &snapshot.config, &snapshot.ipm).await {
    Ok(authentication) => authentication,
    Err(failure) => {
      if snapshot.config.admin.workload_identity.enabled {
        snapshot
          .metrics
          .record_admin_workload_identity_authentication("rejected", failure.reason());
      }
      if let Some(audit) = &audit {
        failure.record_audit(audit);
      }
      return text_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
  };
  if snapshot.config.admin.workload_identity.enabled {
    snapshot
      .metrics
      .record_admin_workload_identity_authentication("accepted", authentication.reason());
  }
  if let Some(audit) = &audit {
    authentication.record_audit(audit);
  }
  let authenticated_with_break_glass = authentication.authenticated_with_break_glass();
  let actor = &authentication.actor;
  if authenticated_with_break_glass
    && snapshot.config.ipm.break_glass.access_mode == IpmBreakGlassAccessMode::TwoFactorActivation
    && !admin_mutations::break_glass_activation_bootstrap_route(&method, &path)
  {
    match snapshot
      .admin_mutations
      .active_break_glass_activation(&actor.principal)
      .await
    {
      Ok(Some(activation)) if activation.scopes.iter().any(|scope| scope == "admin") => {}
      Ok(_) => return text_response(StatusCode::FORBIDDEN, "break-glass activation is required"),
      Err(error) => {
        warn!(error = %error, "failed to verify break-glass activation");
        return text_response(
          StatusCode::SERVICE_UNAVAILABLE,
          "break-glass activation store is unavailable",
        );
      }
    }
  }
  let authorization = if let Some(audit) = audit.clone() {
    AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &admin_context, audit)
  } else {
    AdminAuthorization::new(actor, &snapshot.ipm, &admin_context)
  };

  let handled_by_mutation_runtime =
    admin_mutations::handles(&snapshot.admin_mutations, &method, &path, request.headers());
  if let Err(response) = admin_audit_gate::begin_authenticated_mutation(
    audit.as_ref(),
    &state,
    &method,
    &path,
    handled_by_mutation_runtime,
  )
  .await
  {
    return *response;
  }

  if handled_by_mutation_runtime {
    return admin_mutations::response(
      request,
      state.clone(),
      admin_control.clone(),
      &authorization,
      authenticated_with_break_glass,
      &method,
      &path,
    )
    .await;
  }

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
      snapshot.config.rollout.blocks_per_pod_mutation(),
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

  if path == "/admin/v1/waf/rulepacks/plan" {
    return admin_rulepacks::plan_response(request, &snapshot.config, &authorization, &method)
      .await;
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

struct AdminControlContext {
  receiver: mpsc::UnboundedReceiver<AdminControlCommand>,
  handle: AdminControlHandle,
  runtime_overrides: RuntimeOverrides,
}

async fn serve_until_shutdown(
  state: AppHandle,
  listeners: &mut ListenerSupervisor,
  error_rx: &mut mpsc::UnboundedReceiver<anyhow::Error>,
  mut admin_control: AdminControlContext,
  process_signals: &mut ProcessSignals,
) -> anyhow::Result<()> {
  let mut rollback: Option<RollbackSnapshot> = None;
  loop {
    tokio::select! {
      result = process_signals.recv() => {
          match result? {
            ProcessSignal::PreDrain => begin_process_predrain(&state, listeners),
            ProcessSignal::Shutdown => return graceful_process_shutdown(&state, listeners).await,
          }
      }
      Some(error) = error_rx.recv() => return Err(error),
      Some(command) = admin_control.receiver.recv() => {
        admin_control::handle_admin_control_command(
          command,
          &state,
          listeners,
          &admin_control.handle,
          &admin_control.runtime_overrides,
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
  mut admin_control: AdminControlContext,
  mut reload: ReloadManager,
  process_signals: &mut ProcessSignals,
) -> anyhow::Result<()> {
  #[cfg(unix)]
  let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    .context("failed to install SIGHUP listener")?;

  let mut rollback: Option<RollbackSnapshot> = None;
  loop {
    let poll_sleep = tokio::time::sleep(reload.poll_interval());
    tokio::pin!(poll_sleep);
    tokio::select! {
        result = process_signals.recv() => {
            match result? {
              ProcessSignal::PreDrain => begin_process_predrain(&state, listeners),
              ProcessSignal::Shutdown => return graceful_process_shutdown(&state, listeners).await,
            }
        }
        Some(error) = error_rx.recv() => return Err(error),
        Some(command) = admin_control.receiver.recv() => {
            admin_control::handle_admin_control_command(
              command,
              &state,
              listeners,
              &admin_control.handle,
              &admin_control.runtime_overrides,
              &mut rollback,
            ).await;
        }
        _ = &mut poll_sleep, if !state.snapshot().lifecycle.is_shutdown_draining() => {
            reload.reload_if_changed(ReloadTrigger::Poll, &state, listeners).await;
        }
        _ = hup.recv(), if !state.snapshot().lifecycle.is_shutdown_draining() => {
            reload.reload_if_changed(ReloadTrigger::Signal, &state, listeners).await;
        }
    }
  }
}

pub(crate) struct ListenerSupervisor {
  tcp: BTreeMap<SocketAddr, TcpListenerTask>,
  http: BTreeMap<SocketAddr, TcpListenerTask>,
  http3: BTreeMap<SocketAddr, Http3ListenerTask>,
  admin: Option<AdminListenerTask>,
  admin_h3: Option<admin_h3::AdminHttp3ListenerTask>,
  streams: Vec<StreamListenerTask>,
  turns: Vec<TurnListenerTask>,
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
  admin_control: AdminControlHandle,
  admin_operations: AdminOperationRuntime,
  quiescing: bool,
}

struct TcpListenerTask {
  options: TcpListenOptions,
  quiesce: watch::Sender<bool>,
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
  quiesce: watch::Sender<bool>,
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
  tcp: Option<listener_sets::PendingTcpListenerSetUpdate>,
  http: Option<listener_sets::PendingTcpListenerSetUpdate>,
  http3: Option<listener_sets::PendingHttp3ListenerSetUpdate>,
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
      tcp: BTreeMap::new(),
      http: BTreeMap::new(),
      http3: BTreeMap::new(),
      admin: None,
      admin_h3: None,
      streams: Vec::new(),
      turns: Vec::new(),
      error_tx,
      admin_control,
      admin_operations,
      quiescing: false,
    };
    let pending = supervisor.prepare(&snapshot).await?;
    supervisor.commit(pending, &snapshot, state);
    Ok(supervisor)
  }

  pub(crate) async fn prepare(
    &self,
    snapshot: &AppSnapshot,
  ) -> anyhow::Result<PendingListenerUpdate> {
    if self.quiescing {
      bail!("data-plane listeners are quiescing");
    }
    let tcp_options = TcpListenOptions::from(&snapshot.config.runtime.accept);
    let desired_tcp = if snapshot.config.needs_https_listener() {
      snapshot.config.listeners.https_binds.clone()
    } else {
      Vec::new()
    };
    let tcp = listener_sets::prepare_tcp_listener_set_update(
      &self.tcp,
      desired_tcp,
      tcp_options,
      snapshot.config.runtime.accept.accept_error_backoff_ms,
      TcpListenerKind::Https,
    )?;

    let desired_http =
      if snapshot.config.listeners.http_mode != crate::config::HttpListenerMode::Off {
        snapshot.config.listeners.http_binds.clone()
      } else {
        Vec::new()
      };
    let http = listener_sets::prepare_tcp_listener_set_update(
      &self.http,
      desired_http,
      tcp_options,
      snapshot.config.runtime.accept.accept_error_backoff_ms,
      TcpListenerKind::PlainHttp,
    )?;

    let desired_http3 = if snapshot.config.listeners.http3 {
      snapshot.config.listeners.https_binds.clone()
    } else {
      Vec::new()
    };
    let (http3, refresh_http3_config) =
      listener_sets::prepare_http3_listener_set_update(&self.http3, desired_http3, snapshot)?;

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
      .map(|listener| (listener.clone(), tcp_options))
      .collect::<Vec<_>>();
    let current_turns = self
      .turns
      .iter()
      .map(|listener| {
        let key = listener.listener_key();
        (key.config.clone(), key.tcp_options)
      })
      .collect::<Vec<_>>();
    let turns = if desired_turns != current_turns {
      let mut bound = Vec::with_capacity(snapshot.config.webrtc_turn_listeners.len());
      for listener in &snapshot.config.webrtc_turn_listeners {
        bound.push(BoundTurnListener::bind(
          listener.clone(),
          tcp_options,
          Duration::from_millis(snapshot.config.runtime.accept.accept_error_backoff_ms),
          &snapshot.config.crypto,
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
    if let Some(tcp) = pending.tcp {
      listener_sets::commit_tcp_listener_set_update(
        &mut self.tcp,
        tcp,
        state.clone(),
        self.error_tx.clone(),
        drain_timeouts,
      );
    }
    if let Some(http) = pending.http {
      listener_sets::commit_tcp_listener_set_update(
        &mut self.http,
        http,
        state.clone(),
        self.error_tx.clone(),
        drain_timeouts,
      );
    }
    match pending.http3 {
      Some(http3) => {
        listener_sets::commit_http3_listener_set_update(
          &mut self.http3,
          http3,
          snapshot,
          state.clone(),
          self.error_tx.clone(),
          drain_timeouts,
        );
      }
      None if pending.refresh_http3_config => {
        listener_sets::refresh_http3_server_config(&self.http3, snapshot);
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
    self.quiesce();
    let drain_timeouts = DrainTimeouts::from_snapshot(snapshot);
    let mut tasks = Vec::new();
    for task in std::mem::take(&mut self.tcp).into_values() {
      tasks.push(task.drain());
    }
    for task in std::mem::take(&mut self.http).into_values() {
      tasks.push(task.drain());
    }
    for task in std::mem::take(&mut self.http3).into_values() {
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

  fn quiesce(&mut self) {
    self.quiescing = true;
    for task in self.tcp.values() {
      task.quiesce();
    }
    for task in self.http.values() {
      task.quiesce();
    }
    for task in self.http3.values() {
      task.quiesce();
    }
    for task in &self.streams {
      task.quiesce();
    }
    for task in &self.turns {
      task.quiesce();
    }
  }
}

impl Drop for ListenerSupervisor {
  fn drop(&mut self) {
    for task in std::mem::take(&mut self.tcp).into_values() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.http).into_values() {
      task.drain_background();
    }
    for task in std::mem::take(&mut self.http3).into_values() {
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
  fn quiesce(&self) {
    let _ = self.quiesce.send(true);
  }

  fn drain_background(self) {
    drop(self.drain());
  }

  fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let TcpListenerTask {
        quiesce,
        shutdown,
        connections,
        drain_timeouts,
        tasks,
        ..
      } = self;
      let _ = quiesce.send(true);
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
    let (quiesce, quiesce_rx) = watch::channel(false);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let options = self.options;
    let kind = self.kind;
    let accept_error_backoff = self.accept_error_backoff;
    let connections = TaskRegistry::new(
      RuntimeTaskKind::HttpConnection,
      state.snapshot().runtime_health.clone(),
    );
    let tasks = self
      .listeners
      .into_iter()
      .enumerate()
      .map(|(worker_index, listener)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_quiesce = quiesce_rx.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        let worker_connections = connections.clone();
        tokio::spawn(async move {
          if let Err(error) = serve_tcp(
            listener,
            kind,
            worker_state,
            worker_quiesce,
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
      options,
      quiesce,
      shutdown,
      connections,
      drain_timeouts,
      tasks,
    }
  }
}

impl Http3ListenerTask {
  fn quiesce(&self) {
    let _ = self.quiesce.send(true);
  }

  fn drain_background(self) {
    drop(self.drain());
  }

  fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let Http3ListenerTask {
        endpoints,
        quiesce,
        shutdown,
        connections,
        drain_timeouts,
        tasks,
        ..
      } = self;
      let _ = quiesce.send(true);
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
    let (quiesce, quiesce_rx) = watch::channel(false);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let socket = self.socket;
    let transport = self.transport;
    let connections = TaskRegistry::new(
      RuntimeTaskKind::HttpConnection,
      state.snapshot().runtime_health.clone(),
    );
    let mut tasks = crate::sni_forward::quic::spawn_demux_tasks(
      self.sni_forward_quic,
      quiesce_rx.clone(),
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
          let worker_quiesce = quiesce_rx.clone();
          let worker_state = state.clone();
          let worker_error_tx = error_tx.clone();
          let worker_connections = connections.clone();
          tokio::spawn(async move {
            if let Err(error) = serve_http3(
              endpoint,
              worker_state,
              worker_quiesce,
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
      quiesce,
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
  mut quiesce: watch::Receiver<bool>,
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
        changed = quiesce.changed() => {
            if changed.is_err() || *quiesce.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream TCP listener quiesced");
              return Ok(());
            }
        }
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
            let overload_connection = match connection_snapshot.overload.try_admit_connection() {
              Ok(lease) => lease,
              Err(_) => continue,
            };
            let connection_drain = ConnectionDrain::with_data_plane(
              connection_shutdown.clone(),
              connection_snapshot.lifecycle.subscribe(),
              data_plane_drain.clone(),
              long_connection_close_delay,
            );
            connections.spawn(async move {
                let _overload_connection = overload_connection;
                let result = match kind {
                  TcpListenerKind::Https => handle_connection(
                    stream,
                    peer_addr,
                    bind,
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
  mut quiesce: watch::Receiver<bool>,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
) -> anyhow::Result<()> {
  let bind = endpoint
    .local_addr()
    .context("failed to read HTTP/3 listener address")?;
  let mut shutting_down = *shutdown.borrow();
  let mut quiescing = *quiesce.borrow() || shutting_down;
  info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener started");

  loop {
    tokio::select! {
        biased;
        changed = quiesce.changed() => {
            if changed.is_err() || *quiesce.borrow() {
              if !quiescing {
                info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener quiesced");
              }
              quiescing = true;
            }
        }
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, worker = worker_index, "downstream HTTP/3 listener stopped");
            }
            quiescing = true;
            shutting_down = true;
        }
        _ = connections.wait_idle(), if shutting_down => {
            // `Endpoint::close` is safe only after every accepted connection has
            // finished. It then prevents a final race from re-queuing an Initial
            // after this worker stops consuming `endpoint.accept()`.
            endpoint.close(0u32.into(), b"listener drained");
            return Ok(());
        }
        connecting = endpoint.accept() => {
            let Some(connecting) = connecting else {
                return Ok(());
            };
            if quiescing {
                // The endpoint driver continues receiving QUIC Initial packets while
                // established connections drain. Consume every queued Incoming so an
                // unauthenticated peer cannot accumulate Quinn's pending-handshake
                // buffer during pre-drain, but retain already accepted connections.
                connecting.ignore();
                continue;
            }
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
            let overload_connection = match connection_snapshot.overload.try_admit_connection() {
                Ok(lease) => lease,
                Err(_) => {
                    connecting.refuse();
                    continue;
                }
            };
            let connection_shutdown = shutdown.clone();
            let connection_drain = ConnectionDrain::with_data_plane(
              connection_shutdown.clone(),
              connection_snapshot.lifecycle.subscribe(),
              data_plane_drain.clone(),
              long_connection_close_delay,
            );
            let peer_addr = connecting.remote_address();
            connections.spawn(async move {
                let _overload_connection = overload_connection;
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
  listener_bind: SocketAddr,
  handshake_state: Arc<AppSnapshot>,
  mut shutdown: watch::Receiver<bool>,
  mut data_plane_drain: watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let _global_permit = acquire_global_connection_permit(&handshake_state).await?;
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
    Some(acquire_ip_connection_permit(&handshake_state, peer_addr).await?)
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
  let tls_server_config = handshake_state
    .tls_server_config
    .select(&start.client_hello());
  let mut tls_stream = tokio::time::timeout(
    Duration::from_millis(handshake_state.config.limits.tls_handshake_timeout_ms),
    start.into_stream(tls_server_config),
  )
  .await
  .context("TLS handshake timed out")?
  .context("TLS handshake failed")?;
  let mut early_data_prefix = Vec::new();
  if let Some(mut early_data) = tls_stream.get_mut().1.early_data() {
    early_data
      .read_to_end(&mut early_data_prefix)
      .context("failed to read accepted TLS early data")?;
  }
  let tcp_early_data = !early_data_prefix.is_empty();

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
  let h1_forwarded_header_cache = forwarded_header_cache.clone();
  let h1_tls_metadata = tls_metadata.clone();
  let h1_request_count = request_count.clone();
  let request_state = handshake_state.clone();
  let request_drain = drain.clone();
  let service = service_fn(move |mut request: hyper::Request<Incoming>| {
    let state = request_state.clone();
    let tls_metadata = tls_metadata.clone();
    let forwarded_header_cache = forwarded_header_cache.clone();
    let request_index = request_count.fetch_add(1, Ordering::Relaxed);
    let connection_limit_context = connection_limit_context.clone();
    let drain = request_drain.clone();
    async move {
      request
        .extensions_mut()
        .insert(http::DownstreamListenerBind(listener_bind));
      if tcp_early_data {
        http::early_data::mark_verified(&mut request);
      }
      let _request_guard = state.runtime_introspection_guard(request_counter);
      if request_index >= state.config.limits.max_requests_per_connection {
        return Ok(text_response(
          StatusCode::TOO_MANY_REQUESTS,
          "too many requests on this connection",
        ));
      }
      let response = http::handle_with_forwarded_header_cache(
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
      .await;
      if is_silent_close_response(&response) {
        Err(SilentClose)
      } else {
        Ok(response)
      }
    }
  });

  if negotiated == b"h2" {
    let _http2_connection_guard =
      handshake_state.runtime_introspection_guard(RuntimeCounter::Http2Connection);
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    crate::h2_tuning::apply_server_defaults(&mut builder, &handshake_state.config.proxy.http2);
    builder.max_header_list_size(handshake_state.config.limits.max_total_header_bytes as u32);
    let io = prefixed_io::PrefixedIo::new(tls_stream, early_data_prefix);
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    let mut graceful_drain = drain;
    if graceful_drain.is_graceful_connection_draining() {
      connection.as_mut().graceful_shutdown();
    }
    let result = tokio::select! {
      result = &mut connection => result,
      _ = graceful_drain.wait_for_graceful_connection_drain() => {
        connection.as_mut().graceful_shutdown();
        (&mut connection).await
      }
    };
    result.map_err(|error| anyhow::anyhow!(error))?;
  } else {
    let _http1_connection_guard =
      handshake_state.runtime_introspection_guard(RuntimeCounter::Http1Connection);
    let (io, served_requests) = if tcp_early_data {
      (
        prefixed_io::PrefixedIo::new(tls_stream, early_data_prefix),
        0,
      )
    } else {
      let Some((io, served_requests)) = h1_fast_proxy::try_handle_connection(
        tls_stream,
        peer_addr,
        listener_bind,
        &handshake_state,
        tcp_max_hop,
        h1_tls_metadata,
        transport_metadata,
        h1_forwarded_header_cache.as_ref(),
        &mut shutdown,
        &mut data_plane_drain,
      )
      .await?
      .into_continue() else {
        return Ok(());
      };
      (io, served_requests)
    };
    h1_request_count.store(served_requests, Ordering::Relaxed);
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
    let io =
      http_io::InstrumentedDownstreamIo::new(io, handshake_state.metrics.clone(), "h1", "tls");
    let connection = builder.serve_connection(TokioIo::new(io), service);
    let mut graceful_drain = drain;
    let result = if handshake_state.http1_upgrades_possible {
      let connection = connection.with_upgrades();
      tokio::pin!(connection);
      if graceful_drain.is_graceful_connection_draining() {
        connection.as_mut().graceful_shutdown();
      }
      tokio::select! {
        result = &mut connection => result,
        _ = graceful_drain.wait_for_graceful_connection_drain() => {
          connection.as_mut().graceful_shutdown();
          (&mut connection).await
        }
      }
    } else {
      tokio::pin!(connection);
      if graceful_drain.is_graceful_connection_draining() {
        connection.as_mut().graceful_shutdown();
      }
      tokio::select! {
        result = &mut connection => result,
        _ = graceful_drain.wait_for_graceful_connection_drain() => {
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

async fn acquire_global_connection_permit(
  snapshot: &AppSnapshot,
) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_global_connection_async(&snapshot.config.limits)
    .await
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))
}

async fn acquire_ip_connection_permit(
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_ip_connection_async(
      peer_addr.ip(),
      &snapshot.config.limits,
      &snapshot.config.connection_limits,
    )
    .await
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
  hex_encode(&crate::crypto::sha256(payload.as_bytes()))
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
  hex_encode(&crate::crypto::sha256(payload.as_bytes()))
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
