//! HTTP/3 admin listener support.
//! Admin H3 reuses the same authorization path as TCP admin endpoints.

use std::net::SocketAddr;
use std::time::Duration;

use ::http::{Request, Response, StatusCode};
use anyhow::Context;
use bytes::Bytes;
use h3_webtransport::server::WebTransportSession;
use tokio::io::AsyncWriteExt;
use tokio::sync::{OwnedSemaphorePermit, broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::admin_audit::{AdminAuditHandle, AdminAuditReservation};
use crate::config::{QuicSocketConfig, QuicTransportConfig};
use crate::lifecycle::TaskRegistry;
use crate::overload::ControlPlane;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::proxy::http3::{is_webtransport_request, respond_to_h3_request};
use crate::state::{AppHandle, AppSnapshot};

use super::admin_auth::{AdminAuthorization, admin_authentication, admin_request_context};
use super::admin_operations::{
  AdminOperationError, AdminOperationEvent, AdminOperationRuntime, can_access_operation,
  encode_ndjson_event, parse_operation_id,
};
use super::{admin_error, connection_errors};

type AdminH3BidiStream = crate::quic::h3::BidiStream<Bytes>;
type AdminH3RequestStream = h3::server::RequestStream<AdminH3BidiStream, Bytes>;
type AdminH3Connection = h3::server::Connection<crate::quic::h3::Connection, Bytes>;
type AdminWebTransportSession = WebTransportSession<crate::quic::h3::Connection, Bytes>;

const TERMINAL_EVENT_DRAIN_DELAY: Duration = Duration::from_millis(250);

pub(super) struct AdminHttp3ListenerTask {
  bind: SocketAddr,
  socket: QuicSocketConfig,
  transport: QuicTransportConfig,
  endpoints: Vec<h3_quinn::quinn::Endpoint>,
  shutdown: watch::Sender<bool>,
  connections: TaskRegistry,
  graceful_timeout: Duration,
  tasks: Vec<JoinHandle<()>>,
}

pub(super) struct BoundAdminHttp3Listener {
  bind: SocketAddr,
  socket: QuicSocketConfig,
  transport: QuicTransportConfig,
  endpoints: Vec<h3_quinn::quinn::Endpoint>,
}

impl AdminHttp3ListenerTask {
  pub(super) fn matches(
    &self,
    bind: SocketAddr,
    socket: &QuicSocketConfig,
    transport: &QuicTransportConfig,
  ) -> bool {
    self.bind == bind && self.socket == *socket && self.transport == *transport
  }

  pub(super) fn refresh_server_config(&self, config: h3_quinn::quinn::ServerConfig) {
    for endpoint in &self.endpoints {
      endpoint.set_server_config(Some(config.clone()));
    }
    info!(bind = %self.bind, "admin HTTP/3 TLS config refreshed");
  }

  pub(super) fn drain_background(self) {
    drop(self.drain());
  }

  pub(super) fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let AdminHttp3ListenerTask {
        endpoints,
        shutdown,
        connections,
        graceful_timeout,
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
      if tokio::time::timeout(graceful_timeout, wait).await.is_err() {
        for endpoint in endpoints {
          endpoint.close(0u32.into(), b"admin h3 listener drain timeout");
        }
        connections.abort_all();
      }
    })
  }
}

impl BoundAdminHttp3Listener {
  pub(super) fn bind(bind: SocketAddr, snapshot: &AppSnapshot) -> anyhow::Result<Self> {
    let server_config = snapshot
      .admin_quic_server_config
      .clone()
      .ok_or_else(|| anyhow::anyhow!("admin HTTP/3 listener is enabled without QUIC TLS config"))?;
    let endpoints = crate::quic::bind_server_endpoints(
      bind,
      server_config,
      &snapshot.config.quic,
      snapshot.config.source_paths.cert_dir.as_deref(),
    )
    .with_context(|| format!("failed to bind admin HTTP/3 listener to {bind}"))?;
    Ok(Self {
      bind,
      socket: snapshot.config.quic.socket.clone(),
      transport: snapshot.config.quic.downstream.transport.clone(),
      endpoints,
    })
  }

  pub(super) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
    admin_operations: AdminOperationRuntime,
    graceful_timeout: Duration,
  ) -> AdminHttp3ListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let socket = self.socket;
    let transport = self.transport;
    let connections = TaskRegistry::default();
    let tasks = self
      .endpoints
      .iter()
      .cloned()
      .enumerate()
      .map(|(worker_index, endpoint)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        let worker_connections = connections.clone();
        let worker_operations = admin_operations.clone();
        tokio::spawn(async move {
          if let Err(error) = serve_admin_http3(
            endpoint,
            bind,
            worker_state,
            worker_operations,
            worker_shutdown,
            worker_index,
            worker_connections,
          )
          .await
          {
            let _ = worker_error_tx.send(error.context("admin HTTP/3 listener failed"));
          }
        })
      })
      .collect();
    AdminHttp3ListenerTask {
      bind,
      socket,
      transport,
      endpoints: self.endpoints,
      shutdown,
      connections,
      graceful_timeout,
      tasks,
    }
  }
}

async fn serve_admin_http3(
  endpoint: h3_quinn::quinn::Endpoint,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_operations: AdminOperationRuntime,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  connections: TaskRegistry,
) -> anyhow::Result<()> {
  let bind = endpoint
    .local_addr()
    .context("failed to read admin HTTP/3 listener address")?;
  info!(bind = %bind, worker = worker_index, "admin HTTP/3 listener started");

  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(bind = %bind, worker = worker_index, "admin HTTP/3 listener stopped");
        }
        return Ok(());
      }
      connecting = endpoint.accept() => {
        let Some(connecting) = connecting else {
          return Ok(());
        };
        let peer_addr = connecting.remote_address();
        let Some(control_connection) = state
          .snapshot()
          .overload
          .try_admit_control_connection(ControlPlane::Admin)
        else {
          connecting.refuse();
          continue;
        };
        let connection_state = state.clone();
        let connection_operations = admin_operations.clone();
        let connection_shutdown = shutdown.clone();
        connections.spawn(async move {
          let _control_connection = control_connection;
          match connecting.await {
            Ok(connection) => {
              if let Err(error) = handle_admin_http3_connection(
                connection,
                listener_bind,
                connection_state,
                connection_operations,
                connection_shutdown,
              )
              .await
              {
                connection_errors::log_http3(peer_addr, &error);
              }
            }
            Err(error) => {
              warn!(error = %error, "failed to accept admin HTTP/3 connection");
            }
          }
        });
      }
    }
  }
}

async fn handle_admin_http3_connection(
  connection: h3_quinn::quinn::Connection,
  listener_bind: SocketAddr,
  state: AppHandle,
  admin_operations: AdminOperationRuntime,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let peer_addr = connection.remote_address();
  let client_certificate = connection
    .peer_identity()
    .and_then(|identity| {
      identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()
    })
    .and_then(|certificates| crate::tls::verified_client_certificate(&certificates));
  let early_data = crate::quic::h3::EarlyDataTracker::default();
  let quic_connection = crate::quic::h3::Connection::new(connection, early_data);
  let mut h3_connection = h3::server::builder()
    .enable_extended_connect(true)
    .enable_datagram(true)
    .enable_webtransport(true)
    .max_webtransport_sessions(admin_operations.config().webtransport_max_sessions as u64)
    .build(quic_connection)
    .await
    .context("failed to establish admin HTTP/3 connection")?;

  loop {
    if *shutdown.borrow() {
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
      accepted = h3_connection.accept() => {
        accepted.context("failed to accept admin HTTP/3 request")?
      }
    };
    let Some(resolver) = resolver else {
      return Ok(());
    };

    let (mut request, stream) = resolver
      .resolve_request()
      .await
      .context("failed to resolve admin HTTP/3 request")?;
    if let Some(client_certificate) = &client_certificate {
      request.extensions_mut().insert(client_certificate.clone());
    }
    let path = request.uri().path().to_string();
    if matches_operation_event_webtransport_path(&path) && is_webtransport_request(&request) {
      let Some(_control_request) = state
        .snapshot()
        .overload
        .try_admit_control_request(ControlPlane::Admin)
      else {
        respond_to_h3_request(
          stream,
          text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "control capacity exhausted",
          ),
        )
        .await?;
        continue;
      };
      return handle_operation_event_webtransport(
        request,
        stream,
        h3_connection,
        listener_bind,
        peer_addr,
        state,
        admin_operations,
      )
      .await;
    }

    let response = admin_http3_response(
      &mut request,
      &state,
      &admin_operations,
      peer_addr,
      listener_bind,
      &path,
    )
    .await;
    let status = response.status();
    respond_to_h3_request(stream, response).await?;
    debug!(peer = %peer_addr, %status, path, "handled admin HTTP/3 request");
  }
}

async fn admin_http3_response(
  request: &mut Request<()>,
  state: &AppHandle,
  operations: &AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  path: &str,
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
  let (audit, reservation) = match begin_admin_h3_audit(request, state, peer_addr) {
    Ok(value) => value,
    Err(response) => return *response,
  };
  let response =
    admin_http3_response_inner(request, state, operations, peer_addr, listener_bind, path).await;
  finalize_admin_h3_response(response, audit, reservation).await
}

async fn admin_http3_response_inner(
  request: &Request<()>,
  state: &AppHandle,
  operations: &AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  path: &str,
) -> Response<ProxyBody> {
  let snapshot = state.snapshot();
  if !admin_http3_listener_current(&snapshot, listener_bind) {
    return text_response(StatusCode::NOT_FOUND, "not found");
  }
  if !matches_operation_event_webtransport_path(path) {
    return text_response(StatusCode::NOT_FOUND, "not found");
  }
  if request.method() != ::http::Method::CONNECT {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  if !operations.config().webtransport {
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "WebTransport operation events are disabled",
    );
  }
  if !is_webtransport_request(request) {
    return text_response(StatusCode::BAD_REQUEST, "WebTransport CONNECT required");
  }

  let context = admin_request_context(request, peer_addr);
  let audit = AdminAuditHandle::from_request(request);
  let authentication = match admin_authentication(request, &snapshot.config, &snapshot.ipm).await {
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
  let actor = &authentication.actor;
  let authorization = if let Some(audit) = audit {
    AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &context, audit)
  } else {
    AdminAuthorization::new(actor, &snapshot.ipm, &context)
  };
  let operation_id = match operation_id_from_webtransport_path(path) {
    Ok(id) => id,
    Err(error) => return text_response(StatusCode::BAD_REQUEST, &error.to_string()),
  };
  let Some((_, _, operation)) = operations.subscribe(operation_id).await else {
    return text_response(StatusCode::NOT_FOUND, "not found");
  };
  if !can_access_operation(&authorization, &operation, "admin:ReadOperation") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  text_response(StatusCode::BAD_REQUEST, "WebTransport CONNECT required")
}

async fn handle_operation_event_webtransport(
  mut request: Request<()>,
  stream: AdminH3RequestStream,
  h3_connection: AdminH3Connection,
  listener_bind: SocketAddr,
  peer_addr: SocketAddr,
  state: AppHandle,
  operations: AdminOperationRuntime,
) -> anyhow::Result<()> {
  let (audit, reservation) = match begin_admin_h3_audit(&mut request, &state, peer_addr) {
    Ok(value) => value,
    Err(response) => {
      respond_to_h3_request(stream, *response).await?;
      return Ok(());
    }
  };
  let response =
    prepare_operation_event_webtransport(&request, &state, &operations, peer_addr, listener_bind)
      .await;
  let (history, receiver, permit) = match response {
    Ok(value) => value,
    Err(response) => {
      let response = finalize_admin_h3_response(response, audit, reservation).await;
      respond_to_h3_request(stream, response).await?;
      return Ok(());
    }
  };

  let session = match WebTransportSession::accept(request, stream, h3_connection).await {
    Ok(session) => session,
    Err(error) => {
      let event = audit.finish_with_error(
        StatusCode::BAD_REQUEST,
        "failed to accept WebTransport session",
      );
      reservation.commit(event);
      return Err(anyhow::anyhow!(
        "failed to accept admin WebTransport session: {error}"
      ));
    }
  };
  reservation.commit(audit.finish(StatusCode::OK));
  write_operation_events(session, history, receiver, permit).await
}

async fn prepare_operation_event_webtransport(
  request: &Request<()>,
  state: &AppHandle,
  operations: &AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
) -> Result<
  (
    Vec<AdminOperationEvent>,
    broadcast::Receiver<AdminOperationEvent>,
    OwnedSemaphorePermit,
  ),
  Response<ProxyBody>,
> {
  let snapshot = state.snapshot();
  if !admin_http3_listener_current(&snapshot, listener_bind) {
    return Err(text_response(StatusCode::NOT_FOUND, "not found"));
  }
  if !operations.config().webtransport {
    return Err(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "WebTransport operation events are disabled",
    ));
  }
  let operation_id = operation_id_from_webtransport_path(request.uri().path())
    .map_err(|error| text_response(StatusCode::BAD_REQUEST, &error.to_string()))?;
  let context = admin_request_context(request, peer_addr);
  let audit = AdminAuditHandle::from_request(request);
  let authentication = match admin_authentication(request, &snapshot.config, &snapshot.ipm).await {
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
      return Err(text_response(StatusCode::UNAUTHORIZED, "unauthorized"));
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
  let actor = &authentication.actor;
  let authorization = if let Some(audit) = audit {
    AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &context, audit)
  } else {
    AdminAuthorization::new(actor, &snapshot.ipm, &context)
  };
  let Some((history, receiver, operation)) = operations.subscribe(operation_id).await else {
    return Err(text_response(StatusCode::NOT_FOUND, "not found"));
  };
  if !can_access_operation(&authorization, &operation, "admin:ReadOperation") {
    return Err(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  let permit = operations
    .try_acquire_webtransport_session()
    .map_err(operation_webtransport_error_response)?;
  Ok((history, receiver, permit))
}

async fn write_operation_events(
  session: AdminWebTransportSession,
  history: Vec<AdminOperationEvent>,
  mut receiver: broadcast::Receiver<AdminOperationEvent>,
  _permit: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
  let mut stream = session
    .open_uni(session.session_id())
    .await
    .context("failed to open admin WebTransport event stream")?;
  for event in history {
    let terminal = event.operation.state.is_terminal();
    stream
      .write_all(&encode_ndjson_event(&event))
      .await
      .context("failed to write admin WebTransport operation history")?;
    if terminal {
      stream
        .shutdown()
        .await
        .context("failed to close admin WebTransport operation event stream")?;
      tokio::time::sleep(TERMINAL_EVENT_DRAIN_DELAY).await;
      return Ok(());
    }
  }

  let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
  loop {
    tokio::select! {
      biased;
      received = receiver.recv() => {
        match received {
          Ok(event) => {
            let terminal = event.operation.state.is_terminal();
            stream
              .write_all(&encode_ndjson_event(&event))
              .await
              .context("failed to write admin WebTransport operation event")?;
            if terminal {
              stream
                .shutdown()
                .await
                .context("failed to close admin WebTransport operation event stream")?;
              tokio::time::sleep(TERMINAL_EVENT_DRAIN_DELAY).await;
              return Ok(());
            }
          }
          Err(broadcast::error::RecvError::Lagged(_)) => {
            anyhow::bail!("admin WebTransport operation event stream lagged");
          }
          Err(broadcast::error::RecvError::Closed) => {
            stream
              .shutdown()
              .await
              .context("failed to close admin WebTransport operation event stream")?;
            tokio::time::sleep(TERMINAL_EVENT_DRAIN_DELAY).await;
            return Ok(());
          }
        }
      }
      _ = heartbeat.tick() => {
        stream
          .write_all(br#"{"event":"heartbeat"}"#)
          .await
          .context("failed to write admin WebTransport heartbeat")?;
        stream
          .write_all(b"\n")
          .await
          .context("failed to write admin WebTransport heartbeat newline")?;
      }
    }
  }
}

fn begin_admin_h3_audit<B>(
  request: &mut Request<B>,
  state: &AppHandle,
  peer_addr: SocketAddr,
) -> Result<(AdminAuditHandle, AdminAuditReservation), Box<Response<ProxyBody>>> {
  let method = request.method().clone();
  let path = request.uri().path().to_string();
  let query = request.uri().query().map(str::to_string);
  let audit = AdminAuditHandle::new(peer_addr, "https", &method, &path, query.as_deref());
  let audit_runtime = state.snapshot().admin_audit.clone();
  let reservation = audit_runtime.reserve().map_err(|error| {
    let event = audit.finish_with_error(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "admin audit unavailable",
    );
    audit_runtime.emit_unstored(event, &error);
    Box::new(admin_error::error_envelope_response(
      ::http::StatusCode::SERVICE_UNAVAILABLE,
      "admin audit unavailable",
      &audit.request_id(),
      None,
    ))
  })?;
  request.extensions_mut().insert(audit.clone());
  Ok((audit, reservation))
}

async fn finalize_admin_h3_response(
  response: Response<ProxyBody>,
  audit: AdminAuditHandle,
  reservation: AdminAuditReservation,
) -> Response<ProxyBody> {
  let response = admin_error::finalize_response(response, &audit).await;
  reservation.commit(audit.finish(response.status()));
  response
}

fn operation_webtransport_error_response(error: AdminOperationError) -> Response<ProxyBody> {
  match error {
    AdminOperationError::Disabled => text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "WebTransport operation events are disabled",
    ),
    AdminOperationError::QueueFull => text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "too many active WebTransport operation event sessions",
    ),
    AdminOperationError::StoreFull
    | AdminOperationError::NotFound
    | AdminOperationError::AlreadyTerminal => {
      text_response(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
    }
  }
}

fn matches_operation_event_webtransport_path(path: &str) -> bool {
  path.starts_with("/admin/v1/operations/") && path.ends_with("/events/wt")
}

fn operation_id_from_webtransport_path(path: &str) -> anyhow::Result<&str> {
  let Some(rest) = path.strip_prefix("/admin/v1/operations/") else {
    anyhow::bail!("not an operation event WebTransport endpoint");
  };
  let mut segments = rest.split('/');
  match (
    segments.next(),
    segments.next(),
    segments.next(),
    segments.next(),
  ) {
    (Some(id), Some("events"), Some("wt"), None) => parse_operation_id(id),
    _ => anyhow::bail!("not an operation event WebTransport endpoint"),
  }
}

pub(super) fn configured_bind(snapshot: &AppSnapshot) -> SocketAddr {
  snapshot
    .config
    .admin
    .http3
    .bind
    .unwrap_or(snapshot.config.admin.bind)
}

fn admin_http3_listener_current(snapshot: &AppSnapshot, listener_bind: SocketAddr) -> bool {
  snapshot.config.admin.enabled
    && snapshot.config.admin.http3.enabled
    && configured_bind(snapshot) == listener_bind
}
