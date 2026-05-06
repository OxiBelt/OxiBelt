use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::{Response, StatusCode};
use anyhow::Context;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ring::digest;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{error, info, warn};

use crate::config::RuntimeOverrides;
use crate::limits::ConnectionPermit;
use crate::pool_health;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::proxy::{http, http3};
use crate::proxy_protocol;
use crate::reload::{ReloadManager, ReloadTrigger};
use crate::state::{AppHandle, AppSnapshot};
use crate::tcp_hop;
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
      let task_error = error_tx;
      tasks.push(tokio::spawn(async move {
        if let Err(error) = serve_ops_listener(listener, task_state, rx, OpsKind::Health).await {
          let _ = task_error.send(error.context("health listener failed"));
        }
      }));
    }
    let (tx, rx) = watch::channel(false);
    shutdown.push(tx);
    let task_state = state;
    tasks.push(tokio::spawn(async move {
      pool_health::run_pool_health_checks(task_state, rx).await;
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
      let body = state.snapshot().metrics.prometheus();
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
  error_tx: mpsc::UnboundedSender<anyhow::Error>,
}

struct TcpListenerTask {
  bind: SocketAddr,
  shutdown: watch::Sender<bool>,
  task: JoinHandle<()>,
}

struct BoundTcpListener {
  bind: SocketAddr,
  kind: TcpListenerKind,
  listener: TcpListener,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpListenerKind {
  Https,
  PlainHttp,
}

struct Http3ListenerTask {
  bind: SocketAddr,
  endpoint: h3_quinn::quinn::Endpoint,
  shutdown: watch::Sender<bool>,
  task: JoinHandle<()>,
}

struct BoundHttp3Listener {
  bind: SocketAddr,
  endpoint: h3_quinn::quinn::Endpoint,
}

pub(crate) struct PendingListenerUpdate {
  tcp: Option<Option<BoundTcpListener>>,
  http: Option<Option<BoundTcpListener>>,
  http3: Option<Option<BoundHttp3Listener>>,
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
    let tcp = if snapshot.config.listeners.http1 || snapshot.config.listeners.http2 {
      let bind = snapshot.config.listeners.https_bind;
      if self.tcp.as_ref().map(|task| task.bind) == Some(bind) {
        None
      } else {
        Some(Some(bind_tcp_listener(bind, TcpListenerKind::Https).await?))
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
      if self.http.as_ref().map(|task| task.bind) == Some(bind) {
        None
      } else {
        Some(Some(
          bind_tcp_listener(bind, TcpListenerKind::PlainHttp).await?,
        ))
      }
    } else if self.http.is_some() {
      Some(None)
    } else {
      None
    };

    let (http3, refresh_http3_config) = if snapshot.config.listeners.http3 {
      let bind = snapshot.config.listeners.https_bind;
      if self.http3.as_ref().map(|task| task.bind) == Some(bind) {
        (None, true)
      } else {
        (Some(Some(bind_http3_listener(bind, snapshot)?)), false)
      }
    } else if self.http3.is_some() {
      (Some(None), false)
    } else {
      (None, false)
    };

    Ok(PendingListenerUpdate {
      tcp,
      http,
      http3,
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
        let http3 = http3.start(state, self.error_tx.clone());
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
          task.endpoint.set_server_config(Some(config.clone()));
          info!(bind = %task.bind, "downstream HTTP/3 TLS config refreshed");
        }
      }
      None => {}
    }
  }
}

impl TcpListenerTask {
  fn shutdown(self) {
    let _ = self.shutdown.send(true);
    self.task.abort();
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
    let kind = self.kind;
    let task = tokio::spawn(async move {
      if let Err(error) = serve_tcp(self.listener, kind, state, shutdown_rx).await {
        let _ = error_tx.send(error.context("downstream TCP HTTP listener failed"));
      }
    });
    TcpListenerTask {
      bind,
      shutdown,
      task,
    }
  }
}

impl Http3ListenerTask {
  fn shutdown(self) {
    let _ = self.shutdown.send(true);
    self.endpoint.close(0u32.into(), b"listener reload");
    self.task.abort();
  }
}

impl BoundHttp3Listener {
  fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> Http3ListenerTask {
    let task_endpoint = self.endpoint.clone();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let bind = self.bind;
    let task = tokio::spawn(async move {
      if let Err(error) = serve_http3(task_endpoint, state, shutdown_rx).await {
        let _ = error_tx.send(error.context("downstream HTTP/3 listener failed"));
      }
    });
    Http3ListenerTask {
      bind,
      endpoint: self.endpoint,
      shutdown,
      task,
    }
  }
}

async fn bind_tcp_listener(
  bind: SocketAddr,
  kind: TcpListenerKind,
) -> anyhow::Result<BoundTcpListener> {
  let listener = TcpListener::bind(bind)
    .await
    .with_context(|| format!("failed to bind downstream listener to {bind}"))?;
  Ok(BoundTcpListener {
    bind,
    kind,
    listener,
  })
}

async fn serve_tcp(
  listener: TcpListener,
  kind: TcpListenerKind,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read TCP listener address")?;
  info!(bind = %bind, ?kind, "downstream TCP listener started");

  loop {
    tokio::select! {
        biased;
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, "downstream HTTPS listener stopped");
            }
            return Ok(());
        }
        accepted = listener.accept() => {
            let (stream, peer_addr) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "failed to accept downstream connection");
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
  let endpoint = h3_quinn::quinn::Endpoint::server(server_config, bind)
    .with_context(|| format!("failed to bind downstream HTTP/3 listener to {bind}"))?;
  Ok(BoundHttp3Listener { bind, endpoint })
}

async fn serve_http3(
  endpoint: h3_quinn::quinn::Endpoint,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  let bind = endpoint
    .local_addr()
    .context("failed to read HTTP/3 listener address")?;
  info!(bind = %bind, "downstream HTTP/3 listener started");

  loop {
    tokio::select! {
        biased;
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
              info!(bind = %bind, "downstream HTTP/3 listener stopped");
            }
            return Ok(());
        }
        connecting = endpoint.accept() => {
            let Some(connecting) = connecting else {
                return Ok(());
            };
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
  let _permit = acquire_connection_permit(&handshake_state, peer_addr)?;
  let (stream, peer_addr) = proxy_protocol::accept_proxy_header(
    stream,
    peer_addr,
    &handshake_state.config.listeners.proxy_protocol,
  )
  .await?;
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
  let _permit = acquire_connection_permit(&snapshot, peer_addr)?;
  let request_count = Arc::new(AtomicUsize::new(0));
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    let request_count = request_count.clone();
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

fn acquire_connection_permit(
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_connection(
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
