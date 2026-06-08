//! Raw stream listener runtime and upstream forwarding.
//! Stream handling keeps transport metadata available for WAF and limit decisions.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{StreamListenerConfig, StreamNetwork};
use crate::lifecycle::{ConnectionDrain, TaskRegistry};
use crate::limits::ConnectionPermit;
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
use crate::proxy_protocol_egress;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::sni_forward::client_hello::{ClientHelloSni, tls_record_client_hello_sni};
use crate::state::AppHandle;
use crate::stream::sni::select_stream_route;
use crate::stream::target::resolve_stream_route_target;

pub(crate) mod pools;
mod sni;
mod target;
mod udp;

const STREAM_TLS_CLIENT_HELLO_MAX_BYTES: usize = 64 * 1024;
const STREAM_INCOMPLETE_CLIENT_HELLO_RETRY_DELAY: Duration = Duration::from_millis(10);

pub(crate) struct StreamListenerTask {
  pub(crate) options: TcpListenOptions,
  pub(crate) config: StreamListenerConfig,
  shutdown: watch::Sender<bool>,
  connections: TaskRegistry,
  graceful_timeout: Duration,
  tasks: Vec<JoinHandle<()>>,
}

pub(crate) struct BoundStreamListener {
  pub(crate) config: StreamListenerConfig,
  options: TcpListenOptions,
  accept_error_backoff: Duration,
  transport: BoundStreamTransport,
}

enum BoundStreamTransport {
  Tcp(Vec<TcpListener>),
  Udp(std::net::UdpSocket),
}

impl StreamListenerTask {
  pub(crate) fn drain_background(self) {
    drop(self.drain());
  }

  pub(crate) fn drain(self) -> JoinHandle<()> {
    tokio::spawn(async move {
      let StreamListenerTask {
        shutdown,
        connections,
        graceful_timeout,
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
      if tokio::time::timeout(graceful_timeout, wait).await.is_err() {
        connections.abort_all();
      }
    })
  }
}

impl BoundStreamListener {
  pub(crate) fn bind(
    config: StreamListenerConfig,
    options: TcpListenOptions,
    accept_error_backoff: Duration,
  ) -> anyhow::Result<Self> {
    let transport = match config.network {
      StreamNetwork::Tcp => {
        let listeners = bind_tcp_listeners(config.bind, options, "stream").with_context(|| {
          format!(
            "failed to bind stream listener {} to {}",
            config.name, config.bind
          )
        })?;
        BoundStreamTransport::Tcp(listeners)
      }
      StreamNetwork::Udp => {
        BoundStreamTransport::Udp(udp::bind_udp_socket(config.bind).with_context(|| {
          format!(
            "failed to bind UDP stream listener {} to {}",
            config.name, config.bind
          )
        })?)
      }
    };
    Ok(Self {
      config,
      options,
      accept_error_backoff,
      transport,
    })
  }

  pub(crate) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> StreamListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let name = self.config.name.clone();
    let options = self.options;
    let config = self.config;
    let transport = self.transport;
    let task_name = name.clone();
    let accept_error_backoff = self.accept_error_backoff;
    let snapshot = state.snapshot();
    let graceful_timeout = Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms);
    let long_connection_close_delay =
      Duration::from_millis(snapshot.config.runtime.drain.long_connection_close_delay_ms);
    drop(snapshot);
    let connections = TaskRegistry::default();
    let tasks = match transport {
      BoundStreamTransport::Tcp(listeners) => listeners
        .into_iter()
        .enumerate()
        .map(|(worker_index, listener)| {
          let worker_shutdown = shutdown_rx.clone();
          let worker_config = config.clone();
          let worker_state = state.clone();
          let worker_error_tx = error_tx.clone();
          let worker_task_name = task_name.clone();
          let worker_connections = connections.clone();
          tokio::spawn(async move {
            if let Err(error) = serve_stream_listener(
              listener,
              worker_config,
              worker_state,
              worker_shutdown,
              worker_index,
              accept_error_backoff,
              worker_connections,
              long_connection_close_delay,
            )
            .await
            {
              let _ = worker_error_tx
                .send(error.context(format!("stream listener {worker_task_name} failed")));
            }
          })
        })
        .collect(),
      BoundStreamTransport::Udp(socket) => {
        let worker_shutdown = shutdown_rx.clone();
        let worker_config = config.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        let worker_task_name = task_name.clone();
        let worker_connections = connections.clone();
        vec![tokio::spawn(async move {
          let socket =
            UdpSocket::from_std(socket).context("failed to register UDP stream listener socket");
          let result = match socket {
            Ok(socket) => {
              udp::serve_udp_listener(
                socket,
                worker_config,
                worker_state,
                worker_shutdown,
                worker_connections,
              )
              .await
            }
            Err(error) => Err(error),
          };
          if let Err(error) = result {
            let _ = worker_error_tx
              .send(error.context(format!("UDP stream listener {worker_task_name} failed")));
          }
        })]
      }
    };
    StreamListenerTask {
      options,
      config,
      shutdown,
      connections,
      graceful_timeout,
      tasks,
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn serve_stream_listener(
  listener: TcpListener,
  config: StreamListenerConfig,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  accept_error_backoff: Duration,
  connections: TaskRegistry,
  long_connection_close_delay: Duration,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read stream listener address")?;
  info!(
    name = %config.name,
    bind = %bind,
    network = ?config.network,
    worker = worker_index,
    "stream listener started"
  );

  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(name = %config.name, bind = %bind, worker = worker_index, "stream listener stopped");
        }
        return Ok(());
      }
      accepted = listener.accept() => {
        let (downstream, peer_addr) = match accepted {
          Ok(value) => value,
          Err(error) => {
            warn!(name = %config.name, error = %error, worker = worker_index, "failed to accept stream connection");
            tokio::time::sleep(accept_error_backoff).await;
            continue;
          }
        };
        let connection_config = config.clone();
        let permit = match acquire_connection_permit(&state, peer_addr) {
          Ok(permit) => permit,
          Err(error) => {
            warn!(name = %config.name, peer = %peer_addr, error = %error, "stream connection rejected");
            continue;
          }
        };
        let connection_shutdown = shutdown.clone();
        let snapshot = state.snapshot();
        let connection_drain = ConnectionDrain::new(
          connection_shutdown,
          snapshot.lifecycle.subscribe(),
          long_connection_close_delay,
        );
        let introspection_guard = snapshot
          .runtime_introspection
          .guard(RuntimeCounter::StreamListenerConnection);
        let task_state = state.clone();
        connections.spawn(async move {
          let _introspection_guard = introspection_guard;
          let result = proxy_stream_connection(
            downstream,
            peer_addr,
            connection_config,
            task_state,
            permit,
            connection_drain,
          ).await;
          if let Err(error) = result {
            warn!(peer = %peer_addr, error = %error, "stream proxy connection failed");
          }
        });
      }
    }
  }
}

async fn proxy_stream_connection(
  downstream: TcpStream,
  peer_addr: SocketAddr,
  config: StreamListenerConfig,
  state: AppHandle,
  _permit: ConnectionPermit,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let sni = peek_optional_tls_sni(&downstream, &config).await?;
  let route = select_stream_route(&config, sni.as_deref()).ok_or_else(|| {
    anyhow::anyhow!(
      "stream listener {} has no matching SNI route and no default target",
      config.name
    )
  })?;
  let resolved =
    resolve_stream_route_target(&state, StreamNetwork::Tcp, route.target, peer_addr).await?;
  let mut upstream = tokio::time::timeout(route.connect_timeout, TcpStream::connect(resolved.addr))
    .await
    .context("stream upstream connect timed out")?
    .with_context(|| format!("failed to connect stream target {}", resolved.label))?;

  proxy_protocol_egress::write_header(
    &mut upstream,
    route.proxy_protocol_egress,
    peer_addr,
    resolved.addr,
  )
  .await
  .context("failed to write stream PROXY protocol egress header")?;

  let _selection = resolved.selection;
  let result = copy_bidirectional_with_idle(downstream, upstream, route.idle_timeout, drain).await;
  let snapshot = state.snapshot();
  snapshot
    .metrics
    .record_stream_session_end("tcp", &config.name, route.name, result.is_ok());
  result
}

async fn peek_optional_tls_sni(
  stream: &TcpStream,
  config: &StreamListenerConfig,
) -> anyhow::Result<Option<String>> {
  if config.sni_rules.is_empty() {
    return Ok(None);
  }
  let timeout = Duration::from_millis(config.connect_timeout_ms.max(1));
  let result: anyhow::Result<Option<String>> = tokio::time::timeout(timeout, async {
    let mut buffer = vec![0u8; STREAM_TLS_CLIENT_HELLO_MAX_BYTES];
    loop {
      let read = stream
        .peek(&mut buffer)
        .await
        .context("failed to peek stream TLS ClientHello")?;
      if read == 0 {
        return Ok::<Option<String>, anyhow::Error>(None);
      }
      match tls_record_client_hello_sni(&buffer[..read]) {
        Ok(ClientHelloSni::Complete(sni)) => return Ok(sni),
        Ok(ClientHelloSni::Incomplete) if read >= STREAM_TLS_CLIENT_HELLO_MAX_BYTES => {
          return Ok(None);
        }
        Ok(ClientHelloSni::Incomplete) => {
          tokio::time::sleep(STREAM_INCOMPLETE_CLIENT_HELLO_RETRY_DELAY).await;
        }
        Err(_) => return Ok(None),
      }
    }
  })
  .await
  .unwrap_or_else(|_| Ok(None));
  result
}

fn acquire_connection_permit(
  state: &AppHandle,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  let snapshot = state.snapshot();
  snapshot
    .limits
    .acquire_connection(
      peer_addr.ip(),
      &snapshot.config.limits,
      &snapshot.config.connection_limits,
    )
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))
}

pub(crate) async fn resolve_target_addr(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
  tokio::net::lookup_host((host, port))
    .await
    .with_context(|| format!("failed to resolve stream target {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("stream target resolved no addresses: {host}:{port}"))
}

async fn copy_bidirectional_with_idle(
  downstream: TcpStream,
  upstream: TcpStream,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let (downstream_read, downstream_write) = downstream.into_split();
  let (upstream_read, upstream_write) = upstream.into_split();
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let mut downstream_to_upstream = tokio::spawn(copy_one_way_with_activity(
    downstream_read,
    upstream_write,
    activity_tx.clone(),
  ));
  let mut upstream_to_downstream = tokio::spawn(copy_one_way_with_activity(
    upstream_read,
    downstream_write,
    activity_tx,
  ));
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);

  loop {
    tokio::select! {
      result = &mut downstream_to_upstream => {
        upstream_to_downstream.abort();
        return result.context("stream copy task panicked")?;
      }
      result = &mut upstream_to_downstream => {
        downstream_to_upstream.abort();
        return result.context("stream copy task panicked")?;
      }
      activity = activity_rx.recv() => {
        if activity.is_none() {
          return Ok(());
        }
        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
      }
      _ = &mut idle => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Err(anyhow::anyhow!("stream proxy idle timeout elapsed"));
      }
      _ = &mut drain_close => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Ok(());
      }
    }
  }
}

async fn copy_one_way_with_activity<R, W>(
  mut reader: R,
  mut writer: W,
  activity: mpsc::Sender<()>,
) -> anyhow::Result<()>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut buffer = vec![0u8; 16 * 1024];
  loop {
    let read = reader.read(&mut buffer).await?;
    if read == 0 {
      writer.shutdown().await?;
      return Ok(());
    }
    writer.write_all(&buffer[..read]).await?;
    let _ = activity.try_send(());
  }
}
