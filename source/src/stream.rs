use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{StreamListenerConfig, parse_stream_target};
use crate::limits::ConnectionPermit;
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
use crate::proxy_protocol_egress;
use crate::state::AppHandle;

pub(crate) struct StreamListenerTask {
  pub(crate) name: String,
  pub(crate) bind: SocketAddr,
  pub(crate) options: TcpListenOptions,
  shutdown: watch::Sender<bool>,
  tasks: Vec<JoinHandle<()>>,
}

pub(crate) struct BoundStreamListener {
  pub(crate) config: StreamListenerConfig,
  options: TcpListenOptions,
  accept_error_backoff: Duration,
  listeners: Vec<TcpListener>,
}

impl StreamListenerTask {
  pub(crate) fn shutdown(self) {
    let _ = self.shutdown.send(true);
    for task in self.tasks {
      task.abort();
    }
  }
}

impl BoundStreamListener {
  pub(crate) fn bind(
    config: StreamListenerConfig,
    options: TcpListenOptions,
    accept_error_backoff: Duration,
  ) -> anyhow::Result<Self> {
    let listeners = bind_tcp_listeners(config.bind, options, "stream").with_context(|| {
      format!(
        "failed to bind stream listener {} to {}",
        config.name, config.bind
      )
    })?;
    Ok(Self {
      config,
      options,
      accept_error_backoff,
      listeners,
    })
  }

  pub(crate) fn start(
    self,
    state: AppHandle,
    error_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> StreamListenerTask {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let name = self.config.name.clone();
    let bind = self.config.bind;
    let options = self.options;
    let config = self.config;
    let listeners = self.listeners;
    let task_name = name.clone();
    let accept_error_backoff = self.accept_error_backoff;
    let tasks = listeners
      .into_iter()
      .enumerate()
      .map(|(worker_index, listener)| {
        let worker_shutdown = shutdown_rx.clone();
        let worker_config = config.clone();
        let worker_state = state.clone();
        let worker_error_tx = error_tx.clone();
        let worker_task_name = task_name.clone();
        tokio::spawn(async move {
          if let Err(error) = serve_stream_listener(
            listener,
            worker_config,
            worker_state,
            worker_shutdown,
            worker_index,
            accept_error_backoff,
          )
          .await
          {
            let _ = worker_error_tx
              .send(error.context(format!("stream listener {worker_task_name} failed")));
          }
        })
      })
      .collect();
    StreamListenerTask {
      name,
      bind,
      options,
      shutdown,
      tasks,
    }
  }
}

async fn serve_stream_listener(
  listener: TcpListener,
  config: StreamListenerConfig,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  worker_index: usize,
  accept_error_backoff: Duration,
) -> anyhow::Result<()> {
  let bind = listener
    .local_addr()
    .context("failed to read stream listener address")?;
  info!(name = %config.name, bind = %bind, target = %config.target, worker = worker_index, "stream listener started");

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
        tokio::spawn(async move {
          let result = proxy_stream_connection(downstream, peer_addr, connection_config, permit).await;
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
  _permit: ConnectionPermit,
) -> anyhow::Result<()> {
  let (host, port) = parse_stream_target(&config.target)?;
  let remote_addr = resolve_target_addr(&host, port).await?;
  let mut upstream = tokio::time::timeout(
    Duration::from_millis(config.connect_timeout_ms),
    TcpStream::connect(remote_addr),
  )
  .await
  .context("stream upstream connect timed out")?
  .with_context(|| format!("failed to connect stream target {}", config.target))?;

  proxy_protocol_egress::write_header(
    &mut upstream,
    config.proxy_protocol_egress,
    peer_addr,
    remote_addr,
  )
  .await
  .context("failed to write stream PROXY protocol egress header")?;

  copy_bidirectional_with_idle(
    downstream,
    upstream,
    Duration::from_millis(config.idle_timeout_ms),
  )
  .await
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
