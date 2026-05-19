use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::config::parse_stream_target;
use crate::lifecycle::ConnectionDrain;
use crate::proxy_protocol_egress;
use crate::sni_forward::client_hello::{ClientHelloSni, tls_record_client_hello_sni};
use crate::sni_forward::{SniForwardDecision, SniForwardRule};
use crate::state::AppSnapshot;
use crate::stream::resolve_target_addr;
use crate::telemetry::TelemetryRuntime;

pub(crate) enum TcpSniForwardResult {
  Local(TcpStream),
  Forwarded,
}

pub(crate) async fn local_stream_or_forwarded(
  stream: TcpStream,
  peer_addr: SocketAddr,
  snapshot: Arc<AppSnapshot>,
  drain: ConnectionDrain,
) -> anyhow::Result<Option<TcpStream>> {
  match classify_and_maybe_forward(stream, peer_addr, snapshot, drain).await? {
    TcpSniForwardResult::Local(stream) => Ok(Some(stream)),
    TcpSniForwardResult::Forwarded => Ok(None),
  }
}

pub(crate) async fn classify_and_maybe_forward(
  stream: TcpStream,
  peer_addr: SocketAddr,
  snapshot: Arc<AppSnapshot>,
  drain: ConnectionDrain,
) -> anyhow::Result<TcpSniForwardResult> {
  if !snapshot.sni_forward.is_enabled() {
    return Ok(TcpSniForwardResult::Local(stream));
  }

  let sni = match peek_sni(
    &stream,
    snapshot.config.sni_forward.client_hello_max_bytes,
    Duration::from_millis(snapshot.config.limits.tls_handshake_timeout_ms),
  )
  .await
  {
    Ok(sni) => sni,
    Err(error) => {
      snapshot.metrics.record_sni_forward_parse_failure("tcp_tls");
      snapshot
        .metrics
        .record_sni_forward_decision("tcp_tls", "reject", "parse_failure", "none");
      return Err(error);
    }
  };

  match snapshot.sni_forward.decide_tcp_tls(sni.as_deref()) {
    SniForwardDecision::Local => {
      snapshot
        .metrics
        .record_sni_forward_decision("tcp_tls", "local", "local_route", "local");
      Ok(TcpSniForwardResult::Local(stream))
    }
    SniForwardDecision::Reject => {
      snapshot
        .metrics
        .record_sni_forward_decision("tcp_tls", "reject", "no_match", "none");
      bail!("TLS ClientHello SNI is not configured for local routing or SNI forwarding")
    }
    SniForwardDecision::Forward(rule) => {
      snapshot
        .metrics
        .record_sni_forward_decision("tcp_tls", "forward", &rule.name, &rule.target);
      forward_tcp(stream, peer_addr, sni.as_deref(), snapshot, rule, drain).await?;
      Ok(TcpSniForwardResult::Forwarded)
    }
  }
}

async fn peek_sni(
  stream: &TcpStream,
  max_bytes: usize,
  timeout: Duration,
) -> anyhow::Result<Option<String>> {
  tokio::time::timeout(timeout, async {
    let mut buffer = vec![0u8; max_bytes];
    loop {
      let read = stream
        .peek(&mut buffer)
        .await
        .context("failed to peek TLS ClientHello")?;
      if read == 0 {
        bail!("connection closed before TLS ClientHello");
      }
      match tls_record_client_hello_sni(&buffer[..read])? {
        ClientHelloSni::Complete(sni) => return Ok(sni),
        ClientHelloSni::Incomplete if read >= max_bytes => {
          bail!("TLS ClientHello exceeded sni_forward.client_hello_max_bytes");
        }
        ClientHelloSni::Incomplete => tokio::task::yield_now().await,
      }
    }
  })
  .await
  .context("TLS ClientHello SNI inspection timed out")?
}

async fn forward_tcp(
  downstream: TcpStream,
  peer_addr: SocketAddr,
  sni: Option<&str>,
  snapshot: Arc<AppSnapshot>,
  rule: Arc<SniForwardRule>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let started = TelemetryRuntime::start();
  let (host, port) = parse_stream_target(&rule.target)
    .with_context(|| format!("invalid SNI forwarding target {}", rule.target))?;
  let remote_addr = resolve_target_addr(&host, port).await?;
  let mut upstream = tokio::time::timeout(rule.connect_timeout, TcpStream::connect(remote_addr))
    .await
    .context("SNI forwarding TCP connect timed out")?
    .with_context(|| format!("failed to connect SNI forwarding target {}", rule.target))?;

  proxy_protocol_egress::write_header(
    &mut upstream,
    rule.tcp_proxy_protocol_egress,
    peer_addr,
    remote_addr,
  )
  .await
  .context("failed to write SNI forwarding PROXY protocol egress header")?;

  info!(
    protocol = "tcp_tls",
    peer = %peer_addr,
    target = %rule.target,
    rule = %rule.name,
    sni = sni.unwrap_or("none"),
    "SNI forwarding TCP session started"
  );

  let result = copy_bidirectional_with_idle(downstream, upstream, rule.idle_timeout, drain).await;
  let (client_bytes, upstream_bytes, outcome) = match &result {
    Ok(counts) => (
      counts.client_to_upstream,
      counts.upstream_to_client,
      "closed",
    ),
    Err(_) => (0, 0, "error"),
  };
  snapshot
    .metrics
    .add_sni_forward_tcp_bytes(client_bytes.saturating_add(upstream_bytes));
  snapshot.metrics.record_sni_forward_session_end(
    &snapshot.config.metrics,
    "tcp_tls",
    &rule.name,
    &rule.target,
    outcome,
    started.elapsed_ms(),
  );
  match &result {
    Ok(counts) => {
      info!(
        protocol = "tcp_tls",
        peer = %peer_addr,
        target = %rule.target,
        rule = %rule.name,
        sni = sni.unwrap_or("none"),
        duration_ms = started.elapsed_ms(),
        client_to_upstream_bytes = counts.client_to_upstream,
        upstream_to_client_bytes = counts.upstream_to_client,
        "SNI forwarding TCP session ended"
      );
    }
    Err(error) => {
      warn!(
        protocol = "tcp_tls",
        peer = %peer_addr,
        target = %rule.target,
        rule = %rule.name,
        sni = sni.unwrap_or("none"),
        duration_ms = started.elapsed_ms(),
        error = %error,
        "SNI forwarding TCP session failed"
      );
    }
  }
  result.map(|_| ())
}

#[derive(Debug, Clone, Copy, Default)]
struct CopyCounts {
  client_to_upstream: u64,
  upstream_to_client: u64,
}

async fn copy_bidirectional_with_idle(
  downstream: TcpStream,
  upstream: TcpStream,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<CopyCounts> {
  let (downstream_read, downstream_write) = downstream.into_split();
  let (upstream_read, upstream_write) = upstream.into_split();
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let mut downstream_to_upstream = tokio::spawn(copy_one_way_with_activity(
    downstream_read,
    upstream_write,
    CopyDirection::ClientToUpstream,
    activity_tx.clone(),
  ));
  let mut upstream_to_downstream = tokio::spawn(copy_one_way_with_activity(
    upstream_read,
    downstream_write,
    CopyDirection::UpstreamToClient,
    activity_tx,
  ));
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);
  let mut counts = CopyCounts::default();

  loop {
    tokio::select! {
      result = &mut downstream_to_upstream => {
        upstream_to_downstream.abort();
        counts.client_to_upstream = result.context("SNI forward copy task panicked")??;
        return Ok(counts);
      }
      result = &mut upstream_to_downstream => {
        downstream_to_upstream.abort();
        counts.upstream_to_client = result.context("SNI forward copy task panicked")??;
        return Ok(counts);
      }
      activity = activity_rx.recv() => {
        if let Some((direction, bytes)) = activity {
          match direction {
            CopyDirection::ClientToUpstream => {
              counts.client_to_upstream = counts.client_to_upstream.saturating_add(bytes);
            }
            CopyDirection::UpstreamToClient => {
              counts.upstream_to_client = counts.upstream_to_client.saturating_add(bytes);
            }
          }
          idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
        } else {
          return Ok(counts);
        }
      }
      _ = &mut idle => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        bail!("SNI forwarding TCP idle timeout elapsed");
      }
      _ = &mut drain_close => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Ok(counts);
      }
    }
  }
}

#[derive(Debug, Clone, Copy)]
enum CopyDirection {
  ClientToUpstream,
  UpstreamToClient,
}

async fn copy_one_way_with_activity<R, W>(
  mut reader: R,
  mut writer: W,
  direction: CopyDirection,
  activity: mpsc::Sender<(CopyDirection, u64)>,
) -> anyhow::Result<u64>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut copied = 0u64;
  let mut buffer = vec![0u8; 16 * 1024];
  loop {
    let read = reader.read(&mut buffer).await?;
    if read == 0 {
      writer.shutdown().await?;
      return Ok(copied);
    }
    writer.write_all(&buffer[..read]).await?;
    let bytes = read as u64;
    copied = copied.saturating_add(bytes);
    let _ = activity.try_send((direction, bytes));
  }
}
