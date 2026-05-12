use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use fastwebsockets::{
  Frame, OpCode, Payload, Role, WebSocketError, WebSocketRead, WebSocketWrite,
  after_handshake_split,
};
use http::{HeaderMap, Method, Uri, Version};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

mod webtransport;

#[cfg(test)]
mod tests;

pub(crate) use webtransport::{
  blocked_close, check_webtransport_payload, webtransport_datagram_metadata,
  webtransport_stream_metadata,
};

use crate::dynamic_policy::DynamicPolicyContext;
use crate::lifecycle::ConnectionDrain;
use crate::state::AppSnapshot;
use crate::waf::{
  WafBodyInput, WafProtocol, WafRequestInput, WafStreamClose, WafStreamDecision,
  WafStreamDirection, WafStreamInput, WafStreamProtocol, WafStreamUnit, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, WafWebSocketStreamMetadata,
  WafWebTransportStreamMetadata,
};

#[derive(Clone)]
pub(crate) struct StreamWafRequestContext {
  request_id: String,
  transaction_id: String,
  received_at_unix_ms: u64,
  method: Method,
  uri: Uri,
  version: Version,
  headers: HeaderMap,
  peer_addr: SocketAddr,
  downstream_host: String,
  downstream_scheme: &'static str,
  route_name: String,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  tcp_mss: Option<u32>,
  tcp_rtt_ms: Option<u64>,
  udp_datagram_size: Option<usize>,
  udp_connection_id: Option<String>,
  tags: HashMap<String, String>,
  dynamic_policy: DynamicPolicyContext,
  max_payload_bytes: usize,
}

pub(crate) struct StreamWafRequestSeed {
  pub(crate) request_id: String,
  pub(crate) transaction_id: String,
  pub(crate) received_at_unix_ms: u64,
  pub(crate) method: Method,
  pub(crate) uri: Uri,
  pub(crate) version: Version,
  pub(crate) headers: HeaderMap,
  pub(crate) peer_addr: SocketAddr,
  pub(crate) downstream_host: String,
  pub(crate) downstream_scheme: &'static str,
  pub(crate) route_name: String,
  pub(crate) tcp_max_hop: Option<u8>,
  pub(crate) tls: Arc<WafTlsMetadata>,
  pub(crate) protocol: WafProtocol,
  pub(crate) transport_network: WafTransportNetwork,
  pub(crate) tcp_mss: Option<u32>,
  pub(crate) tcp_rtt_ms: Option<u64>,
  pub(crate) udp_datagram_size: Option<usize>,
  pub(crate) udp_connection_id: Option<String>,
  pub(crate) tags: HashMap<String, String>,
  pub(crate) dynamic_policy: DynamicPolicyContext,
}

impl StreamWafRequestContext {
  pub(crate) fn from_seed(state: &AppSnapshot, seed: StreamWafRequestSeed) -> Option<Self> {
    if !state.waf.requires_stream_inspection(&seed.route_name) {
      return None;
    }

    Some(Self {
      request_id: seed.request_id,
      transaction_id: seed.transaction_id,
      received_at_unix_ms: seed.received_at_unix_ms,
      method: seed.method,
      uri: seed.uri,
      version: seed.version,
      headers: seed.headers,
      peer_addr: seed.peer_addr,
      downstream_host: seed.downstream_host,
      downstream_scheme: seed.downstream_scheme,
      route_name: seed.route_name,
      tcp_max_hop: seed.tcp_max_hop,
      tls: seed.tls,
      protocol: seed.protocol,
      transport_network: seed.transport_network,
      tcp_mss: seed.tcp_mss,
      tcp_rtt_ms: seed.tcp_rtt_ms,
      udp_datagram_size: seed.udp_datagram_size,
      udp_connection_id: seed.udp_connection_id,
      tags: seed.tags,
      dynamic_policy: seed.dynamic_policy,
      max_payload_bytes: state.config.waf.limits.max_body_inspection_bytes,
    })
  }

  pub(crate) fn max_payload_bytes(&self) -> usize {
    self.max_payload_bytes
  }

  fn request_input(&self) -> WafRequestInput<'_> {
    WafRequestInput {
      request_id: &self.request_id,
      transaction_id: &self.transaction_id,
      received_at_unix_ms: self.received_at_unix_ms,
      method: &self.method,
      uri: &self.uri,
      version: self.version,
      headers: &self.headers,
      body: None,
      peer_addr: self.peer_addr,
      downstream_host: &self.downstream_host,
      downstream_scheme: self.downstream_scheme,
      route_name: &self.route_name,
      tcp_max_hop: self.tcp_max_hop,
      tls: self.tls.as_ref(),
      protocol: self.protocol,
      transport_network: self.transport_network,
      transport_metadata: WafTransportMetadataInput {
        tcp_mss: self.tcp_mss,
        tcp_rtt_ms: self.tcp_rtt_ms,
        udp_datagram_size: self.udp_datagram_size,
        udp_connection_id: self.udp_connection_id.as_deref(),
      },
      tags: &self.tags,
      dynamic_policy: &self.dynamic_policy,
    }
  }

  fn evaluate_websocket(
    &self,
    state: &AppSnapshot,
    direction: WafStreamDirection,
    unit: WafStreamUnit,
    payload: &[u8],
    is_truncated: bool,
    websocket: WafWebSocketStreamMetadata<'_>,
  ) -> WafStreamDecision {
    state.waf.evaluate_stream(WafStreamInput {
      request: self.request_input(),
      protocol: WafStreamProtocol::Websocket,
      direction,
      unit,
      payload: WafBodyInput {
        bytes: payload,
        is_truncated,
      },
      websocket: Some(websocket),
      webtransport: None,
    })
  }

  pub(crate) fn evaluate_webtransport(
    &self,
    state: &AppSnapshot,
    direction: WafStreamDirection,
    payload: &[u8],
    is_truncated: bool,
    metadata: WafWebTransportStreamMetadata,
  ) -> WafStreamDecision {
    state.waf.evaluate_stream(WafStreamInput {
      request: self.request_input(),
      protocol: WafStreamProtocol::Webtransport,
      direction,
      unit: if metadata.datagram_size.is_some() {
        WafStreamUnit::WebtransportDatagram
      } else {
        WafStreamUnit::WebtransportStreamChunk
      },
      payload: WafBodyInput {
        bytes: payload,
        is_truncated,
      },
      websocket: None,
      webtransport: Some(metadata),
    })
  }
}

#[derive(Debug)]
pub(crate) struct StreamWafBlocked {
  close: WafStreamClose,
}

impl StreamWafBlocked {
  pub(crate) fn new(close: WafStreamClose) -> Self {
    Self { close }
  }

  pub(crate) fn close(&self) -> &WafStreamClose {
    &self.close
  }
}

impl std::fmt::Display for StreamWafBlocked {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("stream closed by stream-phase WAF rule")
  }
}

impl std::error::Error for StreamWafBlocked {}

#[derive(Clone)]
struct OwnedWebSocketFrame {
  fin: bool,
  opcode: OpCode,
  payload: Vec<u8>,
}

struct WebSocketMessageState {
  active_opcode: Option<OpCode>,
  captured: Vec<u8>,
  captured_truncated: bool,
  queued_frames: Vec<OwnedWebSocketFrame>,
  released_after_truncated: bool,
}

impl WebSocketMessageState {
  fn new(max_payload_bytes: usize) -> Self {
    Self {
      active_opcode: None,
      captured: Vec::with_capacity(max_payload_bytes.min(16 * 1024)),
      captured_truncated: false,
      queued_frames: Vec::new(),
      released_after_truncated: false,
    }
  }

  fn reset(&mut self) {
    self.active_opcode = None;
    self.captured.clear();
    self.captured_truncated = false;
    self.queued_frames.clear();
    self.released_after_truncated = false;
  }
}

struct WebSocketFrameOutcome {
  frames: Vec<OwnedWebSocketFrame>,
  peer_close: bool,
}

#[derive(Clone, Copy)]
enum WebSocketReadSide {
  Downstream,
  Upstream,
}

enum WebSocketReadEvent {
  Downstream(Result<OwnedWebSocketFrame, String>),
  Upstream(Result<OwnedWebSocketFrame, String>),
}

struct WebSocketReadTaskGuard {
  tasks: Vec<JoinHandle<()>>,
}

impl WebSocketReadTaskGuard {
  fn new() -> Self {
    Self { tasks: Vec::new() }
  }

  fn spawn<F>(&mut self, future: F)
  where
    F: std::future::Future<Output = ()> + Send + 'static,
  {
    self.tasks.push(tokio::spawn(future));
  }
}

impl Drop for WebSocketReadTaskGuard {
  fn drop(&mut self) {
    for task in &self.tasks {
      task.abort();
    }
  }
}

pub(crate) async fn bridge_websocket<D, U>(
  downstream: D,
  upstream: U,
  state: Arc<AppSnapshot>,
  context: StreamWafRequestContext,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (downstream_read, downstream_write) = tokio::io::split(downstream);
  let (upstream_read, upstream_write) = tokio::io::split(upstream);
  let (mut downstream_reader, mut downstream_writer) =
    after_handshake_split(downstream_read, downstream_write, Role::Server);
  let (mut upstream_reader, mut upstream_writer) =
    after_handshake_split(upstream_read, upstream_write, Role::Client);
  configure_reader(&mut downstream_reader, context.max_payload_bytes());
  configure_reader(&mut upstream_reader, context.max_payload_bytes());
  let (read_tx, mut read_rx) = mpsc::channel(2);
  let mut read_tasks = WebSocketReadTaskGuard::new();
  read_tasks.spawn(read_websocket_frames(
    downstream_reader,
    read_tx.clone(),
    WebSocketReadSide::Downstream,
  ));
  read_tasks.spawn(read_websocket_frames(
    upstream_reader,
    read_tx,
    WebSocketReadSide::Upstream,
  ));

  let mut downstream_messages = WebSocketMessageState::new(context.max_payload_bytes());
  let mut upstream_messages = WebSocketMessageState::new(context.max_payload_bytes());
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);

  loop {
    tokio::select! {
      event = read_rx.recv() => {
        let Some(event) = event else {
          return Ok(());
        };
        match event {
          WebSocketReadEvent::Downstream(result) => {
        let frame = result
          .map_err(|error| anyhow::anyhow!("failed to read downstream WebSocket frame: {error}"))?;
        let outcome = match inspect_websocket_frame(
          state.as_ref(),
          &context,
          WafStreamDirection::DownstreamToUpstream,
          frame,
          &mut downstream_messages,
        ) {
          Ok(outcome) => outcome,
          Err(blocked) => {
            close_websocket_pair(&mut downstream_writer, &mut upstream_writer, blocked.close())
              .await;
            return Ok(());
          }
        };
        forward_websocket_frames(&mut upstream_writer, outcome.frames)
          .await
          .context("failed to forward downstream WebSocket frame")?;
        if outcome.peer_close {
          return Ok(());
        }
        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
          }
          WebSocketReadEvent::Upstream(result) => {
        let frame = result
          .map_err(|error| anyhow::anyhow!("failed to read upstream WebSocket frame: {error}"))?;
        let outcome = match inspect_websocket_frame(
          state.as_ref(),
          &context,
          WafStreamDirection::UpstreamToDownstream,
          frame,
          &mut upstream_messages,
        ) {
          Ok(outcome) => outcome,
          Err(blocked) => {
            close_websocket_pair(&mut downstream_writer, &mut upstream_writer, blocked.close())
              .await;
            return Ok(());
          }
        };
        forward_websocket_frames(&mut downstream_writer, outcome.frames)
          .await
          .context("failed to forward upstream WebSocket frame")?;
        if outcome.peer_close {
          return Ok(());
        }
        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
          }
        }
      }
      _ = &mut idle => {
        return Err(anyhow::anyhow!("WebSocket stream WAF bridge idle timeout elapsed"));
      }
      _ = &mut drain_close => {
        return Ok(());
      }
    }
  }
}

async fn read_websocket_frames<R>(
  mut reader: WebSocketRead<R>,
  tx: mpsc::Sender<WebSocketReadEvent>,
  side: WebSocketReadSide,
) where
  R: AsyncRead + Unpin,
{
  loop {
    let result = read_owned_frame(&mut reader)
      .await
      .map_err(|error| error.to_string());
    let should_stop = result.is_err();
    let event = match side {
      WebSocketReadSide::Downstream => WebSocketReadEvent::Downstream(result),
      WebSocketReadSide::Upstream => WebSocketReadEvent::Upstream(result),
    };
    if tx.send(event).await.is_err() || should_stop {
      return;
    }
  }
}

fn configure_reader<R>(reader: &mut WebSocketRead<R>, max_payload_bytes: usize)
where
  R: AsyncRead + Unpin,
{
  reader.set_auto_close(false);
  reader.set_auto_pong(false);
  reader.set_max_message_size(websocket_max_frame_size(max_payload_bytes));
}

fn websocket_max_frame_size(max_payload_bytes: usize) -> usize {
  max_payload_bytes.saturating_add(1).max(1)
}

async fn read_owned_frame<R>(
  reader: &mut WebSocketRead<R>,
) -> Result<OwnedWebSocketFrame, WebSocketError>
where
  R: AsyncRead + Unpin,
{
  let mut ignore_obligated_send = |_frame: Frame<'_>| async { Ok::<(), std::io::Error>(()) };
  let frame = reader.read_frame(&mut ignore_obligated_send).await?;
  Ok(OwnedWebSocketFrame {
    fin: frame.fin,
    opcode: frame.opcode,
    payload: frame.payload.to_vec(),
  })
}

fn inspect_websocket_frame(
  state: &AppSnapshot,
  context: &StreamWafRequestContext,
  direction: WafStreamDirection,
  frame: OwnedWebSocketFrame,
  messages: &mut WebSocketMessageState,
) -> Result<WebSocketFrameOutcome, StreamWafBlocked> {
  let message_opcode = websocket_message_opcode(frame.opcode, messages.active_opcode);
  let payload = inspect_prefix(&frame.payload, context.max_payload_bytes());
  let raw_decision = context.evaluate_websocket(
    state,
    direction,
    WafStreamUnit::WebsocketFrame,
    payload.bytes,
    payload.is_truncated,
    WafWebSocketStreamMetadata {
      opcode: websocket_opcode_name(frame.opcode),
      fin: frame.fin,
      is_control: websocket_is_control(frame.opcode),
      message_opcode,
      frame_payload_size: frame.payload.len(),
    },
  );
  if let Some(close) = raw_decision.close {
    return Err(StreamWafBlocked::new(close));
  }

  if websocket_is_control(frame.opcode) {
    let peer_close = frame.opcode == OpCode::Close;
    return Ok(WebSocketFrameOutcome {
      frames: vec![frame],
      peer_close,
    });
  }

  match frame.opcode {
    OpCode::Text | OpCode::Binary => {
      inspect_initial_message_frame(state, context, direction, frame, messages)
    }
    OpCode::Continuation => inspect_continuation_frame(state, context, direction, frame, messages),
    OpCode::Close | OpCode::Ping | OpCode::Pong => {
      let peer_close = frame.opcode == OpCode::Close;
      Ok(WebSocketFrameOutcome {
        frames: vec![frame],
        peer_close,
      })
    }
  }
}

fn inspect_initial_message_frame(
  state: &AppSnapshot,
  context: &StreamWafRequestContext,
  direction: WafStreamDirection,
  frame: OwnedWebSocketFrame,
  messages: &mut WebSocketMessageState,
) -> Result<WebSocketFrameOutcome, StreamWafBlocked> {
  if messages.active_opcode.is_some() {
    return Err(StreamWafBlocked::new(protocol_error_close()));
  }

  if frame.fin {
    let payload = inspect_prefix(&frame.payload, context.max_payload_bytes());
    evaluate_websocket_message(
      state,
      context,
      direction,
      frame.opcode,
      payload.bytes,
      payload.is_truncated,
      frame.payload.len(),
    )?;
    return Ok(WebSocketFrameOutcome {
      frames: vec![frame],
      peer_close: false,
    });
  }

  messages.active_opcode = Some(frame.opcode);
  append_message_payload(messages, &frame.payload, context.max_payload_bytes());
  messages.queued_frames.push(frame);

  if messages.captured_truncated {
    evaluate_websocket_message(
      state,
      context,
      direction,
      messages.active_opcode.unwrap_or(OpCode::Binary),
      &messages.captured,
      true,
      messages.captured.len(),
    )?;
    messages.released_after_truncated = true;
    let frames = std::mem::take(&mut messages.queued_frames);
    return Ok(WebSocketFrameOutcome {
      frames,
      peer_close: false,
    });
  }

  Ok(WebSocketFrameOutcome {
    frames: Vec::new(),
    peer_close: false,
  })
}

fn inspect_continuation_frame(
  state: &AppSnapshot,
  context: &StreamWafRequestContext,
  direction: WafStreamDirection,
  frame: OwnedWebSocketFrame,
  messages: &mut WebSocketMessageState,
) -> Result<WebSocketFrameOutcome, StreamWafBlocked> {
  let Some(active_opcode) = messages.active_opcode else {
    return Err(StreamWafBlocked::new(protocol_error_close()));
  };

  if messages.released_after_truncated {
    if frame.fin {
      messages.reset();
    }
    return Ok(WebSocketFrameOutcome {
      frames: vec![frame],
      peer_close: false,
    });
  }

  append_message_payload(messages, &frame.payload, context.max_payload_bytes());
  messages.queued_frames.push(frame);
  if messages.captured_truncated {
    evaluate_websocket_message(
      state,
      context,
      direction,
      active_opcode,
      &messages.captured,
      true,
      messages.captured.len(),
    )?;
    let frames = std::mem::take(&mut messages.queued_frames);
    if frames.last().is_some_and(|queued| queued.fin) {
      messages.reset();
    } else {
      messages.released_after_truncated = true;
    }
    return Ok(WebSocketFrameOutcome {
      frames,
      peer_close: false,
    });
  }

  let finished = messages
    .queued_frames
    .last()
    .is_some_and(|queued| queued.fin);
  if finished {
    evaluate_websocket_message(
      state,
      context,
      direction,
      active_opcode,
      &messages.captured,
      false,
      messages.captured.len(),
    )?;
    let frames = std::mem::take(&mut messages.queued_frames);
    messages.reset();
    return Ok(WebSocketFrameOutcome {
      frames,
      peer_close: false,
    });
  }

  Ok(WebSocketFrameOutcome {
    frames: Vec::new(),
    peer_close: false,
  })
}

fn append_message_payload(
  messages: &mut WebSocketMessageState,
  payload: &[u8],
  max_payload_bytes: usize,
) {
  if messages.captured.len() >= max_payload_bytes {
    messages.captured_truncated = true;
    return;
  }

  let remaining = max_payload_bytes - messages.captured.len();
  let copied = remaining.min(payload.len());
  messages.captured.extend_from_slice(&payload[..copied]);
  if copied < payload.len() {
    messages.captured_truncated = true;
  }
}

fn evaluate_websocket_message(
  state: &AppSnapshot,
  context: &StreamWafRequestContext,
  direction: WafStreamDirection,
  opcode: OpCode,
  payload: &[u8],
  is_truncated: bool,
  frame_payload_size: usize,
) -> Result<(), StreamWafBlocked> {
  let decision = context.evaluate_websocket(
    state,
    direction,
    WafStreamUnit::WebsocketMessage,
    payload,
    is_truncated,
    WafWebSocketStreamMetadata {
      opcode: "message",
      fin: true,
      is_control: false,
      message_opcode: Some(websocket_opcode_name(opcode)),
      frame_payload_size,
    },
  );
  if let Some(close) = decision.close {
    Err(StreamWafBlocked::new(close))
  } else {
    Ok(())
  }
}

async fn forward_websocket_frames<W>(
  writer: &mut WebSocketWrite<W>,
  frames: Vec<OwnedWebSocketFrame>,
) -> Result<(), WebSocketError>
where
  W: AsyncWrite + Unpin,
{
  for frame in frames {
    writer
      .write_frame(Frame::new(
        frame.fin,
        frame.opcode,
        None,
        Payload::Owned(frame.payload),
      ))
      .await?;
  }
  writer.flush().await
}

pub(super) fn inspect_prefix(payload: &[u8], limit: usize) -> WafBodyInput<'_> {
  let copied = limit.min(payload.len());
  WafBodyInput {
    bytes: &payload[..copied],
    is_truncated: copied < payload.len(),
  }
}

fn websocket_message_opcode(opcode: OpCode, active_opcode: Option<OpCode>) -> Option<&'static str> {
  match opcode {
    OpCode::Text | OpCode::Binary => Some(websocket_opcode_name(opcode)),
    OpCode::Continuation => active_opcode.map(websocket_opcode_name),
    OpCode::Close | OpCode::Ping | OpCode::Pong => active_opcode.map(websocket_opcode_name),
  }
}

fn websocket_opcode_name(opcode: OpCode) -> &'static str {
  match opcode {
    OpCode::Continuation => "continuation",
    OpCode::Text => "text",
    OpCode::Binary => "binary",
    OpCode::Close => "close",
    OpCode::Ping => "ping",
    OpCode::Pong => "pong",
  }
}

fn websocket_is_control(opcode: OpCode) -> bool {
  matches!(opcode, OpCode::Close | OpCode::Ping | OpCode::Pong)
}

fn protocol_error_close() -> WafStreamClose {
  WafStreamClose {
    websocket_code: 1002,
    webtransport_code: 1,
    reason: "protocol error".to_string(),
  }
}

async fn close_websocket_pair<D, U>(
  downstream: &mut WebSocketWrite<D>,
  upstream: &mut WebSocketWrite<U>,
  close: &WafStreamClose,
) where
  D: AsyncWrite + Unpin,
  U: AsyncWrite + Unpin,
{
  if let Err(error) = downstream
    .write_frame(Frame::close(close.websocket_code, close.reason.as_bytes()))
    .await
  {
    warn!(error = %error, "failed to send downstream WebSocket WAF close frame");
  }
  if let Err(error) = upstream
    .write_frame(Frame::close(close.websocket_code, close.reason.as_bytes()))
    .await
  {
    warn!(error = %error, "failed to send upstream WebSocket WAF close frame");
  }
  let _ = downstream.flush().await;
  let _ = upstream.flush().await;
}
