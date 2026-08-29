//! WAF inspection adapters for bidirectional stream transports.
//! Stream decisions are direction-aware so close actions do not lose protocol context.

use fastwebsockets::{Frame, OpCode, WebSocketError, WebSocketRead};
#[cfg(feature = "fuzzing")]
use fastwebsockets::{Role, after_handshake_split};
use tokio::io::AsyncRead;

mod context;
mod websocket_bridge;
mod webtransport;

#[cfg(test)]
mod tests;

pub(crate) use websocket_bridge::bridge_websocket;
pub(crate) use webtransport::{
  blocked_close, blocked_silent_close, check_webtransport_payload, webtransport_datagram_metadata,
  webtransport_stream_metadata,
};

use crate::state::AppSnapshot;
use crate::waf::{
  WafBodyInput, WafStreamClose, WafStreamDirection, WafStreamUnit, WafWebSocketStreamMetadata,
};
pub(crate) use context::{StreamWafRequestContext, StreamWafRequestSeed};

#[derive(Debug)]
pub(crate) struct StreamWafBlocked {
  close: Option<WafStreamClose>,
  silent_close: bool,
}

impl StreamWafBlocked {
  pub(crate) fn new(close: WafStreamClose) -> Self {
    Self {
      close: Some(close),
      silent_close: false,
    }
  }

  pub(crate) fn silent_close() -> Self {
    Self {
      close: None,
      silent_close: true,
    }
  }

  pub(crate) fn close_option(&self) -> Option<&WafStreamClose> {
    self.close.as_ref()
  }

  pub(crate) fn is_silent_close(&self) -> bool {
    self.silent_close
  }
}

impl std::fmt::Display for StreamWafBlocked {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if self.silent_close {
      formatter.write_str("stream silently closed by stream-phase WAF rule")
    } else {
      formatter.write_str("stream closed by stream-phase WAF rule")
    }
  }
}

impl std::error::Error for StreamWafBlocked {}

#[derive(Clone)]
pub(super) struct OwnedWebSocketFrame {
  pub(super) fin: bool,
  pub(super) opcode: OpCode,
  pub(super) payload: Vec<u8>,
}

pub(super) struct WebSocketMessageState {
  active_opcode: Option<OpCode>,
  captured: Vec<u8>,
  captured_truncated: bool,
  queued_payload: Vec<u8>,
  released_after_truncated: bool,
}

impl WebSocketMessageState {
  pub(super) fn new(max_payload_bytes: usize) -> Self {
    Self {
      active_opcode: None,
      captured: Vec::with_capacity(max_payload_bytes.min(16 * 1024)),
      captured_truncated: false,
      queued_payload: Vec::with_capacity(max_payload_bytes.min(16 * 1024)),
      released_after_truncated: false,
    }
  }

  fn reset(&mut self) {
    self.active_opcode = None;
    self.captured.clear();
    self.captured_truncated = false;
    self.queued_payload.clear();
    self.released_after_truncated = false;
  }

  fn queue_payload(&mut self, payload: &[u8]) {
    self.queued_payload.extend_from_slice(payload);
  }

  fn take_queued_frame(&mut self, fin: bool) -> OwnedWebSocketFrame {
    OwnedWebSocketFrame {
      fin,
      opcode: self.active_opcode.unwrap_or(OpCode::Binary),
      payload: std::mem::take(&mut self.queued_payload),
    }
  }
}

pub(super) struct WebSocketFrameOutcome {
  pub(super) frames: Vec<OwnedWebSocketFrame>,
  pub(super) peer_close: bool,
}

#[cfg(any(test, feature = "fuzzing"))]
pub(super) fn configure_reader<R>(reader: &mut WebSocketRead<R>, max_payload_bytes: usize)
where
  R: AsyncRead + Unpin,
{
  configure_reader_controls(reader);
  reader.set_max_message_size(websocket_max_frame_size(max_payload_bytes));
}

pub(super) fn configure_reader_controls<R>(reader: &mut WebSocketRead<R>)
where
  R: AsyncRead + Unpin,
{
  reader.set_auto_close(false);
  reader.set_auto_pong(false);
}

#[cfg(any(test, feature = "fuzzing"))]
fn websocket_max_frame_size(max_payload_bytes: usize) -> usize {
  max_payload_bytes.saturating_add(1).max(1)
}

#[cfg(feature = "fuzzing")]
pub(crate) async fn fuzz_websocket_frame(raw: &[u8], max_payload_bytes: usize) {
  use tokio::io::AsyncWriteExt;

  let capacity = raw.len().saturating_add(16).max(64);
  let (mut writer, reader) = tokio::io::duplex(capacity);
  if writer.write_all(raw).await.is_ok() {
    let _ = writer.shutdown().await;
  }
  drop(writer);

  let (read, write) = tokio::io::split(reader);
  let (mut reader, _writer) = after_handshake_split(read, write, Role::Server);
  configure_reader(&mut reader, max_payload_bytes);
  for _ in 0..8 {
    if read_owned_frame(&mut reader).await.is_err() {
      break;
    }
  }
  let _ = inspect_prefix(raw, max_payload_bytes);
}

pub(super) async fn read_owned_frame<R>(
  reader: &mut WebSocketRead<R>,
) -> Result<OwnedWebSocketFrame, WebSocketError>
where
  R: AsyncRead + Unpin,
{
  let mut ignore_obligated_send = |_frame: Frame<'_>| async { Ok::<(), std::io::Error>(()) };
  let frame = reader.read_frame(&mut ignore_obligated_send).await?;
  if websocket_is_control(frame.opcode) && frame.payload.len() > 125 {
    return Err(WebSocketError::FrameTooLarge);
  }
  Ok(OwnedWebSocketFrame {
    fin: frame.fin,
    opcode: frame.opcode,
    payload: frame.payload.to_vec(),
  })
}

pub(super) fn inspect_websocket_frame(
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
  if raw_decision.silent_close {
    return Err(StreamWafBlocked::silent_close());
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
  messages.queue_payload(&frame.payload);

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
    let queued = messages.take_queued_frame(false);
    return Ok(WebSocketFrameOutcome {
      frames: vec![queued],
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
  let finished = frame.fin;
  messages.queue_payload(&frame.payload);
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
    let queued = messages.take_queued_frame(finished);
    if finished {
      messages.reset();
    } else {
      messages.released_after_truncated = true;
    }
    return Ok(WebSocketFrameOutcome {
      frames: vec![queued],
      peer_close: false,
    });
  }

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
    let queued = messages.take_queued_frame(true);
    messages.reset();
    return Ok(WebSocketFrameOutcome {
      frames: vec![queued],
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
  } else if decision.silent_close {
    Err(StreamWafBlocked::silent_close())
  } else {
    Ok(())
  }
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

pub(super) fn websocket_is_control(opcode: OpCode) -> bool {
  matches!(opcode, OpCode::Close | OpCode::Ping | OpCode::Pong)
}

fn protocol_error_close() -> WafStreamClose {
  WafStreamClose {
    websocket_code: 1002,
    webtransport_code: 1,
    reason: "protocol error".to_string(),
  }
}
