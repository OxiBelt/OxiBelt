use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use fastwebsockets::{Frame, OpCode, Payload, Role, WebSocketWrite, after_handshake_split};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

mod activity_reader;
mod frame_reader;
mod task_guard;

use super::{
  OwnedWebSocketFrame, StreamWafBlocked, StreamWafRequestContext, WebSocketFrameOutcome,
  WebSocketMessageState, configure_reader_controls, inspect_websocket_frame, websocket_is_control,
};
use crate::bandwidth::{
  BandwidthDirection, BandwidthFlow, BandwidthGrant, RefundableBandwidthGrant,
  RouteBandwidthLimiter,
};
use crate::lifecycle::ConnectionDrain;
use crate::metrics::{BandwidthTrafficClass, Metrics};
use crate::state::AppSnapshot;
use crate::waf::{WafStreamClose, WafStreamDirection};
use activity_reader::ActivityReader;
use frame_reader::WebSocketFrameReader;
use task_guard::AbortTaskOnDrop;

type SharedWebSocketWriter<W> = Arc<Mutex<WebSocketWrite<W>>>;
// Defensive fallback for direct bridge users without a stream-WAF context.
const MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum BridgeActivity {
  Network,
  BandwidthWaitStarted,
  BandwidthWaitEnded,
}

#[derive(Debug)]
enum PumpError {
  Blocked(StreamWafBlocked),
  Other(anyhow::Error),
  PeerClosed,
}

impl From<anyhow::Error> for PumpError {
  fn from(error: anyhow::Error) -> Self {
    Self::Other(error)
  }
}

struct WebSocketDirectionPump<W> {
  reader: WebSocketFrameReader,
  writer: SharedWebSocketWriter<W>,
  state: Option<Arc<AppSnapshot>>,
  context: Option<StreamWafRequestContext>,
  messages: WebSocketMessageState,
  direction: WafStreamDirection,
  flow: Option<BandwidthFlow>,
  metrics: Arc<Metrics>,
  activity: mpsc::Sender<BridgeActivity>,
  deferred_data: Option<OwnedWebSocketFrame>,
  priority_data: Option<OwnedWebSocketFrame>,
  pending_waf_upload: Option<RefundableBandwidthGrant>,
  read_error_context: &'static str,
  write_error_context: &'static str,
}

impl<W> Drop for WebSocketDirectionPump<W> {
  fn drop(&mut self) {
    commit_pending_upload(&mut self.pending_waf_upload, self.metrics.as_ref());
  }
}

pub(crate) async fn bridge_websocket<D, U>(
  downstream: D,
  upstream: U,
  state: Arc<AppSnapshot>,
  context: Option<StreamWafRequestContext>,
  bandwidth: Option<Arc<RouteBandwidthLimiter>>,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (downstream_read, downstream_write) = tokio::io::split(downstream);
  let (upstream_read, upstream_write) = tokio::io::split(upstream);
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let downstream_read = ActivityReader::new(downstream_read, activity_tx.clone());
  let upstream_read = ActivityReader::new(upstream_read, activity_tx.clone());
  let (mut downstream_reader, downstream_writer) =
    after_handshake_split(downstream_read, downstream_write, Role::Server);
  let (mut upstream_reader, upstream_writer) =
    after_handshake_split(upstream_read, upstream_write, Role::Client);
  configure_reader_controls(&mut downstream_reader);
  configure_reader_controls(&mut upstream_reader);

  let downstream_writer = Arc::new(Mutex::new(downstream_writer));
  let upstream_writer = Arc::new(Mutex::new(upstream_writer));
  let max_payload_bytes = context
    .as_ref()
    .map_or(0, StreamWafRequestContext::max_payload_bytes);
  let metrics = state.metrics.clone();
  let upload = bandwidth
    .as_ref()
    .map(|limiter| limiter.flow(BandwidthDirection::Upload));
  let download = bandwidth
    .as_ref()
    .map(|limiter| limiter.flow(BandwidthDirection::Download));

  let mut upload_task = tokio::spawn(
    WebSocketDirectionPump {
      reader: WebSocketFrameReader::spawn(downstream_reader),
      writer: upstream_writer.clone(),
      state: context.as_ref().map(|_| state.clone()),
      context: context.clone(),
      messages: WebSocketMessageState::new(max_payload_bytes),
      direction: WafStreamDirection::DownstreamToUpstream,
      flow: upload,
      metrics: metrics.clone(),
      activity: activity_tx.clone(),
      deferred_data: None,
      priority_data: None,
      pending_waf_upload: None,
      read_error_context: "failed to read downstream WebSocket frame",
      write_error_context: "failed to forward downstream WebSocket frame",
    }
    .run(),
  );
  let mut download_task = tokio::spawn(
    WebSocketDirectionPump {
      reader: WebSocketFrameReader::spawn(upstream_reader),
      writer: downstream_writer.clone(),
      state: context.as_ref().map(|_| state),
      context,
      messages: WebSocketMessageState::new(max_payload_bytes),
      direction: WafStreamDirection::UpstreamToDownstream,
      flow: download,
      metrics,
      activity: activity_tx,
      deferred_data: None,
      priority_data: None,
      pending_waf_upload: None,
      read_error_context: "failed to read upstream WebSocket frame",
      write_error_context: "failed to forward upstream WebSocket frame",
    }
    .run(),
  );

  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);
  let mut bandwidth_waiters = 0usize;

  loop {
    tokio::select! {
      biased;
      result = &mut upload_task => {
        let finishing = finish_pump(
          result,
          &mut download_task,
          &downstream_writer,
          &upstream_writer,
        );
        tokio::pin!(finishing);
        return tokio::select! {
          biased;
          result = &mut finishing => result,
          _ = &mut idle => {
            Err(anyhow::anyhow!("WebSocket stream WAF bridge idle timeout elapsed"))
          }
          _ = &mut drain_close => {
            Ok(())
          }
        };
      }
      result = &mut download_task => {
        let finishing = finish_pump(
          result,
          &mut upload_task,
          &downstream_writer,
          &upstream_writer,
        );
        tokio::pin!(finishing);
        return tokio::select! {
          biased;
          result = &mut finishing => result,
          _ = &mut idle => {
            Err(anyhow::anyhow!("WebSocket stream WAF bridge idle timeout elapsed"))
          }
          _ = &mut drain_close => {
            Ok(())
          }
        };
      }
      activity = activity_rx.recv() => {
        let Some(activity) = activity else {
          upload_task.abort();
          download_task.abort();
          let _ = upload_task.await;
          let _ = download_task.await;
          return Ok(());
        };
        match activity {
          BridgeActivity::Network => {
            if bandwidth_waiters == 0 {
              idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
          }
          BridgeActivity::BandwidthWaitStarted => {
            bandwidth_waiters = bandwidth_waiters.saturating_add(1);
          }
          BridgeActivity::BandwidthWaitEnded => {
            bandwidth_waiters = bandwidth_waiters.saturating_sub(1);
            if bandwidth_waiters == 0 {
              idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
          }
        }
      }
      _ = &mut idle, if bandwidth_waiters == 0 => {
        upload_task.abort();
        download_task.abort();
        let _ = upload_task.await;
        let _ = download_task.await;
        return Err(anyhow::anyhow!("WebSocket stream WAF bridge idle timeout elapsed"));
      }
      _ = &mut drain_close => {
        upload_task.abort();
        download_task.abort();
        let _ = upload_task.await;
        let _ = download_task.await;
        return Ok(());
      }
    }
  }
}

async fn finish_pump<D, U>(
  result: Result<Result<(), PumpError>, tokio::task::JoinError>,
  other: &mut JoinHandle<Result<(), PumpError>>,
  downstream: &SharedWebSocketWriter<D>,
  upstream: &SharedWebSocketWriter<U>,
) -> anyhow::Result<()>
where
  D: AsyncWrite + Unpin,
  U: AsyncWrite + Unpin,
{
  let result = result.context("WebSocket bridge task panicked")?;
  let other = AbortTaskOnDrop(other);
  if !matches!(&result, Err(PumpError::PeerClosed)) {
    other.0.abort();
  }
  let _ = (&mut *other.0).await;
  match result {
    Ok(()) => Ok(()),
    Err(PumpError::PeerClosed) => Ok(()),
    Err(PumpError::Other(error)) => Err(error),
    Err(PumpError::Blocked(blocked)) => {
      if let Some(close) = blocked.close_option() {
        close_websocket_pair(downstream, upstream, close).await;
      }
      Ok(())
    }
  }
}

impl<W> WebSocketDirectionPump<W>
where
  W: AsyncWrite + Unpin,
{
  async fn run(mut self) -> Result<(), PumpError> {
    loop {
      let frame = match self.take_deferred_data() {
        Some(frame) => frame,
        None => {
          let max_payload_bytes = self.reader_payload_limit();
          self
            .reader
            .next(max_payload_bytes)
            .await
            .with_context(|| self.read_error_context)
            .map_err(PumpError::Other)?
        }
      };
      if websocket_is_control(frame.opcode) {
        if self.inspect_and_forward_control(frame).await? {
          return Err(PumpError::PeerClosed);
        }
        continue;
      }

      let upload_before_waf =
        if self.direction == WafStreamDirection::DownstreamToUpstream && self.context.is_some() {
          self
            .flow
            .as_ref()
            .map(BandwidthFlow::is_limited)
            .transpose()
            .map_err(|error| PumpError::Other(error.into()))?
            .unwrap_or(false)
        } else {
          false
        };
      if upload_before_waf {
        let Some(mut flow) = self.flow.take() else {
          return Err(PumpError::Other(anyhow::anyhow!(
            "upload bandwidth flow disappeared before WebSocket WAF inspection"
          )));
        };
        let reservation = self
          .reserve_refundable_with_lookahead(&mut flow, frame.payload.len())
          .await;
        self.flow = Some(flow);
        reservation?;
      }

      let outcome = self.inspect_or_commit_pending(frame)?;
      if upload_before_waf {
        if outcome.frames.is_empty() {
          continue;
        }
        self.refund_pending_upload();
        self.forward_frames(outcome.frames).await?;
      } else {
        self.forward_frames(outcome.frames).await?;
      }
      if outcome.peer_close {
        return Ok(());
      }
    }
  }

  fn inspect(&mut self, frame: OwnedWebSocketFrame) -> Result<WebSocketFrameOutcome, PumpError> {
    let Some(context) = self.context.as_ref() else {
      return Ok(WebSocketFrameOutcome {
        peer_close: frame.opcode == OpCode::Close,
        frames: vec![frame],
      });
    };
    let Some(state) = self.state.as_ref() else {
      return Err(PumpError::Other(anyhow::anyhow!(
        "WebSocket stream WAF snapshot state is unavailable"
      )));
    };
    inspect_websocket_frame(
      state.as_ref(),
      context,
      self.direction,
      frame,
      &mut self.messages,
    )
    .map_err(PumpError::Blocked)
  }

  fn inspect_or_commit_pending(
    &mut self,
    frame: OwnedWebSocketFrame,
  ) -> Result<WebSocketFrameOutcome, PumpError> {
    match self.inspect(frame) {
      Ok(outcome) => Ok(outcome),
      Err(error) => {
        self.commit_pending_upload();
        Err(error)
      }
    }
  }

  async fn inspect_and_forward_control(
    &mut self,
    frame: OwnedWebSocketFrame,
  ) -> Result<bool, PumpError> {
    let outcome = self.inspect_or_commit_pending(frame)?;
    let peer_close = outcome.peer_close;
    self.forward_frames_unlimited(outcome.frames).await?;
    Ok(peer_close)
  }

  fn take_deferred_data(&mut self) -> Option<OwnedWebSocketFrame> {
    let frame = self.deferred_data.take()?;
    self.deferred_data = self.priority_data.take();
    Some(frame)
  }

  fn can_read_lookahead(&self) -> bool {
    self.priority_data.is_none()
  }

  fn reader_payload_limit(&self) -> usize {
    match self.context.as_ref() {
      Some(context) => context.max_payload_bytes(),
      None => MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES,
    }
  }

  fn defer_data(&mut self, frame: OwnedWebSocketFrame) -> Result<(), PumpError> {
    if self.deferred_data.is_none() {
      self.deferred_data = Some(frame);
      return Ok(());
    }
    if self.priority_data.is_none() {
      self.priority_data = Some(frame);
      return Ok(());
    }
    Err(PumpError::Other(anyhow::anyhow!(
      "WebSocket control-priority lookahead capacity was exceeded"
    )))
  }

  async fn forward_frames(&mut self, frames: Vec<OwnedWebSocketFrame>) -> Result<(), PumpError> {
    let Some(mut flow) = self.flow.take() else {
      return self.forward_frames_unlimited(frames).await;
    };
    let result = self.forward_frames_shaped(&mut flow, frames).await;
    self.flow = Some(flow);
    result
  }

  async fn forward_frames_unlimited(
    &mut self,
    frames: Vec<OwnedWebSocketFrame>,
  ) -> Result<(), PumpError> {
    for frame in frames {
      self.write_owned_frame(frame).await?;
    }
    Ok(())
  }

  async fn forward_frames_shaped(
    &mut self,
    flow: &mut BandwidthFlow,
    frames: Vec<OwnedWebSocketFrame>,
  ) -> Result<(), PumpError> {
    for frame in frames {
      if frame.payload.is_empty() {
        self.write_owned_frame(frame).await?;
        continue;
      }
      if !flow
        .is_limited()
        .map_err(|error| PumpError::Other(error.into()))?
      {
        self.write_owned_frame(frame).await?;
        continue;
      }
      let mut offset = 0usize;
      while offset < frame.payload.len() {
        let limited = flow
          .is_limited()
          .map_err(|error| PumpError::Other(error.into()))?;
        let grant = if limited {
          self
            .acquire_with_lookahead(flow, frame.payload.len() - offset)
            .await?
        } else {
          ShapedGrant {
            bytes: frame.payload.len() - offset,
            peer_closed: false,
          }
        };
        if grant.peer_closed {
          return Err(PumpError::PeerClosed);
        }
        let end = offset + grant.bytes;
        self
          .write_fragment(&frame, offset, end, end == frame.payload.len())
          .await?;
        offset = end;
      }
    }
    Ok(())
  }

  async fn reserve_refundable_with_lookahead(
    &mut self,
    flow: &mut BandwidthFlow,
    mut remaining: usize,
  ) -> Result<(), PumpError> {
    while remaining > 0 {
      if !flow
        .is_limited()
        .map_err(|error| PumpError::Other(error.into()))?
      {
        break;
      }
      send_activity(self.activity.clone(), BridgeActivity::BandwidthWaitStarted).await?;
      let result = if self.can_read_lookahead() {
        let max_payload_bytes = self.reader_payload_limit();
        self
          .reader
          .prepare(max_payload_bytes)
          .await
          .with_context(|| self.read_error_context)
          .map_err(PumpError::Other)?;
        tokio::select! {
          biased;
          frame = self.reader.receive_prepared() => RefundableAcquisitionResult::Frame(frame),
          grant = flow.acquire_refundable(remaining) => RefundableAcquisitionResult::Grant(grant),
        }
      } else {
        RefundableAcquisitionResult::Grant(flow.acquire_refundable(remaining).await)
      };
      send_activity(self.activity.clone(), BridgeActivity::BandwidthWaitEnded).await?;
      match result {
        RefundableAcquisitionResult::Grant(grant) => {
          let grant = grant.map_err(|error| PumpError::Other(error.into()))?;
          remaining -= grant.bytes();
          if let Some(pending) = self.pending_waf_upload.as_mut() {
            pending
              .merge(grant)
              .map_err(|error| PumpError::Other(error.into()))?;
          } else {
            self.pending_waf_upload = Some(grant);
          }
        }
        RefundableAcquisitionResult::Frame(frame) => {
          let frame = frame
            .with_context(|| self.read_error_context)
            .map_err(PumpError::Other)?;
          if websocket_is_control(frame.opcode) {
            if self.inspect_and_forward_control(frame).await? {
              return Err(PumpError::PeerClosed);
            }
          } else {
            self.defer_data(frame)?;
          }
        }
      }
    }
    Ok(())
  }

  fn commit_pending_upload(&mut self) {
    commit_pending_upload(&mut self.pending_waf_upload, self.metrics.as_ref());
  }

  fn refund_pending_upload(&mut self) {
    if let Some(reservation) = self.pending_waf_upload.take() {
      reservation.refund();
    }
  }

  async fn acquire_with_lookahead(
    &mut self,
    flow: &mut BandwidthFlow,
    requested: usize,
  ) -> Result<ShapedGrant, PumpError> {
    loop {
      send_activity(self.activity.clone(), BridgeActivity::BandwidthWaitStarted).await?;
      let result = if self.can_read_lookahead() {
        let max_payload_bytes = self.reader_payload_limit();
        self
          .reader
          .prepare(max_payload_bytes)
          .await
          .with_context(|| self.read_error_context)
          .map_err(PumpError::Other)?;
        tokio::select! {
          biased;
          frame = self.reader.receive_prepared() => AcquisitionResult::Frame(frame),
          grant = flow.acquire(requested) => AcquisitionResult::Grant(grant),
        }
      } else {
        AcquisitionResult::Grant(flow.acquire(requested).await)
      };
      send_activity(self.activity.clone(), BridgeActivity::BandwidthWaitEnded).await?;

      match result {
        AcquisitionResult::Grant(grant) => {
          let grant = grant.map_err(|error| PumpError::Other(error.into()))?;
          self.record_grant(flow, grant);
          return Ok(ShapedGrant {
            bytes: grant.bytes(),
            peer_closed: false,
          });
        }
        AcquisitionResult::Frame(frame) => {
          let frame = frame
            .with_context(|| self.read_error_context)
            .map_err(PumpError::Other)?;
          if websocket_is_control(frame.opcode) {
            if self.inspect_and_forward_control(frame).await? {
              return Ok(ShapedGrant {
                bytes: 0,
                peer_closed: true,
              });
            }
          } else {
            self.defer_data(frame)?;
          }
        }
      }
    }
  }

  fn record_grant(&self, flow: &BandwidthFlow, grant: BandwidthGrant) {
    self.record_grant_values(flow.direction(), grant.bytes(), grant.waited());
  }

  fn record_grant_values(&self, direction: BandwidthDirection, bytes: usize, waited: Duration) {
    self.metrics.record_bandwidth_shaped_bytes(
      direction,
      BandwidthTrafficClass::WebSocket,
      bytes as u64,
    );
    if !waited.is_zero() {
      self
        .metrics
        .record_bandwidth_wait(direction, BandwidthTrafficClass::WebSocket, waited);
    }
  }

  async fn write_fragment(
    &mut self,
    frame: &OwnedWebSocketFrame,
    start: usize,
    end: usize,
    last: bool,
  ) -> Result<(), PumpError> {
    let opcode = if start == 0 {
      frame.opcode
    } else {
      OpCode::Continuation
    };
    self
      .write_owned_frame(OwnedWebSocketFrame {
        fin: frame.fin && last,
        opcode,
        payload: frame.payload[start..end].to_vec(),
      })
      .await
  }

  async fn write_owned_frame(&mut self, frame: OwnedWebSocketFrame) -> Result<(), PumpError> {
    let mut writer = self.writer.lock().await;
    writer
      .write_frame(Frame::new(
        frame.fin,
        frame.opcode,
        None,
        Payload::Owned(frame.payload),
      ))
      .await
      .with_context(|| self.write_error_context)
      .map_err(PumpError::Other)?;
    writer
      .flush()
      .await
      .with_context(|| self.write_error_context)
      .map_err(PumpError::Other)?;
    drop(writer);
    send_activity(self.activity.clone(), BridgeActivity::Network).await
  }
}

fn commit_pending_upload(pending: &mut Option<RefundableBandwidthGrant>, metrics: &Metrics) {
  if let Some(reservation) = pending.take() {
    let waited = reservation.waited();
    let grant = reservation.commit();
    metrics.record_bandwidth_shaped_bytes(
      BandwidthDirection::Upload,
      BandwidthTrafficClass::WebSocket,
      grant.bytes() as u64,
    );
    if !waited.is_zero() {
      metrics.record_bandwidth_wait(
        BandwidthDirection::Upload,
        BandwidthTrafficClass::WebSocket,
        waited,
      );
    }
  }
}

async fn send_activity(
  activity_tx: mpsc::Sender<BridgeActivity>,
  activity: BridgeActivity,
) -> Result<(), PumpError> {
  activity_tx.send(activity).await.map_err(|_| {
    PumpError::Other(anyhow::anyhow!(
      "WebSocket bridge activity supervisor stopped"
    ))
  })
}

enum AcquisitionResult {
  Grant(Result<BandwidthGrant, crate::bandwidth::BandwidthError>),
  Frame(anyhow::Result<OwnedWebSocketFrame>),
}

enum RefundableAcquisitionResult {
  Grant(Result<RefundableBandwidthGrant, crate::bandwidth::BandwidthError>),
  Frame(anyhow::Result<OwnedWebSocketFrame>),
}

struct ShapedGrant {
  bytes: usize,
  peer_closed: bool,
}

async fn close_websocket_pair<D, U>(
  downstream: &SharedWebSocketWriter<D>,
  upstream: &SharedWebSocketWriter<U>,
  close: &WafStreamClose,
) where
  D: AsyncWrite + Unpin,
  U: AsyncWrite + Unpin,
{
  let mut downstream = downstream.lock().await;
  if let Err(error) = downstream
    .write_frame(Frame::close(close.websocket_code, close.reason.as_bytes()))
    .await
  {
    warn!(error = %error, "failed to send downstream WebSocket WAF close frame");
  }
  let _ = downstream.flush().await;
  drop(downstream);

  let mut upstream = upstream.lock().await;
  if let Err(error) = upstream
    .write_frame(Frame::close(close.websocket_code, close.reason.as_bytes()))
    .await
  {
    warn!(error = %error, "failed to send upstream WebSocket WAF close frame");
  }
  let _ = upstream.flush().await;
}

#[cfg(test)]
mod supervisor_tests;
#[cfg(test)]
mod tests;
