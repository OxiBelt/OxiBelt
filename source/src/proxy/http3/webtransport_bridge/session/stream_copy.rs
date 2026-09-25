//! WebTransport stream forwarding with WAF and bandwidth enforcement.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use h3_webtransport::SessionId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{mpsc, watch};

use super::flow::SessionFlow;
use super::traffic_shaping::{acquire_stream_bandwidth, bandwidth_direction};
use super::{
  DispatcherEvent, UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream,
  UpstreamWebTransportSession, report_activity,
};

pub(super) struct FlowRecv {
  inner: super::super::DownstreamUniRecvStream,
  flow: Option<Arc<SessionFlow>>,
  events: mpsc::Sender<DispatcherEvent>,
  session_id: SessionId,
  header_size: u64,
  body_seen: u64,
  bidi: bool,
  complete: bool,
}

impl FlowRecv {
  pub fn new(
    inner: super::super::DownstreamUniRecvStream,
    flow: Option<Arc<SessionFlow>>,
    events: mpsc::Sender<DispatcherEvent>,
    session_id: SessionId,
    bidi: bool,
  ) -> Self {
    let header_size = inner.webtransport_header_size().unwrap_or(u64::MAX);
    Self {
      inner,
      flow,
      events,
      session_id,
      header_size,
      body_seen: 0,
      bidi,
      complete: false,
    }
  }

  fn fail(&self) {
    if self
      .events
      .try_send(DispatcherEvent::FlowError(self.session_id))
      .is_err()
    {
      let events = self.events.clone();
      let session_id = self.session_id;
      tokio::spawn(async move {
        let _ = events.send(DispatcherEvent::FlowError(session_id)).await;
      });
    }
  }

  fn complete(&mut self, reset: bool) -> std::io::Result<()> {
    if self.complete {
      return Ok(());
    }
    let Some(flow) = self.flow.as_ref() else {
      self.complete = true;
      return Ok(());
    };
    if reset {
      let Some(info) = self.inner.inner_mut().reset_info() else {
        return Ok(());
      };
      if let Err(error) = flow.incoming_reset(self.body_seen, info.final_size, self.header_size) {
        self.fail();
        return Err(std::io::Error::other(format!(
          "WebTransport reset final size: {error:?}"
        )));
      }
    }
    if let Err(error) = flow.incoming_closed(self.bidi) {
      self.fail();
      return Err(std::io::Error::other(format!(
        "WebTransport stream count: {error:?}"
      )));
    }
    self.complete = true;
    Ok(())
  }
}

impl AsyncRead for FlowRecv {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut tokio::io::ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    if buf.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }
    let before = buf.filled().len();
    match Pin::new(&mut self.inner).poll_read(cx, buf) {
      Poll::Ready(Ok(())) => {
        let n = buf.filled().len() - before;
        if n == 0 {
          if let Some(reset) = self.inner.inner_mut().reset_info() {
            let result = self.complete(true);
            return Poll::Ready(result.and_then(|()| Err(reset_error_at_eof(reset))));
          }
          return Poll::Ready(self.complete(false));
        }
        if let Some(flow) = self.flow.clone() {
          self.body_seen = match self.body_seen.checked_add(n as u64) {
            Some(value) => value,
            None => {
              self.fail();
              return Poll::Ready(Err(std::io::Error::other(
                "WebTransport body size overflow",
              )));
            }
          };
          if let Err(error) = flow.incoming_data(n as u64) {
            self.fail();
            return Poll::Ready(Err(std::io::Error::other(format!(
              "WebTransport data credit: {error:?}"
            ))));
          }
        }
        Poll::Ready(Ok(()))
      }
      Poll::Ready(Err(error)) => {
        if let Err(flow_error) = self.complete(true) {
          Poll::Ready(Err(flow_error))
        } else {
          Poll::Ready(Err(error))
        }
      }
      Poll::Pending => Poll::Pending,
    }
  }
}

impl StoppableRecv for FlowRecv {
  fn stop(&mut self, code: u32) -> std::io::Result<()> {
    self.inner.stop(code)
  }
}

pub(super) struct FlowSend {
  inner: super::super::DownstreamUniSendStream,
  flow: Option<Arc<SessionFlow>>,
}

impl FlowSend {
  pub fn new(inner: super::super::DownstreamUniSendStream, flow: Option<Arc<SessionFlow>>) -> Self {
    Self { inner, flow }
  }
}

impl AsyncWrite for FlowSend {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    let Some(flow) = self.flow.clone() else {
      return Pin::new(&mut self.inner).poll_write(cx, buf);
    };
    if buf.is_empty() {
      return Poll::Ready(Ok(0));
    }
    let mut outgoing = flow
      .outgoing
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);
    let available = outgoing.max_data.saturating_sub(outgoing.used_data);
    if available == 0 {
      flow.register_outgoing(cx.waker());
      if outgoing.max_data == outgoing.used_data {
        return Poll::Pending;
      }
    }
    let max = usize::try_from(available)
      .unwrap_or(usize::MAX)
      .min(buf.len());
    let result = Pin::new(&mut self.inner).poll_write(cx, &buf[..max]);
    if let Poll::Ready(Ok(written)) = result
      && outgoing.use_data(written as u64).is_err()
    {
      return Poll::Ready(Err(std::io::Error::other(
        "WebTransport send credit accounting failed",
      )));
    }
    result
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

impl ResettableSend for FlowSend {
  fn reset(&mut self, code: u32) -> std::io::Result<()> {
    self.inner.reset(code)
  }
}

impl StopAwareSend for FlowSend {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<u32>> {
    self.inner.poll_stopped(context)
  }
}
use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};
use crate::metrics::Metrics;
use crate::proxy::stream_waf::{self as stream_waf_bridge, StreamWafRequestContext};
use crate::state::AppSnapshot;
use crate::waf::{WafStreamDirection, WafWebTransportStreamKind};

pub(super) trait ResettableSend {
  fn reset(&mut self, code: u32) -> std::io::Result<()>;
}

pub(super) trait StoppableRecv {
  fn stop(&mut self, code: u32) -> std::io::Result<()>;
}

pub(super) trait StopAwareSend {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<u32>>;
}

enum SendProgress<T> {
  Progress(T),
  Stopped(u32),
}

impl<T> ResettableSend for &mut T
where
  T: ResettableSend + ?Sized,
{
  fn reset(&mut self, code: u32) -> std::io::Result<()> {
    (**self).reset(code)
  }
}

impl<T> StoppableRecv for &mut T
where
  T: StoppableRecv + ?Sized,
{
  fn stop(&mut self, code: u32) -> std::io::Result<()> {
    (**self).stop(code)
  }
}

impl<T> StopAwareSend for &mut T
where
  T: StopAwareSend + ?Sized,
{
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<u32>> {
    (**self).poll_stopped(context)
  }
}

impl ResettableSend for UpstreamWebTransportSendStream {
  fn reset(&mut self, code: u32) -> std::io::Result<()> {
    UpstreamWebTransportSendStream::reset(self, code)
  }
}

impl ResettableSend for super::super::DownstreamUniSendStream {
  fn reset(&mut self, code: u32) -> std::io::Result<()> {
    self
      .inner_mut()
      .reset_webtransport(super::super::h3_application_code_to_wire(code))
  }
}

impl StoppableRecv for UpstreamWebTransportRecvStream {
  fn stop(&mut self, code: u32) -> std::io::Result<()> {
    UpstreamWebTransportRecvStream::stop(self, code)
  }
}

impl StoppableRecv for super::super::DownstreamUniRecvStream {
  fn stop(&mut self, code: u32) -> std::io::Result<()> {
    h3::quic::RecvStream::stop_sending(self, super::super::h3_application_code_to_wire(code));
    Ok(())
  }
}

impl StopAwareSend for UpstreamWebTransportSendStream {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<u32>> {
    UpstreamWebTransportSendStream::poll_stopped(self, context)
  }
}

// h3 does not expose a separate STOP_SENDING future for request-stream send
// halves. An empty unframed send reaches Quinn's stopped check before it
// attempts to write, so the bounded watchdog in `copy_one_way` can forward an
// otherwise idle downstream STOP_SENDING without injecting application bytes.
impl StopAwareSend for super::super::DownstreamUniSendStream {
  fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<u32>> {
    let mut empty = bytes::Bytes::new();
    match h3::quic::SendStreamUnframed::poll_send(self, context, &mut empty) {
      Poll::Ready(Err(h3::quic::StreamErrorIncoming::StreamTerminated { error_code })) => {
        match super::super::h3_application_code_from_wire(error_code) {
          Some(code) => Poll::Ready(Ok(code)),
          None => Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "downstream HTTP/3 STOP_SENDING used a non-WebTransport error code",
          ))),
        }
      }
      Poll::Ready(Err(error)) => Poll::Ready(Err(std::io::Error::other(error))),
      Poll::Ready(Ok(_)) | Poll::Pending => Poll::Pending,
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn copy_bidi_stream(
  session_id: SessionId,
  downstream: super::super::DownstreamBidiStream,
  upstream: Arc<UpstreamWebTransportSession>,
  mut abrupt_reset_rx: watch::Receiver<bool>,
  flow: Option<Arc<SessionFlow>>,
  mut upstream_send: UpstreamWebTransportSendStream,
  mut upstream_recv: UpstreamWebTransportRecvStream,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
  // Split at the QUIC boundary rather than with Tokio I/O.  The resulting
  // send half still implements h3::quic::SendStream, so a reset received from
  // an H2 capsule stream can retain its WebTransport application code when it
  // is forwarded to the downstream H3 stream.
  let (downstream_send, downstream_recv) = h3::quic::BidiStream::split(downstream);
  let mut downstream_send = FlowSend::new(downstream_send, flow.clone());
  let mut downstream_recv =
    FlowRecv::new(downstream_recv, flow, activity.clone(), session_id, true);
  let downstream_to_upstream = copy_one_way(
    session_id,
    &mut downstream_recv,
    &mut upstream_send,
    activity.clone(),
    WafStreamDirection::DownstreamToUpstream,
    WafWebTransportStreamKind::Bidi,
    stream_waf_state.clone(),
    stream_waf.clone(),
    bandwidth.clone(),
    metrics.clone(),
  );
  let upstream_to_downstream = copy_one_way(
    session_id,
    &mut upstream_recv,
    &mut downstream_send,
    activity.clone(),
    WafStreamDirection::UpstreamToDownstream,
    WafWebTransportStreamKind::Bidi,
    stream_waf_state,
    stream_waf,
    bandwidth,
    metrics,
  );
  let result = tokio::try_join!(downstream_to_upstream, upstream_to_downstream);
  if let Err(error) = &result
    && (upstream.abrupt_h3_close() || is_upstream_quic_connection_loss(error))
  {
    // The upstream QUIC connection can fail before the session control task
    // publishes its CONNECT reset. Keep the downstream receive half alive;
    // Quinn would otherwise send STOP_SENDING(0) on Drop and browsers would
    // surface a stream error instead of the session failure.
    let _ = activity
      .send(DispatcherEvent::SessionEnded(session_id))
      .await;
    wait_for_abrupt_reset(&mut abrupt_reset_rx).await;
    let mut buffer = [0; 1024];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
      while matches!(downstream_recv.read(&mut buffer).await, Ok(1..)) {}
    })
    .await;
  }
  result.map(|_| ())
}

pub(super) async fn wait_for_abrupt_reset(reset: &mut watch::Receiver<bool>) {
  let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
    while !*reset.borrow() {
      if reset.changed().await.is_err() {
        return;
      }
    }
  })
  .await;
}

fn is_upstream_quic_connection_loss(error: &anyhow::Error) -> bool {
  let cause = error
    .downcast_ref::<std::io::Error>()
    .and_then(std::io::Error::get_ref);
  cause.is_some_and(|cause| {
    matches!(
      cause.downcast_ref::<h3_quinn::quinn::ReadError>(),
      Some(h3_quinn::quinn::ReadError::ConnectionLost(_))
    ) || matches!(
      cause.downcast_ref::<h3_quinn::quinn::WriteError>(),
      Some(h3_quinn::quinn::WriteError::ConnectionLost(_))
    )
  })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn copy_one_way<R, W>(
  session_id: SessionId,
  mut recv: R,
  mut send: W,
  activity: mpsc::Sender<DispatcherEvent>,
  direction: WafStreamDirection,
  stream_kind: WafWebTransportStreamKind,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<()>
where
  R: AsyncRead + StoppableRecv + Unpin,
  W: AsyncWrite + ResettableSend + StopAwareSend + Unpin,
{
  let mut buffer = vec![0u8; 16 * 1024];
  let bandwidth_direction = bandwidth_direction(direction);
  let mut bandwidth_flow = bandwidth.flow(bandwidth_direction);
  loop {
    let read = match tokio::select! {
      biased;
      stopped = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        std::future::poll_fn(|context| send.poll_stopped(context)),
      ) => {
        let Ok(stopped) = stopped else { continue; };
        recv.stop(stopped?)?;
        return Ok(());
      }
      read = recv.read(&mut buffer) => read,
    } {
      Ok(read) => read,
      Err(error) => {
        if let Some(code) = received_reset_code(&error) {
          // Preserve bytes already delivered by QUIC when the next hop uses
          // the H2 reliable-reset capsule. Quinn's own flush remains a no-op.
          return match flush_or_stop(&mut send).await? {
            SendProgress::Progress(()) => {
              send.reset(code)?;
              Ok(())
            }
            SendProgress::Stopped(code) => {
              recv.stop(code)?;
              Ok(())
            }
          };
        }
        return Err(error.into());
      }
    };
    if read == 0 {
      return match shutdown_or_stop(&mut send).await? {
        SendProgress::Progress(()) => Ok(()),
        SendProgress::Stopped(code) => {
          recv.stop(code)?;
          Ok(())
        }
      };
    }
    if bandwidth_direction == crate::bandwidth::BandwidthDirection::Download
      && let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref())
    {
      stream_waf_bridge::check_webtransport_payload(
        state.as_ref(),
        Some(context),
        direction,
        &buffer[..read],
        stream_waf_bridge::webtransport_stream_metadata(stream_kind),
      )?;
    }
    let mut offset = 0;
    while offset < read {
      let bandwidth_limited = bandwidth_flow.is_limited().map_err(anyhow::Error::from)?;
      let granted = if bandwidth_limited {
        let acquisition = acquire_stream_bandwidth(
          session_id,
          &activity,
          &mut bandwidth_flow,
          read - offset,
          &metrics,
          bandwidth_direction,
        );
        tokio::pin!(acquisition);
        loop {
          tokio::select! {
            biased;
            stopped = std::future::poll_fn(|context| send.poll_stopped(context)) => {
              recv.stop(stopped?)?;
              return Ok(());
            }
            grant = &mut acquisition => break grant?,
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
              // The downstream H3 adapter detects STOP_SENDING with an empty
              // send probe. Re-poll it even if that transport does not wake the
              // bandwidth waiter when the peer stops the stream.
            }
          }
        }
      } else {
        read - offset
      };
      if bandwidth_direction == BandwidthDirection::Upload
        && let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref())
      {
        stream_waf_bridge::check_webtransport_payload(
          state.as_ref(),
          Some(context),
          direction,
          &buffer[offset..offset + granted],
          stream_waf_bridge::webtransport_stream_metadata(stream_kind),
        )?;
      }
      match write_or_stop(&mut send, &buffer[offset..offset + granted]).await? {
        SendProgress::Progress(written) => offset += written,
        SendProgress::Stopped(code) => {
          recv.stop(code)?;
          return Ok(());
        }
      }
    }
    report_activity(&activity, session_id);
  }
}

fn received_reset_code(error: &std::io::Error) -> Option<u32> {
  crate::webtransport::stream_reset_code(error).or_else(|| {
    let h3::quic::StreamErrorIncoming::StreamTerminated { error_code } =
      error
        .get_ref()?
        .downcast_ref::<h3::quic::StreamErrorIncoming>()?
    else {
      return None;
    };
    super::super::h3_application_code_from_wire(*error_code)
  })
}

fn reset_error_at_eof(reset: h3_quinn::quinn::ResetInfo) -> std::io::Error {
  std::io::Error::other(h3::quic::StreamErrorIncoming::StreamTerminated {
    error_code: reset.error_code.into_inner(),
  })
}

async fn write_or_stop<W>(send: &mut W, bytes: &[u8]) -> std::io::Result<SendProgress<usize>>
where
  W: AsyncWrite + StopAwareSend + Unpin,
{
  std::future::poll_fn(|context| match send.poll_stopped(context) {
    Poll::Ready(Ok(code)) => Poll::Ready(Ok(SendProgress::Stopped(code))),
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => match std::pin::Pin::new(&mut *send).poll_write(context, bytes) {
      Poll::Ready(Ok(0)) if !bytes.is_empty() => Poll::Ready(Err(std::io::Error::new(
        std::io::ErrorKind::WriteZero,
        "failed to forward WebTransport stream payload",
      ))),
      Poll::Ready(Ok(written)) => Poll::Ready(Ok(SendProgress::Progress(written))),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    },
  })
  .await
}

async fn shutdown_or_stop<W>(send: &mut W) -> std::io::Result<SendProgress<()>>
where
  W: AsyncWrite + StopAwareSend + Unpin,
{
  std::future::poll_fn(|context| match send.poll_stopped(context) {
    Poll::Ready(Ok(code)) => Poll::Ready(Ok(SendProgress::Stopped(code))),
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => match std::pin::Pin::new(&mut *send).poll_shutdown(context) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(SendProgress::Progress(()))),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    },
  })
  .await
}

async fn flush_or_stop<W>(send: &mut W) -> std::io::Result<SendProgress<()>>
where
  W: AsyncWrite + StopAwareSend + Unpin,
{
  std::future::poll_fn(|context| match send.poll_stopped(context) {
    Poll::Ready(Ok(code)) => Poll::Ready(Ok(SendProgress::Stopped(code))),
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => match std::pin::Pin::new(&mut *send).poll_flush(context) {
      Poll::Ready(Ok(())) => Poll::Ready(Ok(SendProgress::Progress(()))),
      Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
      Poll::Pending => Poll::Pending,
    },
  })
  .await
}

#[cfg(test)]
mod tests {
  use std::pin::Pin;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
  use std::task::{Context, Poll, Waker};

  use tokio::io::AsyncWrite;

  use super::{
    SendProgress, StopAwareSend, received_reset_code, reset_error_at_eof, wait_for_abrupt_reset,
    write_or_stop,
  };

  #[tokio::test]
  async fn abrupt_child_waits_until_connect_reset_is_published() {
    let (published, mut observer) = tokio::sync::watch::channel(false);
    let mut child = tokio::spawn(async move { wait_for_abrupt_reset(&mut observer).await });
    assert!(
      tokio::time::timeout(std::time::Duration::from_millis(20), &mut child)
        .await
        .is_err()
    );
    published.send_replace(true);
    tokio::time::timeout(std::time::Duration::from_secs(1), child)
      .await
      .expect("child did not observe CONNECT reset")
      .expect("child task panicked");
  }

  #[derive(Default)]
  struct StopState {
    code: AtomicU32,
    waker: std::sync::Mutex<Option<Waker>>,
  }

  struct PendingSend {
    state: Arc<StopState>,
    writes: Arc<AtomicUsize>,
  }

  impl StopAwareSend for PendingSend {
    fn poll_stopped(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<u32>> {
      let code = self.state.code.load(Ordering::Acquire);
      if code != 0 {
        return Poll::Ready(Ok(code - 1));
      }
      *self.state.waker.lock().unwrap() = Some(context.waker().clone());
      Poll::Pending
    }
  }

  impl AsyncWrite for PendingSend {
    fn poll_write(
      self: Pin<&mut Self>,
      _: &mut Context<'_>,
      _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
      self.writes.fetch_add(1, Ordering::AcqRel);
      Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
      Poll::Pending
    }
  }

  #[tokio::test]
  async fn stop_preempts_a_blocked_stream_write_without_a_write_error() {
    let state = Arc::new(StopState::default());
    let writes = Arc::new(AtomicUsize::new(0));
    let mut task = tokio::spawn({
      let state = state.clone();
      let writes = writes.clone();
      async move {
        let mut send = PendingSend { state, writes };
        write_or_stop(&mut send, b"buffered").await.unwrap()
      }
    });

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
      while writes.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("write helper was not polled");
    state.code.store(4_322, Ordering::Release);
    if let Some(waker) = state.waker.lock().unwrap().take() {
      waker.wake();
    }

    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut task)
      .await
      .expect("STOP_SENDING did not interrupt the blocked write")
      .expect("write task panicked")
    {
      SendProgress::Stopped(code) => assert_eq!(code, 4_321),
      SendProgress::Progress(_) => {
        panic!("blocked write completed instead of observing STOP_SENDING")
      }
    }
  }

  #[test]
  fn downstream_h3_reset_preserves_the_webtransport_application_code() {
    let code = 4_321;
    let error = std::io::Error::other(h3::quic::StreamErrorIncoming::StreamTerminated {
      error_code: super::super::super::h3_application_code_to_wire(code),
    });

    assert_eq!(received_reset_code(&error), Some(code));
  }

  #[test]
  fn reset_at_eof_is_forwarded_as_reset_instead_of_fin() {
    let code = 95;
    let error = reset_error_at_eof(h3_quinn::quinn::ResetInfo {
      error_code: h3_quinn::quinn::VarInt::from_u64(
        super::super::super::h3_application_code_to_wire(code),
      )
      .expect("valid WebTransport error code"),
      final_size: 2,
      reliable_size: None,
    });
    assert_eq!(received_reset_code(&error), Some(code));
  }
}
