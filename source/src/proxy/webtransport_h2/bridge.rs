//! Stream and datagram forwarding for a downstream HTTP/2 capsule session.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};
use crate::metrics::{BandwidthTrafficClass, Metrics};
use crate::proxy::http3::{
  UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream, UpstreamWebTransportSession,
};
use crate::proxy::stream_waf::{self, StreamWafRequestContext};
use crate::state::AppSnapshot;
use crate::waf::{WafStreamDirection, WafWebTransportStreamKind};

const PROTOCOL_ERROR: u32 = 1;
const MAX_DATAGRAM_BYTES: usize = 65_535;

mod io;
use io::{
  ReadControl, ResettableSend, SendControl, StopAwareSend, StoppableRecv, forward_reset,
  read_or_stop, shutdown_or_stop, write_all_or_stop,
};

/// Activity is shared by every virtual stream and capsule direction so the
/// route idle timeout covers an H2 session just as it covers the H3 bridge.
#[derive(Clone)]
pub(super) struct Activity(Arc<ActivityInner>);

struct ActivityInner {
  last: std::sync::Mutex<tokio::time::Instant>,
  bandwidth_waiters: AtomicUsize,
  changed: tokio::sync::Notify,
}

impl Activity {
  pub(super) fn new() -> Self {
    Self(Arc::new(ActivityInner {
      last: std::sync::Mutex::new(tokio::time::Instant::now()),
      bandwidth_waiters: AtomicUsize::new(0),
      changed: tokio::sync::Notify::new(),
    }))
  }

  fn record(&self) {
    if let Ok(mut last) = self.0.last.lock() {
      *last = tokio::time::Instant::now();
    }
    self.0.changed.notify_waiters();
  }

  fn waiting(&self) -> BandwidthWait {
    self.0.bandwidth_waiters.fetch_add(1, Ordering::AcqRel);
    BandwidthWait(self.clone())
  }

  pub(super) async fn wait_for_idle(&self, timeout: Duration) {
    loop {
      let notified = self.0.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      if self.0.bandwidth_waiters.load(Ordering::Acquire) != 0 {
        notified.await;
        continue;
      }
      let last = self
        .0
        .last
        .lock()
        .map(|last| *last)
        .unwrap_or_else(|_| tokio::time::Instant::now());
      let deadline = last + timeout;
      if tokio::time::Instant::now() >= deadline {
        return;
      }
      tokio::select! { _ = tokio::time::sleep_until(deadline) => return, _ = notified => {} }
    }
  }
}

struct BandwidthWait(Activity);
impl Drop for BandwidthWait {
  fn drop(&mut self) {
    self.0.0.bandwidth_waiters.fetch_sub(1, Ordering::AcqRel);
    self.0.record();
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let result = tokio::try_join!(
    forward_downstream_uni(
      downstream.clone(),
      upstream.clone(),
      stream_waf_state.clone(),
      stream_waf.clone(),
      bandwidth.clone(),
      metrics.clone(),
      activity.clone()
    ),
    forward_upstream_uni(
      downstream.clone(),
      upstream.clone(),
      stream_waf_state.clone(),
      stream_waf.clone(),
      bandwidth.clone(),
      metrics.clone(),
      activity.clone()
    ),
    forward_downstream_bi(
      downstream.clone(),
      upstream.clone(),
      stream_waf_state.clone(),
      stream_waf.clone(),
      bandwidth.clone(),
      metrics.clone(),
      activity.clone()
    ),
    forward_upstream_bi(
      downstream.clone(),
      upstream.clone(),
      stream_waf_state.clone(),
      stream_waf.clone(),
      bandwidth.clone(),
      metrics.clone(),
      activity.clone()
    ),
    forward_downstream_datagrams(
      downstream.clone(),
      upstream.clone(),
      stream_waf_state.clone(),
      stream_waf.clone(),
      bandwidth.clone(),
      metrics.clone(),
      activity.clone()
    ),
    forward_upstream_datagrams(
      downstream.clone(),
      upstream.clone(),
      stream_waf_state,
      stream_waf,
      bandwidth,
      metrics,
      activity
    ),
  );
  result.map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn forward_downstream_uni(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let mut tasks = JoinSet::new();
  loop {
    if tasks.is_empty() {
      let recv = downstream.accept_uni().await?;
      activity.record();
      let send = upstream.open_uni().await?;
      tasks.spawn(copy(
        recv,
        send,
        WafStreamDirection::DownstreamToUpstream,
        WafWebTransportStreamKind::Uni,
        state.clone(),
        waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
        activity.clone(),
      ));
      continue;
    }
    tokio::select! {
      result = tasks.join_next() => finish_stream_task(result)?,
      recv = downstream.accept_uni() => {
        activity.record();
        let send = upstream.open_uni().await?;
        tasks.spawn(copy(recv?, send, WafStreamDirection::DownstreamToUpstream, WafWebTransportStreamKind::Uni, state.clone(), waf.clone(), bandwidth.clone(), metrics.clone(), activity.clone()));
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn forward_upstream_uni(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let mut tasks = JoinSet::new();
  loop {
    if tasks.is_empty() {
      let recv = upstream.accept_uni().await?;
      activity.record();
      let send = downstream.open_uni().await?;
      tasks.spawn(copy(
        recv,
        send,
        WafStreamDirection::UpstreamToDownstream,
        WafWebTransportStreamKind::Uni,
        state.clone(),
        waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
        activity.clone(),
      ));
      continue;
    }
    tokio::select! {
      result = tasks.join_next() => finish_stream_task(result)?,
      recv = upstream.accept_uni() => {
        activity.record();
        let send = downstream.open_uni().await?;
        tasks.spawn(copy(recv?, send, WafStreamDirection::UpstreamToDownstream, WafWebTransportStreamKind::Uni, state.clone(), waf.clone(), bandwidth.clone(), metrics.clone(), activity.clone()));
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn forward_downstream_bi(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let mut tasks = JoinSet::new();
  loop {
    if tasks.is_empty() {
      let (send, recv) = downstream.accept_bi().await?;
      activity.record();
      let (up_send, up_recv) = upstream.open_bi().await?;
      tasks.spawn(copy_bidi(
        recv,
        up_send,
        up_recv,
        send,
        state.clone(),
        waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
        activity.clone(),
      ));
      continue;
    }
    tokio::select! {
      result = tasks.join_next() => finish_stream_task(result)?,
      accepted = downstream.accept_bi() => {
        activity.record();
        let (send, recv) = accepted?;
        let (up_send, up_recv) = upstream.open_bi().await?;
        tasks.spawn(copy_bidi(recv, up_send, up_recv, send, state.clone(), waf.clone(), bandwidth.clone(), metrics.clone(), activity.clone()));
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn forward_upstream_bi(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let mut tasks = JoinSet::new();
  loop {
    if tasks.is_empty() {
      let (up_send, up_recv) = upstream.accept_bi().await?;
      activity.record();
      let (send, recv) = downstream.open_bi().await?;
      tasks.spawn(copy_bidi(
        recv,
        up_send,
        up_recv,
        send,
        state.clone(),
        waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
        activity.clone(),
      ));
      continue;
    }
    tokio::select! {
      result = tasks.join_next() => finish_stream_task(result)?,
      accepted = upstream.accept_bi() => {
        activity.record();
        let (up_send, up_recv) = accepted?;
        let (send, recv) = downstream.open_bi().await?;
        tasks.spawn(copy_bidi(recv, up_send, up_recv, send, state.clone(), waf.clone(), bandwidth.clone(), metrics.clone(), activity.clone()));
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn copy_bidi<R1, W1, R2, W2>(
  recv_one: R1,
  send_one: W1,
  recv_two: R2,
  send_two: W2,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()>
where
  R1: AsyncRead + StoppableRecv + Unpin,
  W1: AsyncWrite + ResettableSend + StopAwareSend + Unpin,
  R2: AsyncRead + StoppableRecv + Unpin,
  W2: AsyncWrite + ResettableSend + StopAwareSend + Unpin,
{
  tokio::try_join!(
    copy(
      recv_one,
      send_one,
      WafStreamDirection::DownstreamToUpstream,
      WafWebTransportStreamKind::Bidi,
      state.clone(),
      waf.clone(),
      bandwidth.clone(),
      metrics.clone(),
      activity.clone()
    ),
    copy(
      recv_two,
      send_two,
      WafStreamDirection::UpstreamToDownstream,
      WafWebTransportStreamKind::Bidi,
      state,
      waf,
      bandwidth,
      metrics,
      activity
    ),
  )?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn forward_downstream_datagrams(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let mut flow = bandwidth.flow(BandwidthDirection::Upload);
  loop {
    let datagram = downstream.read_datagram().await?;
    activity.record();
    pace_datagram(
      &mut flow,
      datagram.len(),
      BandwidthDirection::Upload,
      &metrics,
      &activity,
    )
    .await?;
    check_datagram(
      &state,
      &waf,
      WafStreamDirection::DownstreamToUpstream,
      &datagram,
    )?;
    upstream.send_datagram(datagram)?;
    activity.record();
  }
}

#[allow(clippy::too_many_arguments)]
async fn forward_upstream_datagrams(
  downstream: crate::webtransport::Session,
  upstream: Arc<UpstreamWebTransportSession>,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()> {
  let mut flow = bandwidth.flow(BandwidthDirection::Download);
  loop {
    let datagram = upstream.read_datagram_for_h2_bridge().await?;
    activity.record();
    if datagram.len() > MAX_DATAGRAM_BYTES {
      metrics.record_bandwidth_datagram_drop_newest(BandwidthDirection::Download);
      tracing::debug!(
        length = datagram.len(),
        "dropped oversized upstream WebTransport datagram for HTTP/2 capsule session"
      );
      continue;
    }
    check_datagram(
      &state,
      &waf,
      WafStreamDirection::UpstreamToDownstream,
      &datagram,
    )?;
    pace_datagram(
      &mut flow,
      datagram.len(),
      BandwidthDirection::Download,
      &metrics,
      &activity,
    )
    .await?;
    downstream.send_datagram(datagram)?;
    activity.record();
  }
}

#[allow(clippy::too_many_arguments)]
async fn copy<R, W>(
  mut recv: R,
  mut send: W,
  direction: WafStreamDirection,
  kind: WafWebTransportStreamKind,
  state: Option<Arc<AppSnapshot>>,
  waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  activity: Activity,
) -> anyhow::Result<()>
where
  R: AsyncRead + StoppableRecv + Unpin,
  W: AsyncWrite + ResettableSend + StopAwareSend + Unpin,
{
  let mut buffer = [0_u8; 16 * 1024];
  let bandwidth_direction = bandwidth_direction(direction);
  let mut flow = bandwidth.flow(bandwidth_direction);
  loop {
    let count = match read_or_stop(&mut recv, &mut send, &mut buffer).await? {
      ReadControl::Stopped => return Ok(()),
      ReadControl::Read(Ok(count)) => {
        activity.record();
        count
      }
      ReadControl::Read(Err(error)) => {
        if let Some(code) =
          crate::webtransport::stream_reset_code(&error).or_else(|| recv.reset_code())
        {
          let _ = forward_reset(&mut recv, &mut send, code).await?;
          return Ok(());
        }
        let _ = recv.stop(PROTOCOL_ERROR);
        return Err(error.into());
      }
    };
    if count == 0 {
      return match shutdown_or_stop(&mut send).await? {
        SendControl::Complete => Ok(()),
        SendControl::Stopped(code) => {
          recv.stop(code)?;
          Ok(())
        }
      };
    }
    if bandwidth_direction == BandwidthDirection::Download
      && let Err(error) = check_stream(&state, &waf, direction, kind, &buffer[..count])
    {
      let _ = recv.stop(PROTOCOL_ERROR);
      let _ = send.reset(PROTOCOL_ERROR);
      return Err(error);
    }
    let mut offset = 0;
    while offset < count {
      let granted = tokio::select! {
        biased;
        stopped = std::future::poll_fn(|context| send.poll_stopped(context)) => {
          recv.stop(stopped?)?;
          return Ok(());
        }
        granted = pace_stream(
          &mut flow,
          count - offset,
          bandwidth_direction,
          &metrics,
          &activity,
        ) => granted?,
      };
      if bandwidth_direction == BandwidthDirection::Upload
        && let Err(error) = check_stream(
          &state,
          &waf,
          direction,
          kind,
          &buffer[offset..offset + granted],
        )
      {
        let _ = recv.stop(PROTOCOL_ERROR);
        let _ = send.reset(PROTOCOL_ERROR);
        return Err(error);
      }
      match write_all_or_stop(&mut send, &buffer[offset..offset + granted]).await {
        Ok(SendControl::Complete) => {}
        Ok(SendControl::Stopped(code)) => {
          recv.stop(code)?;
          return Ok(());
        }
        Err(error) => {
          let _ = send.reset(PROTOCOL_ERROR);
          return Err(error.into());
        }
      }
      offset += granted;
      activity.record();
    }
  }
}

fn check_stream(
  state: &Option<Arc<AppSnapshot>>,
  waf: &Option<StreamWafRequestContext>,
  direction: WafStreamDirection,
  kind: WafWebTransportStreamKind,
  payload: &[u8],
) -> anyhow::Result<()> {
  if let (Some(state), Some(waf)) = (state.as_ref(), waf.as_ref()) {
    stream_waf::check_webtransport_payload(
      state.as_ref(),
      Some(waf),
      direction,
      payload,
      stream_waf::webtransport_stream_metadata(kind),
    )
    .context("WebTransport stream payload blocked")?;
  }
  Ok(())
}

fn check_datagram(
  state: &Option<Arc<AppSnapshot>>,
  waf: &Option<StreamWafRequestContext>,
  direction: WafStreamDirection,
  payload: &[u8],
) -> anyhow::Result<()> {
  if payload.len() > MAX_DATAGRAM_BYTES {
    anyhow::bail!("WebTransport datagram exceeds the configured maximum");
  }
  if let (Some(state), Some(waf)) = (state.as_ref(), waf.as_ref()) {
    stream_waf::check_webtransport_payload(
      state.as_ref(),
      Some(waf),
      direction,
      payload,
      stream_waf::webtransport_datagram_metadata(payload.len()),
    )
    .context("WebTransport datagram blocked")?;
  }
  Ok(())
}

async fn pace_stream(
  flow: &mut crate::bandwidth::BandwidthFlow,
  bytes: usize,
  direction: BandwidthDirection,
  metrics: &Metrics,
  activity: &Activity,
) -> anyhow::Result<usize> {
  if !flow.is_limited()? {
    return Ok(bytes);
  }
  let _waiting = activity.waiting();
  let grant = flow.acquire(bytes).await?;
  metrics.record_bandwidth_shaped_bytes(
    direction,
    BandwidthTrafficClass::WebTransportStream,
    grant.bytes() as u64,
  );
  if !grant.waited().is_zero() {
    metrics.record_bandwidth_wait(
      direction,
      BandwidthTrafficClass::WebTransportStream,
      grant.waited(),
    );
  }
  Ok(grant.bytes())
}

async fn pace_datagram(
  flow: &mut crate::bandwidth::BandwidthFlow,
  bytes: usize,
  direction: BandwidthDirection,
  metrics: &Metrics,
  activity: &Activity,
) -> anyhow::Result<()> {
  if !flow.is_limited()? {
    return Ok(());
  }
  let _waiting = activity.waiting();
  let grant = flow.acquire_indivisible(bytes, MAX_DATAGRAM_BYTES).await?;
  anyhow::ensure!(
    grant.bytes() == bytes,
    "WebTransport datagram bandwidth acquisition returned a partial grant"
  );
  metrics.record_bandwidth_shaped_bytes(
    direction,
    BandwidthTrafficClass::WebTransportDatagram,
    grant.bytes() as u64,
  );
  if !grant.waited().is_zero() {
    metrics.record_bandwidth_wait(
      direction,
      BandwidthTrafficClass::WebTransportDatagram,
      grant.waited(),
    );
  }
  Ok(())
}

fn bandwidth_direction(direction: WafStreamDirection) -> BandwidthDirection {
  match direction {
    WafStreamDirection::DownstreamToUpstream => BandwidthDirection::Upload,
    WafStreamDirection::UpstreamToDownstream => BandwidthDirection::Download,
  }
}

fn finish_stream_task(
  result: Option<Result<anyhow::Result<()>, tokio::task::JoinError>>,
) -> anyhow::Result<()> {
  match result {
    Some(Ok(result)) => result,
    Some(Err(error)) => Err(error.into()),
    None => Ok(()),
  }
}

#[cfg(test)]
mod tests;
