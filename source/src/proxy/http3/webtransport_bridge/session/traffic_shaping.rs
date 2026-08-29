//! Shared WebTransport bandwidth acquisition helpers.

use anyhow::Context;
use h3_webtransport::SessionId;
use tokio::sync::mpsc;

use super::DispatcherEvent;
use crate::bandwidth::{BandwidthDirection, BandwidthFlow};
use crate::metrics::{BandwidthTrafficClass, Metrics};
use crate::waf::WafStreamDirection;

const MAX_WEBTRANSPORT_DATAGRAM_BYTES: usize = 64 * 1024;

struct BandwidthWaitGuard {
  events: mpsc::Sender<DispatcherEvent>,
  session_id: SessionId,
  active: bool,
}

impl BandwidthWaitGuard {
  async fn begin(
    events: &mpsc::Sender<DispatcherEvent>,
    session_id: SessionId,
  ) -> anyhow::Result<Self> {
    events
      .send(DispatcherEvent::BandwidthWaitStarted(session_id))
      .await
      .context("WebTransport bandwidth dispatcher closed before wait")?;
    Ok(Self {
      events: events.clone(),
      session_id,
      active: true,
    })
  }

  async fn finish(mut self) -> anyhow::Result<()> {
    let result = self
      .events
      .send(DispatcherEvent::BandwidthWaitEnded(self.session_id))
      .await;
    self.active = false;
    result.context("WebTransport bandwidth dispatcher closed after wait")
  }
}

impl Drop for BandwidthWaitGuard {
  fn drop(&mut self) {
    if !self.active {
      return;
    }
    let events = self.events.clone();
    let session_id = self.session_id;
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
      runtime.spawn(async move {
        let _ = events
          .send(DispatcherEvent::BandwidthWaitEnded(session_id))
          .await;
      });
    }
  }
}

pub(super) const fn bandwidth_direction(direction: WafStreamDirection) -> BandwidthDirection {
  match direction {
    WafStreamDirection::DownstreamToUpstream => BandwidthDirection::Upload,
    WafStreamDirection::UpstreamToDownstream => BandwidthDirection::Download,
  }
}

pub(super) async fn acquire_stream_bandwidth(
  session_id: SessionId,
  events: &mpsc::Sender<DispatcherEvent>,
  flow: &mut BandwidthFlow,
  bytes: usize,
  metrics: &Metrics,
  direction: BandwidthDirection,
) -> anyhow::Result<usize> {
  let wait = BandwidthWaitGuard::begin(events, session_id).await?;
  let acquisition = flow.acquire(bytes).await;
  wait.finish().await?;
  let grant = acquisition.context("WebTransport stream bandwidth acquisition failed")?;
  metrics.record_bandwidth_shaped_bytes(
    direction,
    BandwidthTrafficClass::WebTransportStream,
    u64::try_from(grant.bytes()).unwrap_or(u64::MAX),
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

pub(super) async fn acquire_datagram_bandwidth(
  session_id: SessionId,
  events: &mpsc::Sender<DispatcherEvent>,
  flow: &mut BandwidthFlow,
  bytes: usize,
  metrics: &Metrics,
  direction: BandwidthDirection,
) -> anyhow::Result<()> {
  let wait = BandwidthWaitGuard::begin(events, session_id).await?;
  let acquisition = flow
    .acquire_indivisible(bytes, MAX_WEBTRANSPORT_DATAGRAM_BYTES)
    .await;
  wait.finish().await?;
  let grant = acquisition.context("WebTransport datagram bandwidth acquisition failed")?;
  if grant.bytes() != bytes {
    anyhow::bail!("WebTransport datagram bandwidth acquisition returned a partial grant");
  }
  metrics.record_bandwidth_shaped_bytes(
    direction,
    BandwidthTrafficClass::WebTransportDatagram,
    u64::try_from(grant.bytes()).unwrap_or(u64::MAX),
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

#[cfg(test)]
mod tests {
  use std::convert::TryFrom;

  use h3::quic::StreamId;

  use super::*;
  use crate::proxy::http3::webtransport_bridge::session::session_id_for_stream_id;

  #[tokio::test]
  async fn cancelled_wait_guard_balances_dispatcher_accounting() {
    let (events, mut receiver) = mpsc::channel(2);
    let session_id =
      session_id_for_stream_id(StreamId::try_from(0).expect("valid WebTransport stream id"));
    let wait = BandwidthWaitGuard::begin(&events, session_id)
      .await
      .expect("wait start should be recorded");
    assert!(matches!(
      receiver.recv().await,
      Some(DispatcherEvent::BandwidthWaitStarted(id)) if id == session_id
    ));

    drop(wait);
    assert!(matches!(
      receiver.recv().await,
      Some(DispatcherEvent::BandwidthWaitEnded(id)) if id == session_id
    ));
  }
}
