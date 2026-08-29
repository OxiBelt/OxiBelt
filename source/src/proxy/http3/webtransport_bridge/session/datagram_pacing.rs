//! Bounded WebTransport datagram queues and bandwidth pacing.

use std::sync::Arc;

use bytes::Bytes;
use h3::quic::StreamId;
use h3_webtransport::SessionId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::debug;

use super::traffic_shaping::acquire_datagram_bandwidth;
use super::{
  DispatcherEvent, DownstreamWebTransportConnection, UpstreamWebTransportSession, report_activity,
};
use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};
use crate::metrics::Metrics;
use crate::proxy::stream_waf::{self as stream_waf_bridge, StreamWafRequestContext};
use crate::state::AppSnapshot;
use crate::waf::WafStreamDirection;

pub(super) const WEBTRANSPORT_DATAGRAM_QUEUE_CAPACITY: usize = 1;

#[derive(Clone)]
pub(super) struct DatagramPacerSender {
  sender: mpsc::Sender<QueuedDatagram>,
  slot: Arc<Semaphore>,
}

pub(super) struct QueuedDatagram {
  pub(in crate::proxy::http3::webtransport_bridge) payload: Bytes,
  _slot: OwnedSemaphorePermit,
}

pub(super) fn datagram_pacer_channel() -> (DatagramPacerSender, mpsc::Receiver<QueuedDatagram>) {
  let (sender, receiver) = mpsc::channel(WEBTRANSPORT_DATAGRAM_QUEUE_CAPACITY);
  (
    DatagramPacerSender {
      sender,
      slot: Arc::new(Semaphore::new(WEBTRANSPORT_DATAGRAM_QUEUE_CAPACITY)),
    },
    receiver,
  )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DatagramQueueOutcome {
  Queued,
  DroppedNewest,
  Closed,
}

pub(super) fn try_queue_datagram(
  pacer: &DatagramPacerSender,
  payload: Bytes,
) -> DatagramQueueOutcome {
  let Ok(slot) = pacer.slot.clone().try_acquire_owned() else {
    return DatagramQueueOutcome::DroppedNewest;
  };
  match pacer.sender.try_send(QueuedDatagram {
    payload,
    _slot: slot,
  }) {
    Ok(()) => DatagramQueueOutcome::Queued,
    Err(mpsc::error::TrySendError::Full(_)) => DatagramQueueOutcome::DroppedNewest,
    Err(mpsc::error::TrySendError::Closed(_)) => DatagramQueueOutcome::Closed,
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn bridge_upstream_datagrams(
  session_id: SessionId,
  connect_stream_id: StreamId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<UpstreamWebTransportSession>,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
  let mut direct_sender = downstream.datagram_sender(connect_stream_id)?;
  let mut paced_sender = downstream.datagram_sender(connect_stream_id)?;
  let (datagrams_tx, mut datagrams_rx) = datagram_pacer_channel();
  let receive = async {
    loop {
      let datagram = upstream.read_datagram().await?;
      report_activity(&activity, session_id);
      if let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref()) {
        stream_waf_bridge::check_webtransport_payload(
          state.as_ref(),
          Some(context),
          WafStreamDirection::UpstreamToDownstream,
          &datagram,
          stream_waf_bridge::webtransport_datagram_metadata(datagram.len()),
        )?;
      }
      let download_limited = bandwidth.policy().map_or(true, |policy| {
        policy.download != crate::bandwidth::BandwidthRate::Unlimited
      });
      if !download_limited {
        direct_sender.send_datagram(datagram)?;
        continue;
      }
      match try_queue_datagram(&datagrams_tx, datagram) {
        DatagramQueueOutcome::Queued => {}
        DatagramQueueOutcome::DroppedNewest => {
          metrics.record_bandwidth_datagram_drop_newest(BandwidthDirection::Download);
          debug!(
            ?session_id,
            direction = "download",
            "dropped newest WebTransport datagram because bandwidth pacer queue is full"
          );
        }
        DatagramQueueOutcome::Closed => {
          anyhow::bail!("downstream WebTransport datagram pacer closed");
        }
      }
    }
    #[allow(unreachable_code)]
    Ok::<(), anyhow::Error>(())
  };
  let pace = async {
    let mut flow = bandwidth.flow(BandwidthDirection::Download);
    while let Some(datagram) = datagrams_rx.recv().await {
      if flow.is_limited()? {
        acquire_datagram_bandwidth(
          session_id,
          &activity,
          &mut flow,
          datagram.payload.len(),
          &metrics,
          BandwidthDirection::Download,
        )
        .await?;
      }
      paced_sender.send_datagram(datagram.payload)?;
      report_activity(&activity, session_id);
    }
    Ok::<(), anyhow::Error>(())
  };
  tokio::try_join!(receive, pace)?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn pace_downstream_datagrams(
  session_id: SessionId,
  upstream: Arc<UpstreamWebTransportSession>,
  mut datagrams: mpsc::Receiver<QueuedDatagram>,
  activity: mpsc::Sender<DispatcherEvent>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  let mut flow = bandwidth.flow(BandwidthDirection::Upload);
  while let Some(datagram) = datagrams.recv().await {
    if flow.is_limited()? {
      acquire_datagram_bandwidth(
        session_id,
        &activity,
        &mut flow,
        datagram.payload.len(),
        &metrics,
        BandwidthDirection::Upload,
      )
      .await?;
    }
    if let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref()) {
      stream_waf_bridge::check_webtransport_payload(
        state.as_ref(),
        Some(context),
        WafStreamDirection::DownstreamToUpstream,
        &datagram.payload,
        stream_waf_bridge::webtransport_datagram_metadata(datagram.payload.len()),
      )?;
    }
    upstream.send_datagram(datagram.payload)?;
    report_activity(&activity, session_id);
  }
  Ok(())
}
