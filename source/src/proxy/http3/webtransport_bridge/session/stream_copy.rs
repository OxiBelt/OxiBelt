//! WebTransport stream forwarding with WAF and bandwidth enforcement.

use std::sync::Arc;

use h3_webtransport::SessionId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use super::traffic_shaping::{acquire_stream_bandwidth, bandwidth_direction};
use super::{
  DispatcherEvent, UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream, report_activity,
};
use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};
use crate::metrics::Metrics;
use crate::proxy::stream_waf::{self as stream_waf_bridge, StreamWafRequestContext};
use crate::state::AppSnapshot;
use crate::waf::{WafStreamDirection, WafWebTransportStreamKind};

#[allow(clippy::too_many_arguments)]
pub(super) async fn copy_bidi_stream<D>(
  session_id: SessionId,
  downstream: D,
  mut upstream_send: UpstreamWebTransportSendStream,
  mut upstream_recv: UpstreamWebTransportRecvStream,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (mut downstream_recv, mut downstream_send) = tokio::io::split(downstream);
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
    activity,
    WafStreamDirection::UpstreamToDownstream,
    WafWebTransportStreamKind::Bidi,
    stream_waf_state,
    stream_waf,
    bandwidth,
    metrics,
  );
  tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
  Ok(())
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
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut buffer = vec![0u8; 16 * 1024];
  let bandwidth_direction = bandwidth_direction(direction);
  let mut bandwidth_flow = bandwidth.flow(bandwidth_direction);
  loop {
    let read = recv.read(&mut buffer).await?;
    if read == 0 {
      send.shutdown().await?;
      return Ok(());
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
        acquire_stream_bandwidth(
          session_id,
          &activity,
          &mut bandwidth_flow,
          read - offset,
          &metrics,
          bandwidth_direction,
        )
        .await?
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
      send.write_all(&buffer[offset..offset + granted]).await?;
      offset += granted;
    }
    report_activity(&activity, session_id);
  }
}
