use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::Buf;
use h3_webtransport::server::AcceptedBi;
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::{
  H3WebTransportSession, handle_h3_request, is_webtransport_request, respond_to_h3_request,
};
use crate::lifecycle::ConnectionDrain;
use crate::limits::{ConnectionLimitContext, ConnectionPermit};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::response::text_response;
use crate::proxy::stream_waf::{self as stream_waf_bridge, StreamWafRequestContext};
use crate::state::{AppHandle, AppSnapshot};
use crate::waf::{WafStreamClose, WafStreamDirection, WafWebTransportStreamKind};

enum WebTransportBridgeEvent {
  Activity,
  Blocked(WafStreamClose),
}

fn report_activity(events: &mpsc::Sender<WebTransportBridgeEvent>) {
  let _ = events.try_send(WebTransportBridgeEvent::Activity);
}

async fn report_stream_task_result<F>(future: F, events: mpsc::Sender<WebTransportBridgeEvent>)
where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  let result = future.await;
  if let Err(error) = result
    && let Some(close) = stream_waf_bridge::blocked_close(&error)
  {
    let _ = events
      .send(WebTransportBridgeEvent::Blocked(close.clone()))
      .await;
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn bridge_webtransport(
  downstream: H3WebTransportSession,
  upstream: web_transport_quinn::Session,
  peer_addr: SocketAddr,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  timeouts: EffectiveTimeouts,
  mut drain: ConnectionDrain,
  _connection_limit_permit: Option<ConnectionPermit>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  let downstream = Arc::new(downstream);
  let upstream = Arc::new(upstream);
  let stream_waf_state = stream_waf.as_ref().map(|_| state.snapshot());
  let (activity_tx, mut activity_rx) = mpsc::channel(64);
  let mut tasks = JoinSet::new();
  tasks.spawn(bridge_downstream_bidi(
    downstream.clone(),
    upstream.clone(),
    peer_addr,
    tls_metadata,
    connection_limit_context,
    state,
    activity_tx.clone(),
    drain.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
  ));
  tasks.spawn(bridge_upstream_bidi(
    downstream.clone(),
    upstream.clone(),
    activity_tx.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
  ));
  tasks.spawn(bridge_downstream_uni(
    downstream.clone(),
    upstream.clone(),
    activity_tx.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
  ));
  tasks.spawn(bridge_upstream_uni(
    downstream.clone(),
    upstream.clone(),
    activity_tx.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
  ));
  tasks.spawn(bridge_downstream_datagrams(
    downstream.clone(),
    upstream.clone(),
    activity_tx.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
  ));
  tasks.spawn(bridge_upstream_datagrams(
    downstream,
    upstream.clone(),
    activity_tx.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
  ));
  drop(activity_tx);

  let idle = tokio::time::sleep(timeouts.webtransport_idle);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);

  loop {
    tokio::select! {
      result = tasks.join_next() => {
        tasks.abort_all();
        let Some(result) = result else {
          return Ok(());
        };
        match result.context("WebTransport bridge task panicked")? {
          Ok(()) => return Ok(()),
          Err(error) => {
            if let Some(close) = stream_waf_bridge::blocked_close(&error) {
              upstream.close(close.webtransport_code, close.reason.as_bytes());
              return Ok(());
            }
            return Err(error);
          }
        }
      }
      event = activity_rx.recv() => {
        match event {
          Some(WebTransportBridgeEvent::Activity) => {
            idle.as_mut().reset(tokio::time::Instant::now() + timeouts.webtransport_idle);
          }
          Some(WebTransportBridgeEvent::Blocked(close)) => {
            tasks.abort_all();
            upstream.close(close.webtransport_code, close.reason.as_bytes());
            return Ok(());
          }
          None => return Ok(()),
        }
      }
      _ = &mut idle => {
        tasks.abort_all();
        return Err(anyhow::anyhow!("WebTransport bridge idle timeout elapsed"));
      }
      _ = &mut drain_close => {
        tasks.abort_all();
        return Ok(());
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_downstream_bidi(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  peer_addr: SocketAddr,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  drain: ConnectionDrain,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  loop {
    match downstream.accept_bi().await? {
      Some(AcceptedBi::BidiStream(_session_id, stream)) => {
        report_activity(&activity);
        let (upstream_send, upstream_recv) = upstream.open_bi().await?;
        let stream_result_tx = activity.clone();
        tokio::spawn(report_stream_task_result(
          copy_bidi_stream(
            stream,
            upstream_send,
            upstream_recv,
            activity.clone(),
            stream_waf_state.clone(),
            stream_waf.clone(),
          ),
          stream_result_tx,
        ));
      }
      Some(AcceptedBi::Request(request, stream)) => {
        if is_webtransport_request(&request) {
          respond_to_h3_request(
            stream,
            text_response(
              StatusCode::CONFLICT,
              "additional WebTransport sessions on an active connection are not supported",
            ),
          )
          .await?;
        } else {
          handle_h3_request(
            request,
            stream,
            peer_addr,
            tls_metadata.clone(),
            connection_limit_context.clone(),
            state.clone(),
            drain.clone(),
          )
          .await?;
        }
      }
      None => return Ok(()),
    }
  }
}

async fn bridge_upstream_bidi(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  loop {
    let (upstream_send, upstream_recv) = upstream.accept_bi().await?;
    report_activity(&activity);
    let stream = downstream.open_bi(downstream.session_id()).await?;
    let stream_result_tx = activity.clone();
    tokio::spawn(report_stream_task_result(
      copy_bidi_stream(
        stream,
        upstream_send,
        upstream_recv,
        activity.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
      ),
      stream_result_tx,
    ));
  }
}

async fn bridge_downstream_uni(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  loop {
    let Some((_session_id, downstream_recv)) = downstream.accept_uni().await? else {
      return Ok(());
    };
    report_activity(&activity);
    let upstream_send = upstream.open_uni().await?;
    let stream_result_tx = activity.clone();
    tokio::spawn(report_stream_task_result(
      copy_one_way(
        downstream_recv,
        upstream_send,
        activity.clone(),
        WafStreamDirection::DownstreamToUpstream,
        WafWebTransportStreamKind::Uni,
        stream_waf_state.clone(),
        stream_waf.clone(),
      ),
      stream_result_tx,
    ));
  }
}

async fn bridge_upstream_uni(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  loop {
    let upstream_recv = upstream.accept_uni().await?;
    report_activity(&activity);
    let downstream_send = downstream.open_uni(downstream.session_id()).await?;
    let stream_result_tx = activity.clone();
    tokio::spawn(report_stream_task_result(
      copy_one_way(
        upstream_recv,
        downstream_send,
        activity.clone(),
        WafStreamDirection::UpstreamToDownstream,
        WafWebTransportStreamKind::Uni,
        stream_waf_state.clone(),
        stream_waf.clone(),
      ),
      stream_result_tx,
    ));
  }
}

async fn bridge_downstream_datagrams(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  let mut reader = downstream.datagram_reader();
  loop {
    let datagram = reader.read_datagram().await?;
    report_activity(&activity);
    let mut payload = datagram.into_payload();
    let len = payload.remaining();
    let payload = payload.copy_to_bytes(len);
    if let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref()) {
      stream_waf_bridge::check_webtransport_payload(
        state.as_ref(),
        Some(context),
        WafStreamDirection::DownstreamToUpstream,
        &payload,
        stream_waf_bridge::webtransport_datagram_metadata(len),
      )?;
    }
    upstream.send_datagram(payload)?;
  }
}

async fn bridge_upstream_datagrams(
  downstream: Arc<H3WebTransportSession>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  let mut sender = downstream.datagram_sender();
  loop {
    let datagram = upstream.read_datagram().await?;
    report_activity(&activity);
    if let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref()) {
      stream_waf_bridge::check_webtransport_payload(
        state.as_ref(),
        Some(context),
        WafStreamDirection::UpstreamToDownstream,
        &datagram,
        stream_waf_bridge::webtransport_datagram_metadata(datagram.len()),
      )?;
    }
    sender.send_datagram(datagram)?;
  }
}

async fn copy_bidi_stream<D>(
  downstream: D,
  mut upstream_send: web_transport_quinn::SendStream,
  mut upstream_recv: web_transport_quinn::RecvStream,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (mut downstream_recv, mut downstream_send) = tokio::io::split(downstream);
  let downstream_to_upstream = copy_one_way(
    &mut downstream_recv,
    &mut upstream_send,
    activity.clone(),
    WafStreamDirection::DownstreamToUpstream,
    WafWebTransportStreamKind::Bidi,
    stream_waf_state.clone(),
    stream_waf.clone(),
  );
  let upstream_to_downstream = copy_one_way(
    &mut upstream_recv,
    &mut downstream_send,
    activity,
    WafStreamDirection::UpstreamToDownstream,
    WafWebTransportStreamKind::Bidi,
    stream_waf_state,
    stream_waf,
  );
  tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
  Ok(())
}

async fn copy_one_way<R, W>(
  mut recv: R,
  mut send: W,
  activity: mpsc::Sender<WebTransportBridgeEvent>,
  direction: WafStreamDirection,
  stream_kind: WafWebTransportStreamKind,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut buffer = vec![0u8; 16 * 1024];
  loop {
    let read = recv.read(&mut buffer).await?;
    if read == 0 {
      send.shutdown().await?;
      return Ok(());
    }
    if let (Some(state), Some(context)) = (stream_waf_state.as_ref(), stream_waf.as_ref()) {
      stream_waf_bridge::check_webtransport_payload(
        state.as_ref(),
        Some(context),
        direction,
        &buffer[..read],
        stream_waf_bridge::webtransport_stream_metadata(stream_kind),
      )?;
    }
    send.write_all(&buffer[..read]).await?;
    report_activity(&activity);
  }
}
