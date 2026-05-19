use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use h3::error::Code;
use h3::quic::StreamId;
use h3_webtransport::SessionId;
use http::{Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

use super::super::{H3RequestStream, connect_upstream_webtransport, respond_to_h3_request};
use super::connection::DownstreamWebTransportConnection;
use super::{DispatcherEvent, DownstreamBidiStream, DownstreamUniRecvStream};
use crate::limits::ConnectionLimitContext;
use crate::proxy::http as http_proxy;
use crate::proxy::http::response::text_response;
use crate::proxy::stream_waf::{self as stream_waf_bridge, StreamWafRequestContext};
use crate::state::AppSnapshot;
use crate::waf::{WafStreamClose, WafStreamDirection, WafWebTransportStreamKind};

#[path = "session/connection_limits.rs"]
mod connection_limits;
#[path = "session/metrics.rs"]
mod metrics;
#[path = "session/state.rs"]
mod state;

use connection_limits::acquire_webtransport_session_permits;
use metrics::record_session_end_metrics;
pub(super) use state::ActiveWebTransportSession;
const WEBTRANSPORT_DRAFT_HEADER: &str = "sec-webtransport-http3-draft";
const WEBTRANSPORT_DRAFT_VALUE: &str = "draft02";
#[derive(Default)]
pub(super) struct WebTransportSessionIndex {
  connect_stream_ids: HashMap<SessionId, StreamId>,
}

impl WebTransportSessionIndex {
  fn insert(&mut self, connect_stream_id: StreamId) -> SessionId {
    let session_id = session_id_for_stream_id(connect_stream_id);
    self
      .connect_stream_ids
      .insert(session_id, connect_stream_id);
    session_id
  }

  pub(super) fn remove(&mut self, session_id: SessionId) {
    self.connect_stream_ids.remove(&session_id);
  }

  fn contains(&self, session_id: SessionId) -> bool {
    self.connect_stream_ids.contains_key(&session_id)
  }

  #[cfg(test)]
  fn connect_stream_id(&self, session_id: SessionId) -> Option<StreamId> {
    self.connect_stream_ids.get(&session_id).copied()
  }

  pub(super) fn session_for_datagram_stream_id(&self, stream_id: StreamId) -> Option<SessionId> {
    let session_id = session_id_for_stream_id(stream_id);
    self.contains(session_id).then_some(session_id)
  }
}

fn session_id_for_stream_id(stream_id: StreamId) -> SessionId {
  SessionId::from(stream_id)
}
fn report_activity(events: &mpsc::Sender<DispatcherEvent>, session_id: SessionId) {
  let _ = events.try_send(DispatcherEvent::Activity(session_id));
}

async fn report_stream_task_result<F>(
  session_id: SessionId,
  future: F,
  events: mpsc::Sender<DispatcherEvent>,
) where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  let result = future.await;
  if let Err(error) = result
    && let Some(close) = stream_waf_bridge::blocked_close(&error)
  {
    let _ = events
      .send(DispatcherEvent::Blocked(session_id, close.clone()))
      .await;
  }
}

async fn report_session_task_result<F>(
  session_id: SessionId,
  future: F,
  events: mpsc::Sender<DispatcherEvent>,
) where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  let result = future.await;
  match result {
    Ok(()) => {
      let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
    }
    Err(error) => {
      if let Some(close) = stream_waf_bridge::blocked_close(&error) {
        let _ = events
          .send(DispatcherEvent::Blocked(session_id, close.clone()))
          .await;
      } else {
        warn!(?session_id, error = %error, "WebTransport session task ended");
        let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn accept_webtransport_session(
  downstream: Arc<DownstreamWebTransportConnection>,
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  request: Request<()>,
  mut stream: H3RequestStream,
  peer_addr: SocketAddr,
  udp_connection_id: Arc<str>,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  snapshot: Arc<AppSnapshot>,
  events: mpsc::Sender<DispatcherEvent>,
) -> anyhow::Result<()> {
  let connect_stream_id = stream.id();
  let session_id = session_id_for_stream_id(connect_stream_id);
  let mut prepared = match http_proxy::prepare_webtransport(
    &request,
    peer_addr,
    crate::waf::WafTransportMetadataInput {
      udp_connection_id: Some(udp_connection_id.as_ref()),
      ..crate::waf::WafTransportMetadataInput::default()
    },
    tls_metadata.as_ref(),
    snapshot.as_ref(),
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(response) => {
      respond_to_h3_request(stream, *response).await?;
      return Ok(());
    }
  };

  if sessions.len()
    >= snapshot
      .config
      .limits
      .max_webtransport_sessions_per_connection
  {
    respond_to_h3_request(
      stream,
      text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "too many active WebTransport sessions",
      ),
    )
    .await?;
    return Ok(());
  }

  let connection_permits = match acquire_webtransport_session_permits(
    prepared.client_addr.ip(),
    connection_limit_context.as_ref(),
    snapshot.as_ref(),
  ) {
    Ok(permits) => permits,
    Err(status) => {
      respond_to_h3_request(stream, text_response(status, "connection limit exceeded")).await?;
      return Ok(());
    }
  };

  if sessions.contains_key(&session_id) {
    respond_to_h3_request(
      stream,
      text_response(StatusCode::CONFLICT, "duplicate WebTransport session"),
    )
    .await?;
    return Ok(());
  }

  let upstream = match connect_upstream_webtransport(&prepared, snapshot.as_ref()).await {
    Ok(upstream) => upstream,
    Err(error) => {
      warn!(
        ?session_id,
        error = %error,
        "failed to connect upstream WebTransport session"
      );
      respond_to_h3_request(
        stream,
        text_response(
          StatusCode::BAD_GATEWAY,
          "upstream WebTransport CONNECT failed",
        ),
      )
      .await?;
      return Ok(());
    }
  };

  stream
    .send_response(
      Response::builder()
        .status(StatusCode::OK)
        .header(WEBTRANSPORT_DRAFT_HEADER, WEBTRANSPORT_DRAFT_VALUE)
        .body(())
        .context("failed to build downstream WebTransport response")?,
    )
    .await
    .context("failed to send downstream WebTransport response")?;

  let inserted_session = session_index.insert(connect_stream_id);
  debug_assert_eq!(inserted_session, session_id);
  let upstream = Arc::new(upstream);
  let stream_waf = prepared.stream_waf.take();
  let stream_waf_state = stream_waf.as_ref().map(|_| snapshot.clone());
  snapshot.metrics.record_webtransport_session_start(
    &snapshot.config.metrics,
    &prepared.route_name,
    &prepared.upstream.name,
  );
  let tasks = spawn_upstream_session_tasks(
    session_id,
    connect_stream_id,
    downstream,
    upstream.clone(),
    events,
    stream_waf_state.clone(),
    stream_waf.clone(),
  );
  sessions.insert(
    session_id,
    ActiveWebTransportSession {
      upstream,
      connect_stream: stream,
      _connection_permits: connection_permits,
      stream_waf_state,
      metrics_state: snapshot,
      stream_waf,
      timeouts: prepared.timeouts,
      route_name: prepared.route_name,
      upstream_name: prepared.upstream.name,
      trace_context: prepared.trace_context,
      started_at: crate::telemetry::TelemetryRuntime::start(),
      last_activity: Instant::now(),
      tasks,
    },
  );
  Ok(())
}

fn spawn_upstream_session_tasks(
  session_id: SessionId,
  connect_stream_id: StreamId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<web_transport_quinn::Session>,
  events: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> Vec<JoinHandle<()>> {
  vec![
    tokio::spawn(report_session_task_result(
      session_id,
      bridge_upstream_bidi(
        session_id,
        downstream.clone(),
        upstream.clone(),
        events.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
      ),
      events.clone(),
    )),
    tokio::spawn(report_session_task_result(
      session_id,
      bridge_upstream_uni(
        session_id,
        downstream.clone(),
        upstream.clone(),
        events.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
      ),
      events.clone(),
    )),
    tokio::spawn(report_session_task_result(
      session_id,
      bridge_upstream_datagrams(
        session_id,
        connect_stream_id,
        downstream,
        upstream,
        events.clone(),
        stream_waf_state,
        stream_waf,
      ),
      events,
    )),
  ]
}

pub(super) fn handle_downstream_bidi_stream(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_id: SessionId,
  stream: DownstreamBidiStream,
  events: mpsc::Sender<DispatcherEvent>,
) {
  let Some(session) = sessions.get_mut(&session_id) else {
    reset_unknown_bidi_stream(stream);
    return;
  };
  session.last_activity = Instant::now();
  session.reap_finished_tasks();
  session
    .tasks
    .push(tokio::spawn(bridge_downstream_bidi_stream(
      session_id,
      stream,
      session.upstream.clone(),
      events,
      session.stream_waf_state.clone(),
      session.stream_waf.clone(),
    )));
}

async fn bridge_downstream_bidi_stream(
  session_id: SessionId,
  stream: DownstreamBidiStream,
  upstream: Arc<web_transport_quinn::Session>,
  events: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) {
  let (upstream_send, upstream_recv) = match upstream.open_bi().await {
    Ok(streams) => streams,
    Err(error) => {
      warn!(?session_id, error = %error, "failed to open upstream WebTransport bidi stream");
      let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
      return;
    }
  };
  let result_events = events.clone();
  report_stream_task_result(
    session_id,
    copy_bidi_stream(
      session_id,
      stream,
      upstream_send,
      upstream_recv,
      events,
      stream_waf_state,
      stream_waf,
    ),
    result_events,
  )
  .await;
}

pub(super) fn handle_downstream_uni_stream(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_id: SessionId,
  stream: DownstreamUniRecvStream,
  events: mpsc::Sender<DispatcherEvent>,
) {
  let Some(session) = sessions.get_mut(&session_id) else {
    stop_unknown_uni_stream(stream);
    return;
  };
  session.last_activity = Instant::now();
  session.reap_finished_tasks();
  session
    .tasks
    .push(tokio::spawn(bridge_downstream_uni_stream(
      session_id,
      stream,
      session.upstream.clone(),
      events,
      session.stream_waf_state.clone(),
      session.stream_waf.clone(),
    )));
}

async fn bridge_downstream_uni_stream(
  session_id: SessionId,
  stream: DownstreamUniRecvStream,
  upstream: Arc<web_transport_quinn::Session>,
  events: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) {
  let upstream_send = match upstream.open_uni().await {
    Ok(stream) => stream,
    Err(error) => {
      warn!(?session_id, error = %error, "failed to open upstream WebTransport uni stream");
      let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
      return;
    }
  };
  let result_events = events.clone();
  report_stream_task_result(
    session_id,
    copy_one_way(
      session_id,
      stream,
      upstream_send,
      events,
      WafStreamDirection::DownstreamToUpstream,
      WafWebTransportStreamKind::Uni,
      stream_waf_state,
      stream_waf,
    ),
    result_events,
  )
  .await;
}

pub(super) fn handle_downstream_datagram(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  stream_id: StreamId,
  payload: Bytes,
) {
  let Some(session_id) = session_index.session_for_datagram_stream_id(stream_id) else {
    return;
  };
  let mut close = None;
  let mut end_session = false;
  {
    let Some(session) = sessions.get_mut(&session_id) else {
      return;
    };
    session.last_activity = Instant::now();
    session.reap_finished_tasks();

    if let (Some(state), Some(context)) = (
      session.stream_waf_state.as_ref(),
      session.stream_waf.as_ref(),
    ) {
      let len = payload.len();
      if let Err(blocked) = stream_waf_bridge::check_webtransport_payload(
        state.as_ref(),
        Some(context),
        WafStreamDirection::DownstreamToUpstream,
        &payload,
        stream_waf_bridge::webtransport_datagram_metadata(len),
      ) {
        close = Some(blocked.close().clone());
      }
    }

    if close.is_none()
      && let Err(error) = session.upstream.send_datagram(payload)
    {
      warn!(?session_id, error = %error, "failed to send upstream WebTransport datagram");
      end_session = true;
    }
  }

  if let Some(close) = close {
    close_session(
      sessions,
      session_index,
      session_id,
      Some(&close),
      b"stream WAF closed WebTransport session",
    );
    return;
  }

  if end_session {
    close_session(
      sessions,
      session_index,
      session_id,
      None,
      b"upstream WebTransport datagram send failed",
    );
  }
}

async fn bridge_upstream_bidi(
  session_id: SessionId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  loop {
    let (upstream_send, upstream_recv) = upstream.accept_bi().await?;
    report_activity(&activity, session_id);
    let stream = downstream.open_bi(session_id).await?;
    let stream_result_tx = activity.clone();
    tokio::spawn(report_stream_task_result(
      session_id,
      copy_bidi_stream(
        session_id,
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

async fn bridge_upstream_uni(
  session_id: SessionId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  loop {
    let upstream_recv = upstream.accept_uni().await?;
    report_activity(&activity, session_id);
    let downstream_send = downstream.open_uni(session_id).await?;
    let stream_result_tx = activity.clone();
    tokio::spawn(report_stream_task_result(
      session_id,
      copy_one_way(
        session_id,
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

async fn bridge_upstream_datagrams(
  session_id: SessionId,
  connect_stream_id: StreamId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<web_transport_quinn::Session>,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
) -> anyhow::Result<()> {
  let mut sender = downstream.datagram_sender(connect_stream_id);
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
    sender.send_datagram(datagram)?;
  }
}

pub(super) fn close_expired_sessions(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
) {
  let now = Instant::now();
  let expired = sessions
    .iter()
    .filter_map(|(session_id, session)| {
      (session.last_activity + session.timeouts.webtransport_idle <= now).then_some(*session_id)
    })
    .collect::<Vec<_>>();
  for session_id in expired {
    close_session(
      sessions,
      session_index,
      session_id,
      None,
      b"WebTransport idle timeout",
    );
  }
}

pub(super) fn close_all_sessions(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  reason: Option<&'static [u8]>,
) {
  let session_ids = sessions.keys().copied().collect::<Vec<_>>();
  for session_id in session_ids {
    close_session(
      sessions,
      session_index,
      session_id,
      None,
      reason.unwrap_or(b"WebTransport connection closed"),
    );
  }
}

pub(super) fn close_session(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  close: Option<&WafStreamClose>,
  fallback_reason: &'static [u8],
) {
  let Some(mut session) = sessions.remove(&session_id) else {
    return;
  };
  record_session_end_metrics(&session, close);
  session_index.remove(session_id);
  for task in session.tasks {
    task.abort();
  }
  match close {
    Some(close) => session
      .upstream
      .close(close.webtransport_code, close.reason.as_bytes()),
    None => session.upstream.close(0, fallback_reason),
  }
  session.connect_stream.stop_stream(Code::H3_NO_ERROR);
  session.connect_stream.stop_sending(Code::H3_NO_ERROR);
}

fn reset_unknown_bidi_stream(mut stream: DownstreamBidiStream) {
  h3::quic::RecvStream::stop_sending(&mut stream, Code::H3_REQUEST_CANCELLED.value());
  h3::quic::SendStream::reset(&mut stream, Code::H3_REQUEST_CANCELLED.value());
}

fn stop_unknown_uni_stream(mut stream: DownstreamUniRecvStream) {
  h3::quic::RecvStream::stop_sending(&mut stream, Code::H3_REQUEST_CANCELLED.value());
}

async fn copy_bidi_stream<D>(
  session_id: SessionId,
  downstream: D,
  mut upstream_send: web_transport_quinn::SendStream,
  mut upstream_recv: web_transport_quinn::RecvStream,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
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
  );
  tokio::try_join!(downstream_to_upstream, upstream_to_downstream)?;
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn copy_one_way<R, W>(
  session_id: SessionId,
  mut recv: R,
  mut send: W,
  activity: mpsc::Sender<DispatcherEvent>,
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
    report_activity(&activity, session_id);
  }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
