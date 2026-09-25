//! WebTransport session runtime for bridged HTTP/3 streams.
//! Session state owns stream tasks until drain or close so cleanup is coordinated.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use bytes::Bytes;
use h3::error::Code;
use h3::quic::StreamId;
use h3_webtransport::SessionId;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::super::{H3RequestStream, connect_upstream_webtransport, respond_to_h3_request};
use super::connection::DownstreamWebTransportConnection;
use super::upstream_adapter::{UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream};
use super::{
  DispatcherEvent, DownstreamBidiStream, DownstreamUniRecvStream, UpstreamWebTransportSession,
};
use crate::limits::ConnectionLimitContext;
use crate::proxy::http as http_proxy;
use crate::proxy::http::response::{is_silent_close_response, text_response};
use crate::proxy::stream_waf::{self as stream_waf_bridge, StreamWafRequestContext};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::waf::{WafStreamDirection, WafWebTransportStreamKind};
#[cfg(feature = "admin-runtime")]
use crate::webtransport_admin::WebTransportSessionRegistration;

#[path = "session/admin_commands.rs"]
#[cfg(feature = "admin-runtime")]
mod admin_commands;
#[path = "session/connection_limits.rs"]
mod connection_limits;
#[path = "session/datagram_pacing.rs"]
mod datagram_pacing;
#[path = "session/flow.rs"]
pub(super) mod flow;
#[path = "session/index.rs"]
mod index;
#[path = "session/lifecycle.rs"]
mod lifecycle;
#[path = "session/metrics.rs"]
mod metrics;
#[path = "session/silent_close.rs"]
mod silent_close;
#[path = "session/state.rs"]
mod state;
#[path = "session/stream_copy.rs"]
mod stream_copy;
#[path = "session/task_reporting.rs"]
mod task_reporting;
#[path = "session/traffic_shaping.rs"]
mod traffic_shaping;

use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};
use crate::metrics::Metrics;
#[cfg(feature = "admin-runtime")]
pub(super) use admin_commands::close_session_with_code;
#[cfg(feature = "admin-runtime")]
use admin_commands::spawn_admin_session_command_forwarder;
pub(crate) use connection_limits::{
  WebTransportSessionPermits, acquire_webtransport_session_permits,
};
use datagram_pacing::{
  DatagramQueueOutcome, QueuedDatagram, bridge_upstream_datagrams, datagram_pacer_channel,
  pace_downstream_datagrams, try_queue_datagram,
};
use flow::{ConnectStream, SessionFlow, read_connect_capsules, write_credit_capsules};
pub(super) use index::WebTransportSessionIndex;
use index::session_id_for_stream_id;
#[cfg(feature = "admin-runtime")]
use lifecycle::close_session_inner;
pub(super) use lifecycle::{
  close_all_sessions, close_all_sessions_after_downstream_loss, close_expired_sessions,
  close_session, close_session_abrupt, close_session_after_client_reader, close_session_from_peer,
};
use metrics::record_session_end_metrics;
pub(super) use silent_close::close_session_silent;
pub(super) use state::ActiveWebTransportSession;
use stream_copy::{FlowRecv, FlowSend, copy_bidi_stream, copy_one_way};
use task_reporting::{report_activity, report_session_task_result, report_stream_task_result};
#[cfg(all(test, feature = "admin-runtime"))]
use traffic_shaping::bandwidth_direction;
const WEBTRANSPORT_DRAFT_HEADER: &str = "sec-webtransport-http3-draft";
const WEBTRANSPORT_DRAFT_VALUE: &str = "draft02";

pub(super) async fn close_flow_error(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  index: &mut WebTransportSessionIndex,
  session_id: SessionId,
) {
  close_stream_error(
    sessions,
    index,
    session_id,
    Code::from(flow::FLOW_ERROR_CODE),
    b"WebTransport draft16 flow control error",
  )
  .await;
}

pub(super) async fn close_protocol_error(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  index: &mut WebTransportSessionIndex,
  session_id: SessionId,
) {
  close_stream_error(
    sessions,
    index,
    session_id,
    Code::H3_MESSAGE_ERROR,
    b"WebTransport CONNECT capsule error",
  )
  .await;
}

async fn close_stream_error(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  code: Code,
  reason: &[u8],
) {
  let Some(mut session) = sessions.remove(&session_id) else {
    return;
  };
  record_session_end_metrics(&session, None);
  index.remove(session_id);
  for task in &session.tasks {
    task.abort();
  }
  session.upstream.close(0, reason);
  session.connect_stream.stop_both(code).await;
  lifecycle::retire_http2_upstream(session);
}

fn report_flow_error(events: &mpsc::Sender<DispatcherEvent>, session_id: SessionId) {
  if events
    .try_send(DispatcherEvent::FlowError(session_id))
    .is_err()
  {
    let events = events.clone();
    tokio::spawn(async move {
      let _ = events.send(DispatcherEvent::FlowError(session_id)).await;
    });
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
    None,
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
      if is_silent_close_response(&response) {
        return Ok(());
      }
      let response =
        http_proxy::shape_webtransport_response(*response, None, snapshot.metrics.clone());
      respond_to_h3_request(stream, response).await?;
      return Ok(());
    }
  };
  let client_certificate_forwarding = prepared.client_certificate_forwarding;
  let shape_prepared_response = |response| {
    let mut response = http_proxy::shape_webtransport_response(
      response,
      Some(prepared.bandwidth.clone()),
      snapshot.metrics.clone(),
    );
    crate::proxy::http::client_certificate::finalize_response(
      &mut response,
      client_certificate_forwarding,
      snapshot.as_ref(),
    );
    crate::proxy::http::status_headers::finalize(response, &prepared.status_headers)
  };

  if prepared.upstream_version == crate::config::HttpVersion::H3 {
    let matching = matches!(
      (
        downstream.wire_draft(),
        prepared.upstream.webtransport_http3_draft
      ),
      (
        super::super::WebTransportWireDraft::Draft02,
        crate::config::WebTransportH3Draft::Draft02
      ) | (
        super::super::WebTransportWireDraft::Draft16,
        crate::config::WebTransportH3Draft::Draft16
      )
    );
    if !matching {
      respond_to_h3_request(
        stream,
        shape_prepared_response(text_response(
          StatusCode::BAD_REQUEST,
          "WebTransport H3 dialect mismatch",
        )),
      )
      .await?;
      return Ok(());
    }
  }

  #[cfg(feature = "admin-runtime")]
  let registration = WebTransportSessionRegistration {
    route: prepared.route_name.clone(),
    upstream: prepared.upstream.name.clone(),
    peer_ip: peer_addr.ip(),
    client_ip: prepared.client_addr.ip(),
  };
  #[cfg(feature = "admin-runtime")]
  if snapshot.webtransport_admin.is_draining(&registration) {
    respond_to_h3_request(
      stream,
      shape_prepared_response(text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "WebTransport session is draining",
      )),
    )
    .await?;
    return Ok(());
  }

  if sessions.len()
    >= snapshot
      .config
      .limits
      .max_webtransport_sessions_per_connection
  {
    respond_to_h3_request(
      stream,
      shape_prepared_response(text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "too many active WebTransport sessions",
      )),
    )
    .await?;
    return Ok(());
  }

  let connection_permits = match acquire_webtransport_session_permits(
    prepared.client_addr.ip(),
    connection_limit_context.as_ref(),
    snapshot.as_ref(),
  )
  .await
  {
    Ok(permits) => permits,
    Err(status) => {
      respond_to_h3_request(
        stream,
        shape_prepared_response(text_response(status, "connection limit exceeded")),
      )
      .await?;
      return Ok(());
    }
  };

  let buffer_reservation =
    if downstream.wire_draft() == super::super::WebTransportWireDraft::Draft16 {
      let limits = &snapshot.config.proxy.http2.webtransport;
      let Some(bytes) = limits.session_reservation_bytes() else {
        respond_to_h3_request(
          stream,
          shape_prepared_response(text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "WebTransport capacity unavailable",
          )),
        )
        .await?;
        return Ok(());
      };
      match snapshot
        .webtransport_h2_budget
        .reserve(bytes, limits.max_total_buffer_bytes)
      {
        Ok(reservation) => Some(reservation),
        Err(_) => {
          respond_to_h3_request(
            stream,
            shape_prepared_response(text_response(
              StatusCode::SERVICE_UNAVAILABLE,
              "WebTransport capacity exhausted",
            )),
          )
          .await?;
          return Ok(());
        }
      }
    } else {
      None
    };

  if sessions.contains_key(&session_id) {
    respond_to_h3_request(
      stream,
      shape_prepared_response(text_response(
        StatusCode::CONFLICT,
        "duplicate WebTransport session",
      )),
    )
    .await?;
    return Ok(());
  }

  let (upstream, upstream_connection_guard, upstream_certificate) =
    match connect_upstream_webtransport(&prepared, snapshot.as_ref()).await {
      Ok(upstream) => upstream,
      Err(error) => {
        warn!(
          ?session_id,
          error = ?error,
          "failed to connect upstream WebTransport session"
        );
        respond_to_h3_request(
          stream,
          shape_prepared_response(crate::proxy::http::status_headers::transport_error(
            text_response(
              StatusCode::BAD_GATEWAY,
              "upstream WebTransport CONNECT failed",
            ),
            error.as_ref(),
          )),
        )
        .await?;
        return Ok(());
      }
    };

  let mut response_builder = Response::builder().status(StatusCode::OK);
  if let Some(protocol) = upstream.selected_protocol() {
    response_builder = response_builder.header("wt-protocol", selected_protocol_header(protocol)?);
  }
  if downstream.wire_draft() == super::super::WebTransportWireDraft::Draft02 {
    response_builder = response_builder.header(WEBTRANSPORT_DRAFT_HEADER, WEBTRANSPORT_DRAFT_VALUE);
  }
  let mut response = response_builder
    .body(())
    .context("failed to build downstream WebTransport response")?;
  append_upstream_response_headers(response.headers_mut(), upstream.response_headers());
  crate::proxy::http::client_certificate::finalize_response(
    &mut response,
    client_certificate_forwarding,
    snapshot.as_ref(),
  );
  crate::proxy::http::status_headers::finalize_head(&mut response, &prepared.status_headers);
  stream
    .send_response(response)
    .await
    .context("failed to send downstream WebTransport response")?;

  let flow = if downstream.wire_draft() == super::super::WebTransportWireDraft::Draft16 {
    let peer_initial = downstream.peer_initial_credit();
    Some(SessionFlow::new(peer_initial).context("invalid peer draft16 initial credit")?)
  } else {
    None
  };
  let (send, recv) = stream.split();
  let send = Arc::new(tokio::sync::Mutex::new(send));
  let recv = Arc::new(tokio::sync::Mutex::new(recv));
  let upstream = Arc::new(upstream);
  let (reader_done_tx, reader_done_rx) = tokio::sync::oneshot::channel();
  let reader_recv = recv.clone();
  let reader_flow = flow.clone();
  let reader_upstream = upstream.clone();
  let reader_events = events.clone();
  let mut control_tasks = vec![tokio::spawn(async move {
    read_connect_capsules(
      session_id,
      reader_recv,
      reader_flow,
      reader_upstream,
      reader_events,
    )
    .await;
    let _ = reader_done_tx.send(());
  })];
  if let Some(flow) = &flow {
    control_tasks.push(tokio::spawn(write_credit_capsules(
      session_id,
      send.clone(),
      flow.clone(),
      events.clone(),
    )));
    let limits = &snapshot.config.proxy.http2.webtransport;
    flow
      .grant_initial(
        u64::from(limits.max_concurrent_uni_streams),
        u64::from(limits.max_concurrent_bidi_streams),
        limits.max_session_buffer_bytes as u64,
      )
      .context("invalid draft16 session credit")?;
  }
  let connect_stream = ConnectStream { send, recv };

  let inserted_session = session_index.insert(connect_stream_id);
  debug_assert_eq!(inserted_session, session_id);
  #[cfg(feature = "admin-runtime")]
  let (admin_command_tx, admin_command_rx) = tokio::sync::mpsc::unbounded_channel();
  #[cfg(feature = "admin-runtime")]
  let admin_guard = snapshot
    .webtransport_admin
    .register(registration, admin_command_tx)
    .context("failed to register WebTransport admin session")?;
  let stream_waf = prepared
    .stream_waf
    .take()
    .map(|context| context.with_upstream_certificate(upstream_certificate));
  let stream_waf_state = stream_waf.as_ref().map(|_| snapshot.clone());
  let introspection_guard = snapshot
    .runtime_introspection
    .guard(RuntimeCounter::WebTransportSession);
  snapshot.metrics.record_webtransport_session_start(
    &snapshot.config.metrics,
    &prepared.route_name,
    &prepared.upstream.name,
  );
  let bandwidth = prepared.bandwidth.clone();
  let (downstream_datagrams, downstream_datagram_rx) = datagram_pacer_channel();
  let (abrupt_reset_tx, abrupt_reset_rx) = watch::channel(false);
  let mut tasks = spawn_upstream_session_tasks(
    session_id,
    connect_stream_id,
    connect_stream.send.clone(),
    downstream,
    upstream.clone(),
    abrupt_reset_rx,
    flow.clone(),
    events.clone(),
    stream_waf_state.clone(),
    stream_waf.clone(),
    bandwidth.clone(),
    snapshot.metrics.clone(),
    downstream_datagram_rx,
  );
  tasks.extend(control_tasks);
  #[cfg(feature = "admin-runtime")]
  let tasks = {
    let mut tasks = tasks;
    tasks.push(spawn_admin_session_command_forwarder(
      session_id,
      admin_command_rx,
      events,
    ));
    tasks
  };
  sessions.insert(
    session_id,
    ActiveWebTransportSession {
      upstream,
      _upstream_connection_guard: upstream_connection_guard,
      connect_stream,
      client_reader_done: Some(reader_done_rx),
      flow,
      #[cfg(feature = "admin-runtime")]
      admin_guard,
      _connection_permits: connection_permits,
      _buffer_reservation: buffer_reservation,
      _introspection_guard: introspection_guard,
      bandwidth,
      downstream_datagrams,
      stream_waf_state,
      metrics_state: snapshot,
      stream_waf,
      timeouts: prepared.timeouts,
      route_name: prepared.route_name,
      upstream_name: prepared.upstream.name,
      trace_context: prepared.trace_context,
      started_at: crate::telemetry::TelemetryRuntime::start(),
      last_activity: Instant::now(),
      bandwidth_waiters: 0,
      peer_close_pending: false,
      abrupt_reset_tx,
      unassociated_uni_resets: 0,
      tasks,
    },
  );
  Ok(())
}

pub(crate) fn selected_protocol_header(protocol: &str) -> anyhow::Result<String> {
  let protocol = sfv::StringRef::from_str(protocol)
    .context("upstream selected an invalid WebTransport subprotocol")?;
  Ok(sfv::ItemSerializer::new().bare_item(protocol).finish())
}

pub(crate) fn append_upstream_response_headers(
  downstream: &mut http::HeaderMap,
  upstream: &[(HeaderName, HeaderValue)],
) {
  let connection_tokens = upstream
    .iter()
    .filter(|(name, _)| name == http::header::CONNECTION)
    .flat_map(|(_, value)| value.to_str().ok().into_iter())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
    .collect::<Vec<_>>();
  for (name, value) in upstream {
    if is_forwardable_connect_response_header(name) && !connection_tokens.contains(name) {
      downstream.append(name.clone(), value.clone());
    }
  }
}

fn is_forwardable_connect_response_header(name: &HeaderName) -> bool {
  !matches!(
    name.as_str(),
    "connection"
      | "keep-alive"
      | "proxy-connection"
      | "transfer-encoding"
      | "upgrade"
      | "te"
      | "trailer"
      | "content-length"
      | "host"
      | "capsule-protocol"
      | "webtransport-init"
      | "wt-protocol"
      | "sec-webtransport-http3-draft"
      | "sec-webtransport-http3-draft02"
  )
}

pub(super) async fn client_fin_needs_upstream_close<F>(closed: F) -> bool
where
  F: std::future::Future<Output = anyhow::Result<(u32, Bytes)>>,
{
  // FIN without a CLOSE capsule can be a reply to the server's FIN. Give the
  // upstream CONNECT reader a bounded chance to publish that clean close.
  tokio::time::timeout(std::time::Duration::from_secs(1), closed)
    .await
    .is_err()
}

async fn close_after_optional_drain<D, C, W>(
  draining: D,
  closed: C,
  write_drain: W,
) -> anyhow::Result<(u32, Bytes)>
where
  D: std::future::Future<Output = ()>,
  C: std::future::Future<Output = anyhow::Result<(u32, Bytes)>>,
  W: std::future::Future<Output = bool>,
{
  tokio::pin!(draining, closed);
  tokio::select! {
    biased;
    () = &mut draining => {
      anyhow::ensure!(write_drain.await, "failed to forward upstream WebTransport drain capsule");
      closed.await
    }
    result = &mut closed => result,
  }
}

#[allow(clippy::too_many_arguments)]
fn spawn_upstream_session_tasks(
  session_id: SessionId,
  connect_stream_id: StreamId,
  connect_send: Arc<tokio::sync::Mutex<super::super::H3RequestSendStream>>,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<UpstreamWebTransportSession>,
  abrupt_reset_rx: watch::Receiver<bool>,
  flow: Option<Arc<SessionFlow>>,
  events: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
  downstream_datagrams: mpsc::Receiver<QueuedDatagram>,
) -> Vec<JoinHandle<()>> {
  let control_watch = upstream.clone();
  let control_events = events.clone();
  vec![
    tokio::spawn(async move {
      let forwarded_drain = async {
        matches!(
          tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ConnectStream::write_drain(connect_send),
          )
          .await,
          Ok(true)
        )
      };
      match close_after_optional_drain(
        control_watch.draining(),
        control_watch.closed(),
        forwarded_drain,
      )
      .await
      {
        Ok((code, reason)) => {
          let reason = String::from_utf8_lossy(&reason).into_owned();
          let _ = control_events
            .send(DispatcherEvent::SessionClosed(session_id, code, reason))
            .await;
        }
        Err(error) => {
          warn!(?session_id, %error, "upstream WebTransport session close failed");
          let _ = control_events
            .send(DispatcherEvent::SessionEnded(session_id))
            .await;
        }
      }
    }),
    tokio::spawn(report_session_task_result(
      session_id,
      bridge_upstream_bidi(
        session_id,
        downstream.clone(),
        upstream.clone(),
        abrupt_reset_rx,
        flow.clone(),
        events.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
      ),
      upstream.clone(),
      events.clone(),
    )),
    tokio::spawn(report_session_task_result(
      session_id,
      bridge_upstream_uni(
        session_id,
        downstream.clone(),
        upstream.clone(),
        flow,
        events.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
      ),
      upstream.clone(),
      events.clone(),
    )),
    tokio::spawn(report_session_task_result(
      session_id,
      bridge_upstream_datagrams(
        session_id,
        connect_stream_id,
        downstream,
        upstream.clone(),
        events.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
      ),
      upstream.clone(),
      events.clone(),
    )),
    tokio::spawn(report_session_task_result(
      session_id,
      pace_downstream_datagrams(
        session_id,
        upstream.clone(),
        downstream_datagrams,
        events.clone(),
        bandwidth,
        metrics,
        stream_waf_state,
        stream_waf,
      ),
      upstream,
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
  session.record_activity();
  if let Some(flow) = &session.flow
    && flow.incoming_open(true).is_err()
  {
    report_flow_error(&events, session_id);
    return;
  }
  session
    .tasks
    .push(tokio::spawn(bridge_downstream_bidi_stream(
      session_id,
      stream,
      session.upstream.clone(),
      session.abrupt_reset_tx.subscribe(),
      session.flow.clone(),
      events,
      session.stream_waf_state.clone(),
      session.stream_waf.clone(),
      session.bandwidth.clone(),
      session.metrics_state.metrics.clone(),
    )));
}

#[allow(clippy::too_many_arguments)]
async fn bridge_downstream_bidi_stream(
  session_id: SessionId,
  stream: DownstreamBidiStream,
  upstream: Arc<UpstreamWebTransportSession>,
  abrupt_reset_rx: watch::Receiver<bool>,
  flow: Option<Arc<SessionFlow>>,
  events: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
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
      upstream,
      abrupt_reset_rx,
      flow,
      upstream_send,
      upstream_recv,
      events,
      stream_waf_state,
      stream_waf,
      bandwidth,
      metrics,
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
  session.record_activity();
  if let Some(flow) = &session.flow
    && flow.incoming_open(false).is_err()
  {
    report_flow_error(&events, session_id);
    return;
  }
  session
    .tasks
    .push(tokio::spawn(bridge_downstream_uni_stream(
      session_id,
      stream,
      session.upstream.clone(),
      session.flow.clone(),
      events,
      session.stream_waf_state.clone(),
      session.stream_waf.clone(),
      session.bandwidth.clone(),
      session.metrics_state.metrics.clone(),
    )));
}

pub(super) fn handle_unassociated_uni_reset(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &WebTransportSessionIndex,
  draft: super::super::WebTransportWireDraft,
  stream_id: StreamId,
  wire_code: u64,
) {
  let session_count = sessions.len();
  let Some(session) = sessions.values_mut().next() else {
    return;
  };
  let limit = session
    .metrics_state
    .config
    .proxy
    .http2
    .webtransport
    .max_concurrent_uni_streams;
  let Some(code) = eligible_unassociated_uni_reset(
    draft,
    session_count,
    session_index.only_one_session_ever(),
    session.upstream.supports_unassociated_uni_reset(),
    session.unassociated_uni_resets,
    limit,
    wire_code,
  ) else {
    return;
  };
  session.unassociated_uni_resets += 1;
  session.record_activity();
  let upstream = session.upstream.clone();
  session.tasks.push(tokio::spawn(async move {
    if let Err(error) = upstream.relay_unassociated_uni_reset(code).await {
      warn!(?stream_id, %error, "failed to relay unassociated draft02 uni reset");
    }
  }));
}

fn eligible_unassociated_uni_reset(
  draft: super::super::WebTransportWireDraft,
  session_count: usize,
  only_one_session_ever: bool,
  upstream_is_h3: bool,
  used: u32,
  limit: u32,
  wire_code: u64,
) -> Option<u32> {
  if !(draft == super::super::WebTransportWireDraft::Draft02
    && session_count == 1
    && only_one_session_ever
    && upstream_is_h3
    && used < limit)
  {
    return None;
  }
  let code = super::h3_application_code_from_wire(wire_code)?;
  (super::h3_application_code_to_wire(code) == wire_code).then_some(code)
}

#[allow(clippy::too_many_arguments)]
async fn bridge_downstream_uni_stream(
  session_id: SessionId,
  stream: DownstreamUniRecvStream,
  upstream: Arc<UpstreamWebTransportSession>,
  flow: Option<Arc<SessionFlow>>,
  events: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
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
      FlowRecv::new(stream, flow, events.clone(), session_id, false),
      upstream_send,
      events,
      WafStreamDirection::DownstreamToUpstream,
      WafWebTransportStreamKind::Uni,
      stream_waf_state,
      stream_waf,
      bandwidth,
      metrics,
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
  let mut silent_close = false;
  let mut end_session = false;
  {
    let Some(session) = sessions.get_mut(&session_id) else {
      return;
    };
    session.record_activity();

    let upload_limited = session.bandwidth.policy().map_or(true, |policy| {
      policy.upload != crate::bandwidth::BandwidthRate::Unlimited
    });
    if upload_limited {
      match try_queue_datagram(&session.downstream_datagrams, payload) {
        DatagramQueueOutcome::Queued => {}
        DatagramQueueOutcome::DroppedNewest => {
          session
            .metrics_state
            .metrics
            .record_bandwidth_datagram_drop_newest(BandwidthDirection::Upload);
          debug!(
            ?session_id,
            direction = "upload",
            "dropped newest WebTransport datagram because bandwidth pacer queue is full"
          );
        }
        DatagramQueueOutcome::Closed => {
          end_session = true;
        }
      }
    } else {
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
          if blocked.is_silent_close() {
            silent_close = true;
          } else if let Some(blocked_close) = blocked.close_option() {
            close = Some(blocked_close.clone());
          } else {
            silent_close = true;
          }
        }
      }
      if close.is_none()
        && !silent_close
        && let Err(error) = session.upstream.send_datagram(payload)
      {
        warn!(?session_id, error = %error, "failed to send upstream WebTransport datagram");
        end_session = true;
      }
    }
  }

  if silent_close {
    close_session_silent(sessions, session_index, session_id);
    return;
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
      b"upstream WebTransport datagram pacer unavailable",
    );
  }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_upstream_bidi(
  session_id: SessionId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<UpstreamWebTransportSession>,
  abrupt_reset_rx: watch::Receiver<bool>,
  flow: Option<Arc<SessionFlow>>,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
  loop {
    let (upstream_send, upstream_recv) = upstream.accept_bi().await?;
    report_activity(&activity, session_id);
    let stream = downstream.open_bi(session_id, flow.as_ref()).await?;
    let stream_result_tx = activity.clone();
    let task = tokio::spawn(report_stream_task_result(
      session_id,
      copy_bidi_stream(
        session_id,
        stream,
        upstream.clone(),
        abrupt_reset_rx.clone(),
        flow.clone(),
        upstream_send,
        upstream_recv,
        activity.clone(),
        stream_waf_state.clone(),
        stream_waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
      ),
      stream_result_tx,
    ));
    register_stream_task(&activity, session_id, task, Some(abrupt_reset_rx.clone())).await?;
  }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_upstream_uni(
  session_id: SessionId,
  downstream: Arc<DownstreamWebTransportConnection>,
  upstream: Arc<UpstreamWebTransportSession>,
  flow: Option<Arc<SessionFlow>>,
  activity: mpsc::Sender<DispatcherEvent>,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<StreamWafRequestContext>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
  loop {
    let upstream_recv = upstream.accept_uni().await?;
    report_activity(&activity, session_id);
    let downstream_send = downstream.open_uni(session_id, flow.as_ref()).await?;
    let stream_result_tx = activity.clone();
    let task = tokio::spawn(report_stream_task_result(
      session_id,
      copy_one_way(
        session_id,
        upstream_recv,
        FlowSend::new(downstream_send, flow.clone()),
        activity.clone(),
        WafStreamDirection::UpstreamToDownstream,
        WafWebTransportStreamKind::Uni,
        stream_waf_state.clone(),
        stream_waf.clone(),
        bandwidth.clone(),
        metrics.clone(),
      ),
      stream_result_tx,
    ));
    register_stream_task(&activity, session_id, task, None).await?;
  }
}

async fn register_stream_task(
  events: &mpsc::Sender<DispatcherEvent>,
  session_id: SessionId,
  task: JoinHandle<()>,
  abrupt_reset_rx: Option<watch::Receiver<bool>>,
) -> anyhow::Result<()> {
  if let Err(error) = events
    .send(DispatcherEvent::RegisterStreamTask(
      session_id,
      task,
      abrupt_reset_rx,
    ))
    .await
  {
    if let DispatcherEvent::RegisterStreamTask(_, task, _) = error.0 {
      task.abort();
    }
    anyhow::bail!("WebTransport dispatcher closed before stream task registration");
  }
  Ok(())
}

pub(super) fn retire_late_stream_task(
  mut task: JoinHandle<()>,
  abrupt_reset_rx: Option<watch::Receiver<bool>>,
) {
  tokio::spawn(async move {
    if let Some(mut reset) = abrupt_reset_rx {
      // Abrupt cleanup removes the session before it publishes the CONNECT
      // reset. A late registration must not cancel its receive half first.
      stream_copy::wait_for_abrupt_reset(&mut reset).await;
    }
    if tokio::time::timeout(std::time::Duration::from_secs(3), &mut task)
      .await
      .is_err()
    {
      task.abort();
      let _ = task.await;
    }
  });
}

fn reset_unknown_bidi_stream(mut stream: DownstreamBidiStream) {
  h3::quic::RecvStream::stop_sending(&mut stream, Code::H3_REQUEST_CANCELLED.value());
  h3::quic::SendStream::reset(&mut stream, Code::H3_REQUEST_CANCELLED.value());
}

fn stop_unknown_uni_stream(mut stream: DownstreamUniRecvStream) {
  h3::quic::RecvStream::stop_sending(&mut stream, Code::H3_REQUEST_CANCELLED.value());
}

#[cfg(test)]
mod protocol_header_tests {
  use super::{append_upstream_response_headers, selected_protocol_header};
  use http::{HeaderMap, HeaderName, HeaderValue};

  #[test]
  fn selected_protocol_is_an_rfc8941_string_item() {
    assert_eq!(selected_protocol_header("b").expect("protocol"), "\"b\"");
    assert_eq!(
      selected_protocol_header("a\"b\\c").expect("escaped protocol"),
      "\"a\\\"b\\\\c\""
    );
  }

  #[test]
  fn connect_response_forwards_application_headers_and_strips_hop_headers() {
    let headers = vec![
      (
        HeaderName::from_static("x-test"),
        HeaderValue::from_static("one"),
      ),
      (
        HeaderName::from_static("x-test"),
        HeaderValue::from_static("two"),
      ),
      (
        HeaderName::from_static("connection"),
        HeaderValue::from_static("x-hop"),
      ),
      (
        HeaderName::from_static("x-hop"),
        HeaderValue::from_static("drop"),
      ),
      (
        HeaderName::from_static("capsule-protocol"),
        HeaderValue::from_static("?1"),
      ),
      (
        HeaderName::from_static("webtransport-init"),
        HeaderValue::from_static("a"),
      ),
      (
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("probe=1"),
      ),
    ];
    let mut forwarded = HeaderMap::new();
    append_upstream_response_headers(&mut forwarded, &headers);
    assert_eq!(forwarded.get_all("x-test").iter().count(), 2);
    assert_eq!(
      forwarded.get("x-test"),
      Some(&HeaderValue::from_static("one"))
    );
    assert!(!forwarded.contains_key("connection"));
    assert!(!forwarded.contains_key("x-hop"));
    assert!(!forwarded.contains_key("capsule-protocol"));
    assert!(!forwarded.contains_key("webtransport-init"));
    assert_eq!(
      forwarded.get("set-cookie"),
      Some(&HeaderValue::from_static("probe=1"))
    );
  }
}

#[cfg(test)]
mod control_order_tests {
  use std::sync::{Arc, Mutex};

  use bytes::Bytes;
  use tokio::sync::{oneshot, watch};

  use super::{close_after_optional_drain, retire_late_stream_task, stream_copy};

  #[tokio::test]
  async fn drain_is_forwarded_before_immediately_ready_close() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let draining_order = order.clone();
    let close_order = order.clone();
    let write_order = order.clone();
    let result = close_after_optional_drain(
      async move { draining_order.lock().expect("order").push("drain") },
      async move {
        close_order.lock().expect("order").push("close");
        Ok((32, Bytes::from_static(b"done")))
      },
      async move {
        write_order.lock().expect("order").push("write");
        true
      },
    )
    .await
    .expect("close after drain");
    assert_eq!(result, (32, Bytes::from_static(b"done")));
    assert_eq!(*order.lock().expect("order"), ["drain", "write", "close"]);
  }

  #[tokio::test]
  async fn close_without_drain_does_not_synthesize_a_drain_capsule() {
    let result = close_after_optional_drain(
      std::future::pending(),
      async { Ok((0, Bytes::new())) },
      async { panic!("no drain capsule was received") },
    )
    .await
    .expect("clean close");
    assert_eq!(result, (0, Bytes::new()));
  }

  #[tokio::test]
  async fn failed_drain_write_does_not_report_a_clean_close() {
    let result = close_after_optional_drain(
      std::future::ready(()),
      std::future::pending(),
      std::future::ready(false),
    )
    .await;
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn late_upstream_bidi_registration_survives_until_connect_reset() {
    let (reset_tx, reset_rx) = watch::channel(false);
    let (completed_tx, mut completed_rx) = oneshot::channel();
    let mut child_reset_rx = reset_rx.clone();
    let task = tokio::spawn(async move {
      stream_copy::wait_for_abrupt_reset(&mut child_reset_rx).await;
      let _ = completed_tx.send(());
    });
    // The dispatcher has already removed the session when registration arrives.
    retire_late_stream_task(task, Some(reset_rx));
    tokio::task::yield_now().await;
    assert!(matches!(
      completed_rx.try_recv(),
      Err(oneshot::error::TryRecvError::Empty)
    ));
    reset_tx.send_replace(true);
    tokio::time::timeout(std::time::Duration::from_secs(1), completed_rx)
      .await
      .expect("child was retained until CONNECT reset")
      .expect("child was not aborted");
  }
}

#[cfg(test)]
mod unassociated_reset_tests {
  use h3::quic::StreamId;

  use super::{WebTransportSessionIndex, eligible_unassociated_uni_reset};
  use crate::proxy::http3::WebTransportWireDraft;
  use crate::proxy::http3::webtransport_bridge::h3_application_code_to_wire;

  #[test]
  fn only_single_draft02_h3_session_can_relay_valid_bounded_reset() {
    let code = h3_application_code_to_wire(95);
    assert_eq!(
      eligible_unassociated_uni_reset(WebTransportWireDraft::Draft02, 1, true, true, 0, 1, code),
      Some(95)
    );
    for (draft, count, sole_ever, h3, used, limit, wire) in [
      (WebTransportWireDraft::Draft02, 2, true, true, 0, 1, code),
      (WebTransportWireDraft::Draft02, 0, true, true, 0, 1, code),
      (WebTransportWireDraft::Draft02, 1, false, true, 0, 1, code),
      (WebTransportWireDraft::Draft02, 1, true, false, 0, 1, code),
      (WebTransportWireDraft::Draft02, 1, true, true, 1, 1, code),
      (WebTransportWireDraft::Draft02, 1, true, true, 0, 1, 0),
      (
        WebTransportWireDraft::Draft02,
        1,
        true,
        true,
        0,
        1,
        0x52e4a40fa8db + 30,
      ),
      (WebTransportWireDraft::Draft16, 1, true, true, 0, 1, code),
    ] {
      assert_eq!(
        eligible_unassociated_uni_reset(draft, count, sole_ever, h3, used, limit, wire),
        None
      );
    }
  }

  #[test]
  fn reset_from_closed_session_cannot_be_relayed_to_next_session() {
    let mut index = WebTransportSessionIndex::default();
    let first = index.insert(StreamId::try_from(0).expect("valid stream id"));
    assert!(index.only_one_session_ever());
    index.remove(first);
    let second = index.insert(StreamId::try_from(4).expect("valid stream id"));
    assert!(index.contains(second));
    assert!(!index.contains(first));
    assert!(!index.only_one_session_ever());
    assert_eq!(
      eligible_unassociated_uni_reset(
        WebTransportWireDraft::Draft02,
        1,
        index.only_one_session_ever(),
        true,
        0,
        1,
        h3_application_code_to_wire(95),
      ),
      None
    );
  }
}

#[cfg(all(test, feature = "admin-runtime"))]
#[path = "session_tests.rs"]
mod tests;
