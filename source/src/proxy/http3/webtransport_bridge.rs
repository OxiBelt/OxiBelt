//! Bridge between HTTP proxy decisions and HTTP/3 WebTransport sessions.
//! The bridge owns session handoff so request policy is settled before streams are accepted.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h3::quic::{Connection as H3QuicConnection, StreamId};
use h3::stream::BufRecvStream;
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender};
use h3_datagram::quic_traits::DatagramConnectionExt;
use h3_webtransport::SessionId;
use http::{Request, StatusCode};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::debug;

use super::{
  H3BidiStream, H3DownstreamRequestContext, H3RequestStream, H3ServerConnection,
  WebTransportWireDraft, handle_h3_request, is_webtransport_request, request_tasks,
  respond_to_h3_request,
};
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::proxy::http::{early_data as http_early_data, response::text_response};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::waf::WafStreamClose;

mod connection;
mod session;
mod upstream_adapter;

use connection::{DownstreamWebTransportConnection, spawn_downstream_reader_tasks};
#[cfg(feature = "admin-runtime")]
use session::close_session_with_code;
use session::{
  ActiveWebTransportSession, WebTransportSessionIndex, accept_webtransport_session,
  close_all_sessions, close_expired_sessions, close_session, handle_downstream_bidi_stream,
  handle_downstream_datagram, handle_downstream_uni_stream,
};
pub(crate) use session::{WebTransportSessionPermits, acquire_webtransport_session_permits};
pub(crate) use session::{append_upstream_response_headers, selected_protocol_header};
pub(crate) use upstream_adapter::{
  MAX_WEBTRANSPORT_STREAMS, UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream,
  UpstreamWebTransportSession, h3_application_code_from_wire, h3_application_code_to_wire,
};

type H3OpenStreams = <crate::quic::h3::Connection as H3QuicConnection<Bytes>>::OpenStreams;
type DownstreamBidiStream = BufRecvStream<H3BidiStream, Bytes>;
type DownstreamUniRecvStream = BufRecvStream<crate::quic::h3::RecvStream, Bytes>;
type DownstreamUniSendStream = BufRecvStream<crate::quic::h3::SendStream<Bytes>, Bytes>;
type H3DatagramReader = DatagramReader<
  <crate::quic::h3::Connection as DatagramConnectionExt<Bytes>>::RecvDatagramHandler,
>;
type H3DatagramSender = DatagramSender<
  <crate::quic::h3::Connection as DatagramConnectionExt<Bytes>>::SendDatagramHandler,
  Bytes,
>;

enum DispatcherEvent {
  DownstreamBidi(SessionId, Box<DownstreamBidiStream>),
  DownstreamUni(SessionId, DownstreamUniRecvStream),
  UnassociatedUniReset(StreamId, u64),
  DownstreamDatagram(StreamId, Bytes),
  DownstreamRequest(Request<()>, Box<H3RequestStream>),
  Activity(SessionId),
  BandwidthWaitStarted(SessionId),
  BandwidthWaitEnded(SessionId),
  RegisterStreamTask(
    SessionId,
    tokio::task::JoinHandle<()>,
    Option<tokio::sync::watch::Receiver<bool>>,
  ),
  #[cfg(feature = "admin-runtime")]
  AdminClose(SessionId, u32, String),
  Blocked(SessionId, WafStreamClose),
  SilentBlocked(SessionId),
  ClientCloseStarted(SessionId),
  ClientCloseFinished(SessionId, u32, String),
  ClientFinished(SessionId),
  SessionEnded(SessionId),
  SessionClosed(SessionId, u32, String),
  FlowError(SessionId),
  ProtocolError(SessionId),
  ConnectionClosed,
  Fatal(anyhow::Error),
}

enum DownstreamBidiEvent {
  WebTransport(SessionId, Box<DownstreamBidiStream>),
  Request(Box<Request<()>>, Box<H3RequestStream>),
  Closed,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_webtransport_connection(
  h3_connection: H3ServerConnection,
  wire_draft: WebTransportWireDraft,
  initial_request: Request<()>,
  initial_stream: H3RequestStream,
  peer_addr: SocketAddr,
  udp_connection_id: Arc<str>,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  proxy_tls_evidence: Option<crate::proxy_protocol_egress::tls::ConnectionTlsEvidence>,
  forwarded_client_certificate: Option<crate::tls::ForwardedClientCertificate>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  early_data: crate::quic::h3::EarlyDataTracker,
  mut shutdown: watch::Receiver<bool>,
  drain: ConnectionDrain,
  mut request_admission: request_tasks::RequestAdmission,
) -> anyhow::Result<()> {
  let downstream = Arc::new(DownstreamWebTransportConnection::new(
    h3_connection,
    wire_draft,
  ));
  let (events_tx, mut events_rx) = mpsc::channel(256);
  let mut downstream_tasks = spawn_downstream_reader_tasks(downstream.clone(), events_tx.clone());
  let mut sessions = HashMap::new();
  let mut session_index = WebTransportSessionIndex::default();
  let webtransport_only_connections = state.config.proxy.http3.webtransport_only_connections;

  handle_downstream_request(
    downstream.clone(),
    &mut sessions,
    &mut session_index,
    initial_request,
    initial_stream,
    peer_addr,
    udp_connection_id.clone(),
    tls_metadata.clone(),
    proxy_tls_evidence.clone(),
    forwarded_client_certificate.clone(),
    connection_limit_context.clone(),
    state.clone(),
    early_data.clone(),
    drain.clone(),
    events_tx.clone(),
    &mut request_admission,
  )
  .await?;

  let mut drain_for_close = drain.clone();
  let drain_close = drain_for_close.close_delay_elapsed();
  tokio::pin!(drain_close);

  loop {
    if *shutdown.borrow() {
      close_all_sessions(&mut sessions, &mut session_index, Some(b"server shutdown"));
      abort_tasks(&mut downstream_tasks);
      return Ok(());
    }

    let idle_deadline = next_idle_deadline(&sessions);
    let idle_sleep = tokio::time::sleep_until(
      idle_deadline.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600)),
    );
    tokio::pin!(idle_sleep);

    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          close_all_sessions(
            &mut sessions,
            &mut session_index,
            Some(b"server shutdown"),
          );
          abort_tasks(&mut downstream_tasks);
          return Ok(());
        }
      }
      _ = &mut drain_close => {
        close_all_sessions(
          &mut sessions,
          &mut session_index,
          Some(b"connection drain elapsed"),
        );
        abort_tasks(&mut downstream_tasks);
        return Ok(());
      }
      _ = &mut idle_sleep, if idle_deadline.is_some() => {
        close_expired_sessions(&mut sessions, &mut session_index);
      }
      event = events_rx.recv() => {
        match event {
          Some(DispatcherEvent::DownstreamBidi(session_id, stream)) => {
            handle_downstream_bidi_stream(&mut sessions, session_id, *stream, events_tx.clone());
          }
          Some(DispatcherEvent::DownstreamUni(session_id, stream)) => {
            handle_downstream_uni_stream(&mut sessions, session_id, stream, events_tx.clone());
          }
          Some(DispatcherEvent::UnassociatedUniReset(stream_id, code)) => {
            session::handle_unassociated_uni_reset(
              &mut sessions,
              &session_index,
              wire_draft,
              stream_id,
              code,
            );
          }
          Some(DispatcherEvent::DownstreamDatagram(stream_id, payload)) => {
            handle_downstream_datagram(
              &mut sessions,
              &mut session_index,
              stream_id,
              payload,
            );
          }
          Some(DispatcherEvent::DownstreamRequest(request, stream)) => {
            handle_downstream_request(
              downstream.clone(),
              &mut sessions,
              &mut session_index,
              request,
              *stream,
              peer_addr,
              udp_connection_id.clone(),
              tls_metadata.clone(),
              proxy_tls_evidence.clone(),
              forwarded_client_certificate.clone(),
              connection_limit_context.clone(),
              state.clone(),
              early_data.clone(),
              drain.clone(),
              events_tx.clone(),
              &mut request_admission,
            )
            .await?;
          }
          Some(DispatcherEvent::Activity(session_id)) => {
            if let Some(session) = sessions.get_mut(&session_id) {
              session.record_activity();
            }
          }
          Some(DispatcherEvent::BandwidthWaitStarted(session_id)) => {
            if let Some(session) = sessions.get_mut(&session_id) {
              session.begin_bandwidth_wait();
            }
          }
          Some(DispatcherEvent::BandwidthWaitEnded(session_id)) => {
            if let Some(session) = sessions.get_mut(&session_id) {
              session.end_bandwidth_wait();
            }
          }
          Some(DispatcherEvent::RegisterStreamTask(session_id, task, abrupt_reset_rx)) => {
            if let Some(session) = sessions.get_mut(&session_id) {
              session.tasks.push(task);
            } else {
              session::retire_late_stream_task(task, abrupt_reset_rx);
            }
          }
          #[cfg(feature = "admin-runtime")]
          Some(DispatcherEvent::AdminClose(session_id, close_code, reason)) => {
            close_session_with_code(
              &mut sessions,
              &mut session_index,
              session_id,
              close_code,
              reason.as_bytes(),
            );
          }
          Some(DispatcherEvent::Blocked(session_id, close)) => {
            close_session(
              &mut sessions,
              &mut session_index,
              session_id,
              Some(&close),
              b"stream WAF closed WebTransport session",
            );
          }
          Some(DispatcherEvent::SilentBlocked(session_id)) => {
            session::close_session_silent(&mut sessions, &mut session_index, session_id);
          }
          Some(DispatcherEvent::ClientCloseStarted(session_id)) => {
            debug!(?session_id, "downstream WebTransport CLOSE capsule started");
            if let Some(session) = sessions.get_mut(&session_id) {
              session.peer_close_pending = true;
            }
          }
          Some(DispatcherEvent::ClientCloseFinished(session_id, code, reason)) => {
            debug!(?session_id, code, "downstream WebTransport CLOSE capsule finished");
            if let Some(session) = sessions.get(&session_id) {
              session.upstream.close(code, reason.as_bytes());
            }
            session::close_session_from_peer(
              &mut sessions,
              &mut session_index,
              session_id,
              code,
              reason.as_bytes(),
            );
          }
          Some(DispatcherEvent::ClientFinished(session_id)) => {
            debug!(?session_id, "downstream WebTransport CONNECT finished without CLOSE capsule");
            if let Some(session) = sessions.get(&session_id) {
              let upstream = session.upstream.clone();
              let events = events_tx.clone();
              tokio::spawn(async move {
                if session::client_fin_needs_upstream_close(upstream.closed()).await {
                  let _ = events
                    .send(DispatcherEvent::ClientCloseFinished(session_id, 0, String::new()))
                    .await;
                }
              });
            }
          }
          Some(DispatcherEvent::SessionEnded(session_id)) => {
            debug!(?session_id, "WebTransport session ended without a validated CLOSE capsule");
            if sessions.get(&session_id).is_some_and(|session| session.peer_close_pending) {
              continue;
            }
            if sessions
              .get(&session_id)
              .is_some_and(|session| session.upstream.abrupt_h3_close())
            {
              if webtransport_only_connections {
                // This opt-in listener admits only one WebTransport session
                // and no ordinary H3 requests. Closing the physical QUIC
                // connection preserves the browser's one error across its
                // session and child streams.
                downstream.abort_connection();
                close_all_sessions(
                  &mut sessions,
                  &mut session_index,
                  Some(b"upstream WebTransport QUIC connection lost"),
                );
                abort_tasks(&mut downstream_tasks);
                return Ok(());
              }
              session::close_session_abrupt(&mut sessions, &mut session_index, session_id);
              continue;
            }
            if let Some((code, reason)) = sessions
              .get(&session_id)
              .and_then(|session| session.upstream.remote_close())
            {
              session::close_session_from_peer(
                &mut sessions,
                &mut session_index,
                session_id,
                code,
                &reason,
              );
            } else {
              session::close_session_after_client_reader(
                &mut sessions,
                &mut session_index,
                session_id,
                b"WebTransport session ended",
              );
            }
          }
          Some(DispatcherEvent::SessionClosed(session_id, code, reason)) => {
            debug!(?session_id, code, "upstream WebTransport session closed");
            if sessions.get(&session_id).is_some_and(|session| session.peer_close_pending) {
              continue;
            }
            session::close_session_from_peer(
              &mut sessions,
              &mut session_index,
              session_id,
              code,
              reason.as_bytes(),
            );
          }
          Some(DispatcherEvent::FlowError(session_id)) => {
            session::close_flow_error(&mut sessions, &mut session_index, session_id).await;
          }
          Some(DispatcherEvent::ProtocolError(session_id)) => {
            session::close_protocol_error(&mut sessions, &mut session_index, session_id).await;
          }
          Some(DispatcherEvent::ConnectionClosed) | None => {
            session::close_all_sessions_after_downstream_loss(
              &mut sessions,
              &mut session_index,
              b"downstream HTTP/3 connection closed",
            );
            abort_tasks(&mut downstream_tasks);
            return Ok(());
          }
          Some(DispatcherEvent::Fatal(error)) => {
            session::close_all_sessions_after_downstream_loss(
              &mut sessions,
              &mut session_index,
              b"downstream HTTP/3 connection failed",
            );
            abort_tasks(&mut downstream_tasks);
            return Err(error);
          }
        }
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn handle_downstream_request(
  downstream: Arc<DownstreamWebTransportConnection>,
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  request: Request<()>,
  stream: H3RequestStream,
  peer_addr: SocketAddr,
  udp_connection_id: Arc<str>,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  proxy_tls_evidence: Option<crate::proxy_protocol_egress::tls::ConnectionTlsEvidence>,
  forwarded_client_certificate: Option<crate::tls::ForwardedClientCertificate>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  early_data: crate::quic::h3::EarlyDataTracker,
  drain: ConnectionDrain,
  events: mpsc::Sender<DispatcherEvent>,
  request_admission: &mut request_tasks::RequestAdmission,
) -> anyhow::Result<()> {
  if drain.is_draining() {
    let response = crate::proxy::http::status_headers::finalize(
      text_response(StatusCode::SERVICE_UNAVAILABLE, "draining"),
      &state.config.proxy.status_headers,
    );
    respond_to_h3_request(stream, response).await?;
    return Ok(());
  }

  let mut request = request;
  let is_early_data = early_data.take(stream.id());
  if is_early_data {
    http_early_data::mark_verified(&mut request);
  }
  http_early_data::strip_untrusted_header(request.headers_mut());
  if let Some(certificate) = forwarded_client_certificate {
    request.extensions_mut().insert(certificate);
  }

  let is_webtransport = is_webtransport_request(&request);
  if let Some(status) = dedicated_request_rejection(
    state.config.proxy.http3.webtransport_only_connections,
    is_webtransport,
    session_index,
  ) {
    respond_to_h3_request(
      stream,
      text_response(status, "WebTransport-only connection"),
    )
    .await?;
    return Ok(());
  }

  if is_webtransport {
    if !super::webtransport_request_matches_draft(&request, downstream.wire_draft())
      || http_early_data::is_verified(&request)
    {
      respond_to_h3_request(
        stream,
        text_response(StatusCode::BAD_REQUEST, "WebTransport H3 dialect mismatch"),
      )
      .await?;
      return Ok(());
    }
    accept_webtransport_session(
      downstream,
      sessions,
      session_index,
      request,
      stream,
      peer_addr,
      udp_connection_id,
      tls_metadata,
      connection_limit_context,
      state,
      events,
    )
    .await?;
  } else {
    if !request_admission.try_admit() {
      let response = crate::proxy::http::status_headers::finalize(
        request_tasks::too_many_requests_response(),
        &state.config.proxy.status_headers,
      );
      respond_to_h3_request(stream, response).await?;
      return Ok(());
    }

    let context = H3DownstreamRequestContext {
      proxy_tls_evidence,
      peer_addr,
      udp_connection_id,
      tls_metadata,
      connection_limit_context,
      state,
      drain,
    };
    let _request_guard = context
      .state
      .runtime_introspection_guard(RuntimeCounter::Http3Request);
    let status = handle_h3_request(request, stream, context).await?;
    debug!(peer = %peer_addr, %status, "handled downstream HTTP/3 request");
  }

  Ok(())
}

fn dedicated_request_rejection(
  webtransport_only_connections: bool,
  is_webtransport: bool,
  session_index: &WebTransportSessionIndex,
) -> Option<StatusCode> {
  if !webtransport_only_connections {
    return None;
  }
  if !is_webtransport {
    return Some(StatusCode::MISDIRECTED_REQUEST);
  }
  session_index
    .has_accepted_session()
    .then_some(StatusCode::TOO_MANY_REQUESTS)
}

fn next_idle_deadline(
  sessions: &HashMap<SessionId, ActiveWebTransportSession>,
) -> Option<tokio::time::Instant> {
  sessions
    .values()
    .filter_map(ActiveWebTransportSession::idle_deadline)
    .map(tokio::time::Instant::from_std)
    .min()
}

fn abort_tasks(tasks: &mut Vec<JoinHandle<()>>) {
  for task in tasks.drain(..) {
    task.abort();
  }
}

#[cfg(test)]
mod dedicated_connection_tests {
  use h3::quic::StreamId;
  use http::StatusCode;

  use super::{WebTransportSessionIndex, dedicated_request_rejection};

  #[test]
  fn dedicated_connection_rejects_ordinary_and_second_webtransport_request() {
    let mut index = WebTransportSessionIndex::default();
    assert_eq!(dedicated_request_rejection(false, false, &index), None);
    assert_eq!(dedicated_request_rejection(false, true, &index), None);
    assert_eq!(
      dedicated_request_rejection(true, false, &index),
      Some(StatusCode::MISDIRECTED_REQUEST)
    );
    assert_eq!(dedicated_request_rejection(true, true, &index), None);

    let first = index.insert(StreamId::try_from(0).expect("valid stream id"));
    assert_eq!(
      dedicated_request_rejection(true, true, &index),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
    index.remove(first);
    assert_eq!(
      dedicated_request_rejection(true, true, &index),
      Some(StatusCode::TOO_MANY_REQUESTS)
    );
  }
}
