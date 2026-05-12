use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
  H3BidiStream, H3RequestStream, H3ServerConnection, handle_h3_request, is_webtransport_request,
  rejects_unsafe_early_data, respond_to_h3_request,
};
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;
use crate::waf::WafStreamClose;

mod connection;
mod session;

use connection::{DownstreamWebTransportConnection, spawn_downstream_reader_tasks};
use session::{
  ActiveWebTransportSession, WebTransportSessionIndex, accept_webtransport_session,
  close_all_sessions, close_expired_sessions, close_session, handle_downstream_bidi_stream,
  handle_downstream_datagram, handle_downstream_uni_stream,
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
  DownstreamBidi(SessionId, DownstreamBidiStream),
  DownstreamUni(SessionId, DownstreamUniRecvStream),
  DownstreamDatagram(StreamId, Bytes),
  DownstreamRequest(Request<()>, Box<H3RequestStream>),
  Activity(SessionId),
  Blocked(SessionId, WafStreamClose),
  SessionEnded(SessionId),
  ConnectionClosed,
  Fatal(anyhow::Error),
}

enum DownstreamBidiEvent {
  WebTransport(SessionId, DownstreamBidiStream),
  Request(Request<()>, Box<H3RequestStream>),
  Closed,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_webtransport_connection(
  h3_connection: H3ServerConnection,
  initial_request: Request<()>,
  initial_stream: H3RequestStream,
  peer_addr: SocketAddr,
  udp_connection_id: Arc<str>,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  early_data: crate::quic::h3::EarlyDataTracker,
  mut shutdown: watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let downstream = Arc::new(DownstreamWebTransportConnection::new(h3_connection));
  let (events_tx, mut events_rx) = mpsc::channel(256);
  let mut downstream_tasks = spawn_downstream_reader_tasks(downstream.clone(), events_tx.clone());
  let mut sessions = HashMap::new();
  let mut session_index = WebTransportSessionIndex::default();

  handle_downstream_request(
    downstream.clone(),
    &mut sessions,
    &mut session_index,
    initial_request,
    initial_stream,
    peer_addr,
    udp_connection_id.clone(),
    tls_metadata.clone(),
    connection_limit_context.clone(),
    state.clone(),
    early_data.clone(),
    drain.clone(),
    events_tx.clone(),
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
            handle_downstream_bidi_stream(&mut sessions, session_id, stream, events_tx.clone());
          }
          Some(DispatcherEvent::DownstreamUni(session_id, stream)) => {
            handle_downstream_uni_stream(&mut sessions, session_id, stream, events_tx.clone());
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
              connection_limit_context.clone(),
              state.clone(),
              early_data.clone(),
              drain.clone(),
              events_tx.clone(),
            )
            .await?;
          }
          Some(DispatcherEvent::Activity(session_id)) => {
            if let Some(session) = sessions.get_mut(&session_id) {
              session.last_activity = Instant::now();
              session.reap_finished_tasks();
            }
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
          Some(DispatcherEvent::SessionEnded(session_id)) => {
            close_session(
              &mut sessions,
              &mut session_index,
              session_id,
              None,
              b"WebTransport session ended",
            );
          }
          Some(DispatcherEvent::ConnectionClosed) | None => {
            close_all_sessions(
              &mut sessions,
              &mut session_index,
              Some(b"downstream HTTP/3 connection closed"),
            );
            abort_tasks(&mut downstream_tasks);
            return Ok(());
          }
          Some(DispatcherEvent::Fatal(error)) => {
            close_all_sessions(
              &mut sessions,
              &mut session_index,
              Some(b"downstream HTTP/3 connection failed"),
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
  connection_limit_context: Option<ConnectionLimitContext>,
  state: AppHandle,
  early_data: crate::quic::h3::EarlyDataTracker,
  drain: ConnectionDrain,
  events: mpsc::Sender<DispatcherEvent>,
) -> anyhow::Result<()> {
  let is_early_data = early_data.take(stream.id());
  if rejects_unsafe_early_data(
    &request,
    state.snapshot().config.quic.zero_rtt,
    is_early_data,
  ) {
    respond_to_h3_request(stream, text_response(StatusCode::TOO_EARLY, "too early")).await?;
    return Ok(());
  }

  if is_webtransport_request(&request) {
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
    let status = handle_h3_request(
      request,
      stream,
      peer_addr,
      udp_connection_id,
      tls_metadata,
      connection_limit_context,
      state,
      drain,
    )
    .await?;
    debug!(peer = %peer_addr, %status, "handled downstream HTTP/3 request");
  }

  Ok(())
}

fn next_idle_deadline(
  sessions: &HashMap<SessionId, ActiveWebTransportSession>,
) -> Option<tokio::time::Instant> {
  sessions
    .values()
    .map(|session| {
      tokio::time::Instant::from_std(session.last_activity + session.webtransport_idle())
    })
    .min()
}

fn abort_tasks(tasks: &mut Vec<JoinHandle<()>>) {
  for task in tasks.drain(..) {
    task.abort();
  }
}
