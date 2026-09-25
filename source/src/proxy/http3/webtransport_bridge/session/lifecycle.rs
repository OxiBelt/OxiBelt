//! Session expiry and coordinated close cleanup.

use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use h3_webtransport::SessionId;

use crate::waf::WafStreamClose;

use super::metrics::record_session_end_metrics;
use super::{ActiveWebTransportSession, WebTransportSessionIndex};

pub(crate) fn close_expired_sessions(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
) {
  let now = Instant::now();
  let expired = sessions
    .iter()
    .filter_map(|(session_id, session)| {
      session
        .idle_deadline()
        .is_some_and(|deadline| deadline <= now)
        .then_some(*session_id)
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

pub(crate) fn close_all_sessions(
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

pub(crate) fn close_all_sessions_after_downstream_loss(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  reason: &'static [u8],
) {
  let session_ids = sessions.keys().copied().collect::<Vec<_>>();
  for session_id in session_ids {
    close_session_after_client_reader(sessions, session_index, session_id, reason);
  }
}

pub(crate) fn close_session_after_client_reader(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  reason: &'static [u8],
) {
  close_session_inner_with_reader_grace(sessions, session_index, session_id, None, 0, reason, true);
}

pub(crate) fn close_session(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  close: Option<&WafStreamClose>,
  fallback_reason: &'static [u8],
) {
  let (close_code, reason) = match close {
    Some(close) => (close.webtransport_code, close.reason.as_bytes()),
    None => (0, fallback_reason),
  };
  close_session_inner(
    sessions,
    session_index,
    session_id,
    close,
    close_code,
    reason,
  );
}

pub(super) fn close_session_inner(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  metrics_close: Option<&WafStreamClose>,
  close_code: u32,
  reason: &[u8],
) {
  close_session_inner_with_reader_grace(
    sessions,
    session_index,
    session_id,
    metrics_close,
    close_code,
    reason,
    false,
  );
}

#[allow(clippy::too_many_arguments)]
fn close_session_inner_with_reader_grace(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  metrics_close: Option<&WafStreamClose>,
  close_code: u32,
  reason: &[u8],
  wait_for_client_reader: bool,
) {
  let Some(mut session) = sessions.remove(&session_id) else {
    return;
  };
  record_session_end_metrics(&session, metrics_close);
  session_index.remove(session_id);
  let upstream_reason = reason.to_vec();
  let reason = bounded_close_reason(reason);
  tokio::spawn(async move {
    if wait_for_client_reader {
      wait_for_client_close_reader(session.client_reader_done.take()).await;
    }
    let close_written = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      session.connect_stream.write_close(close_code, &reason),
    )
    .await;
    session.upstream.close(close_code, &upstream_reason);
    for task in &session.tasks {
      task.abort();
    }
    for task in session.tasks.drain(..) {
      let _ = task.await;
    }
    if matches!(close_written, Ok(true)) {
      let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        session.connect_stream.drain_after_close(),
      )
      .await;
    } else {
      session
        .connect_stream
        .stop_stream(h3::error::Code::H3_NO_ERROR);
    }
    retire_http2_upstream(session);
  });
}

async fn wait_for_client_close_reader(done: Option<tokio::sync::oneshot::Receiver<()>>) {
  if let Some(done) = done {
    // Connection loss can be observed before buffered CLOSE DATA is parsed.
    // Give the reader a bounded chance to claim its validated application
    // code before a generic code-0 close takes the upstream first-writer slot.
    let _ = tokio::time::timeout(Duration::from_millis(50), done).await;
  }
}

pub(in crate::proxy::http3::webtransport_bridge) fn close_session_from_peer(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  code: u32,
  reason: &[u8],
) {
  close_session_inner(sessions, session_index, session_id, None, code, reason);
}

pub(in crate::proxy::http3::webtransport_bridge) fn close_session_abrupt(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
) {
  let Some(mut session) = take_abrupt_session(sessions, session_index, session_id) else {
    return;
  };
  record_session_end_metrics(&session, None);
  tokio::spawn(async move {
    let reset_first = tokio::time::timeout(
      std::time::Duration::from_secs(1),
      session.connect_stream.reset_abrupt_send(),
    )
    .await
    .is_ok();
    if reset_first {
      session.abrupt_reset_tx.send_replace(true);
      // Child bidi workers retain their downstream receive halves until the
      // peer observes the CONNECT reset and ends the session. Give all tasks
      // a bounded chance to finish on their own before aborting stragglers.
      let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for task in &mut session.tasks {
          let _ = task.await;
        }
      })
      .await;
    }
    for task in &session.tasks {
      if !task.is_finished() {
        task.abort();
      }
    }
    for task in session.tasks.drain(..) {
      if !task.is_finished() {
        let _ = task.await;
      }
    }
    if !reset_first {
      let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        session.connect_stream.reset_abrupt_send(),
      )
      .await;
      session.abrupt_reset_tx.send_replace(true);
    }
    session.connect_stream.drain_after_abrupt_reset().await;
    retire_http2_upstream(session);
  });
}

fn take_abrupt_session<T>(
  sessions: &mut HashMap<SessionId, T>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
) -> Option<T> {
  let session = sessions.remove(&session_id)?;
  session_index.remove(session_id);
  Some(session)
}

fn bounded_close_reason(reason: &[u8]) -> String {
  let reason = String::from_utf8_lossy(reason);
  let limit = reason.floor_char_boundary(reason.len().min(1024));
  reason[..limit].to_owned()
}

pub(super) fn retire_http2_upstream(mut session: ActiveWebTransportSession) {
  if session._upstream_connection_guard.is_http2() {
    // H2 CLOSE is queued asynchronously. Retain the session's permits and
    // reservations until its forwarding tasks and carrier have retired.
    tokio::spawn(async move {
      for task in session.tasks.drain(..) {
        let _ = task.await;
      }
      session._upstream_connection_guard.finish_http2().await;
      drop(session);
    });
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::sync::{Arc, OnceLock};

  use h3::quic::StreamId;
  use tokio::sync::oneshot;

  use super::{
    WebTransportSessionIndex, bounded_close_reason, take_abrupt_session,
    wait_for_client_close_reader,
  };

  #[test]
  fn close_reason_is_utf8_and_bounded() {
    assert_eq!(bounded_close_reason("peer close".as_bytes()), "peer close");
    assert_eq!(bounded_close_reason(&[0xff]), "�");
    assert_eq!(bounded_close_reason("€".repeat(342).as_bytes()).len(), 1023);
  }

  #[test]
  fn abrupt_close_removes_only_affected_session() {
    let mut index = WebTransportSessionIndex::default();
    let lost = index.insert(StreamId::try_from(0).expect("valid stream id"));
    let sibling = index.insert(StreamId::try_from(4).expect("valid stream id"));
    let mut sessions = HashMap::from([(lost, "lost"), (sibling, "sibling")]);

    assert_eq!(
      take_abrupt_session(&mut sessions, &mut index, lost),
      Some("lost")
    );
    assert!(!index.contains(lost));
    assert_eq!(sessions.get(&sibling), Some(&"sibling"));
    assert!(index.contains(sibling));
  }

  #[tokio::test]
  async fn buffered_client_close_wins_before_connection_loss_fallback() {
    let (reader_done_tx, reader_done_rx) = oneshot::channel();
    let upstream_close = Arc::new(OnceLock::new());
    let fallback_close = upstream_close.clone();
    let cleanup = tokio::spawn(async move {
      wait_for_client_close_reader(Some(reader_done_rx)).await;
      let _ = fallback_close.set(0_u32);
    });
    tokio::task::yield_now().await;
    assert!(upstream_close.get().is_none());
    assert!(upstream_close.set(99_u32).is_ok());
    reader_done_tx
      .send(())
      .expect("reader completion delivered");
    cleanup.await.expect("fallback cleanup completed");
    assert_eq!(upstream_close.get(), Some(&99));
  }

  #[tokio::test]
  async fn connection_loss_fallback_closes_when_client_reader_stalls() {
    let (_reader_done_tx, reader_done_rx) = oneshot::channel();
    let upstream_close = Arc::new(OnceLock::new());
    let fallback_close = upstream_close.clone();
    let cleanup = tokio::spawn(async move {
      wait_for_client_close_reader(Some(reader_done_rx)).await;
      let _ = fallback_close.set(0_u32);
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), cleanup)
      .await
      .expect("fallback remained bounded")
      .expect("fallback cleanup completed");
    assert_eq!(upstream_close.get(), Some(&0));
  }
}
