//! Session expiry and coordinated close cleanup.

use std::collections::HashMap;
use std::time::Instant;

use h3::error::Code;
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
  let Some(mut session) = sessions.remove(&session_id) else {
    return;
  };
  record_session_end_metrics(&session, metrics_close);
  session_index.remove(session_id);
  for task in session.tasks {
    task.abort();
  }
  session.upstream.close(close_code, reason);
  session.connect_stream.stop_stream(Code::H3_NO_ERROR);
  session.connect_stream.stop_sending(Code::H3_NO_ERROR);
}
