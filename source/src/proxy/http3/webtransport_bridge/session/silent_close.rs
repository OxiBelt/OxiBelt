use std::collections::HashMap;

use h3::error::Code;
use h3_webtransport::SessionId;

use super::{ActiveWebTransportSession, WebTransportSessionIndex, record_session_end_metrics};

pub(in crate::proxy::http3::webtransport_bridge) fn close_session_silent(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
) {
  let Some(mut session) = sessions.remove(&session_id) else {
    return;
  };
  record_session_end_metrics(&session, None);
  session_index.remove(session_id);
  for task in session.tasks {
    task.abort();
  }
  session.upstream.close(0, b"");
  let stream = &mut session.connect_stream;
  stream.stop_stream(Code::H3_REQUEST_CANCELLED);
  stream.stop_sending(Code::H3_REQUEST_CANCELLED);
}
