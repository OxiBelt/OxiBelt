//! In-memory WebTransport session index.
//! The index is observational and drain-oriented, not an authorization store.

use std::collections::HashMap;

use h3::quic::StreamId;
use h3_webtransport::SessionId;

#[derive(Default)]
pub(in crate::proxy::http3::webtransport_bridge) struct WebTransportSessionIndex {
  connect_stream_ids: HashMap<SessionId, StreamId>,
}

impl WebTransportSessionIndex {
  pub(super) fn insert(&mut self, connect_stream_id: StreamId) -> SessionId {
    let session_id = session_id_for_stream_id(connect_stream_id);
    self
      .connect_stream_ids
      .insert(session_id, connect_stream_id);
    session_id
  }

  pub(super) fn remove(&mut self, session_id: SessionId) {
    self.connect_stream_ids.remove(&session_id);
  }

  pub(in crate::proxy::http3::webtransport_bridge) fn contains(
    &self,
    session_id: SessionId,
  ) -> bool {
    self.connect_stream_ids.contains_key(&session_id)
  }

  #[cfg(test)]
  pub(in crate::proxy::http3::webtransport_bridge) fn connect_stream_id(
    &self,
    session_id: SessionId,
  ) -> Option<StreamId> {
    self.connect_stream_ids.get(&session_id).copied()
  }

  pub(super) fn session_for_datagram_stream_id(&self, stream_id: StreamId) -> Option<SessionId> {
    let session_id = session_id_for_stream_id(stream_id);
    self.contains(session_id).then_some(session_id)
  }
}

pub(super) fn session_id_for_stream_id(stream_id: StreamId) -> SessionId {
  SessionId::from(stream_id)
}
