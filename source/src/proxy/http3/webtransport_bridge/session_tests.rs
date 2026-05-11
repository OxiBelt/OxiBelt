use std::convert::TryFrom;

use h3::quic::StreamId;

use super::*;

#[test]
fn session_index_inserts_and_removes_sessions() {
  let mut index = WebTransportSessionIndex::default();
  let connect_stream_id = StreamId::try_from(8).expect("valid stream id");

  let session_id = index.insert(connect_stream_id);

  assert_eq!(session_id, session_id_for_stream_id(connect_stream_id));
  assert!(index.contains(session_id));
  assert_eq!(index.connect_stream_id(session_id), Some(connect_stream_id));

  index.remove(session_id);

  assert!(!index.contains(session_id));
  assert_eq!(index.connect_stream_id(session_id), None);
}

#[test]
fn unknown_sessions_do_not_route() {
  let mut index = WebTransportSessionIndex::default();
  let known_stream_id = StreamId::try_from(0).expect("valid stream id");
  let unknown_stream_id = StreamId::try_from(4).expect("valid stream id");

  index.insert(known_stream_id);

  assert_eq!(
    index.session_for_datagram_stream_id(unknown_stream_id),
    None
  );
}

#[test]
fn datagram_lookup_uses_associated_connect_stream_id() {
  let mut index = WebTransportSessionIndex::default();
  let connect_stream_id = StreamId::try_from(12).expect("valid stream id");
  let other_connect_stream_id = StreamId::try_from(16).expect("valid stream id");

  let session_id = index.insert(connect_stream_id);

  assert_eq!(
    index.session_for_datagram_stream_id(connect_stream_id),
    Some(session_id)
  );
  assert_eq!(
    index.session_for_datagram_stream_id(other_connect_stream_id),
    None
  );
}
