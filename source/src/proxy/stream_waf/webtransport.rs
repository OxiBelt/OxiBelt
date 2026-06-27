use crate::state::AppSnapshot;
use crate::waf::{
  WafStreamClose, WafStreamDirection, WafWebTransportStreamKind, WafWebTransportStreamMetadata,
};

use super::{StreamWafBlocked, StreamWafRequestContext, inspect_prefix};

pub(crate) fn blocked_close(error: &anyhow::Error) -> Option<&WafStreamClose> {
  error
    .downcast_ref::<StreamWafBlocked>()
    .and_then(StreamWafBlocked::close_option)
}

pub(crate) fn blocked_silent_close(error: &anyhow::Error) -> bool {
  error
    .downcast_ref::<StreamWafBlocked>()
    .is_some_and(StreamWafBlocked::is_silent_close)
}

pub(crate) fn check_webtransport_payload(
  state: &AppSnapshot,
  context: Option<&StreamWafRequestContext>,
  direction: WafStreamDirection,
  payload: &[u8],
  metadata: WafWebTransportStreamMetadata,
) -> Result<(), StreamWafBlocked> {
  let Some(context) = context else {
    return Ok(());
  };
  let prefix = inspect_prefix(payload, context.max_payload_bytes());
  let decision = context.evaluate_webtransport(
    state,
    direction,
    prefix.bytes,
    prefix.is_truncated,
    metadata,
  );
  if let Some(close) = decision.close {
    Err(StreamWafBlocked::new(close))
  } else if decision.silent_close {
    Err(StreamWafBlocked::silent_close())
  } else {
    Ok(())
  }
}

pub(crate) fn webtransport_stream_metadata(
  stream_kind: WafWebTransportStreamKind,
) -> WafWebTransportStreamMetadata {
  WafWebTransportStreamMetadata {
    stream_kind: Some(stream_kind),
    stream_id: None,
    datagram_size: None,
  }
}

pub(crate) fn webtransport_datagram_metadata(size: usize) -> WafWebTransportStreamMetadata {
  WafWebTransportStreamMetadata {
    stream_kind: None,
    stream_id: None,
    datagram_size: Some(size),
  }
}
