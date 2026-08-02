//! Bound TURN listener inventory exposed through the shared lifecycle API.

use crate::server::{BoundListener, BoundListenerKind, BoundListenerTransport};

use super::BoundTurnListener;

pub(super) fn collect(listener: &BoundTurnListener) -> Vec<BoundListener> {
  let mut bound = listener
    .udp
    .as_ref()
    .and_then(|socket| socket.local_addr().ok())
    .map(|address| {
      vec![BoundListener {
        kind: BoundListenerKind::Turn,
        transport: BoundListenerTransport::Udp,
        address,
      }]
    })
    .unwrap_or_default();
  bound.extend(
    listener
      .tcp
      .iter()
      .chain(listener.tls.iter())
      .filter_map(|listener| listener.local_addr().ok())
      .map(|address| BoundListener {
        kind: BoundListenerKind::Turn,
        transport: BoundListenerTransport::Tcp,
        address,
      }),
  );
  bound
}
