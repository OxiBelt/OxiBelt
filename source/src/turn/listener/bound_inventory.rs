//! Bound TURN listener inventory exposed through the shared lifecycle API.

use crate::server::{BoundListener, BoundListenerKind, BoundListenerTransport};

use super::BoundTurnListener;

pub(super) fn collect(listener: &BoundTurnListener) -> Vec<BoundListener> {
  let mut bound = listener
    .udp
    .iter()
    .filter_map(|socket| socket.local_addr().ok())
    .map(|address| BoundListener {
      kind: BoundListenerKind::Turn,
      transport: BoundListenerTransport::Udp,
      address,
    })
    .collect::<Vec<_>>();
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
