//! Admin command handling for live WebTransport sessions.
//! Commands are scoped by session id so diagnostics cannot act on unrelated streams.

use std::collections::HashMap;

use h3_webtransport::SessionId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::super::DispatcherEvent;
use super::{ActiveWebTransportSession, WebTransportSessionIndex, close_session_inner};
use crate::webtransport_admin::WebTransportSessionCommand;

pub(in crate::proxy::http3::webtransport_bridge) fn close_session_with_code(
  sessions: &mut HashMap<SessionId, ActiveWebTransportSession>,
  session_index: &mut WebTransportSessionIndex,
  session_id: SessionId,
  close_code: u32,
  reason: &[u8],
) {
  close_session_inner(
    sessions,
    session_index,
    session_id,
    None,
    close_code,
    reason,
  );
}

pub(super) fn spawn_admin_session_command_forwarder(
  session_id: SessionId,
  mut commands: mpsc::UnboundedReceiver<WebTransportSessionCommand>,
  events: mpsc::Sender<DispatcherEvent>,
) -> JoinHandle<()> {
  tokio::spawn(async move {
    while let Some(command) = commands.recv().await {
      if events
        .send(DispatcherEvent::AdminClose(
          session_id,
          command.close_code,
          command.reason,
        ))
        .await
        .is_err()
      {
        return;
      }
    }
  })
}
