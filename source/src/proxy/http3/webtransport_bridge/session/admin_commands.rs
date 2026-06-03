//! Admin command handling for live WebTransport sessions.
//! Commands are scoped by session id so diagnostics cannot act on unrelated streams.

use h3_webtransport::SessionId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::super::DispatcherEvent;
use crate::webtransport_admin::WebTransportSessionCommand;

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
