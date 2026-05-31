use h3_webtransport::SessionId;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::DispatcherEvent;
use crate::proxy::stream_waf::{self as stream_waf_bridge};

pub(super) fn report_activity(events: &mpsc::Sender<DispatcherEvent>, session_id: SessionId) {
  let _ = events.try_send(DispatcherEvent::Activity(session_id));
}

pub(super) async fn report_stream_task_result<F>(
  session_id: SessionId,
  future: F,
  events: mpsc::Sender<DispatcherEvent>,
) where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  let result = future.await;
  if let Err(error) = result
    && let Some(close) = stream_waf_bridge::blocked_close(&error)
  {
    let _ = events
      .send(DispatcherEvent::Blocked(session_id, close.clone()))
      .await;
  }
}

pub(super) async fn report_session_task_result<F>(
  session_id: SessionId,
  future: F,
  events: mpsc::Sender<DispatcherEvent>,
) where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  let result = future.await;
  match result {
    Ok(()) => {
      let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
    }
    Err(error) => {
      if let Some(close) = stream_waf_bridge::blocked_close(&error) {
        let _ = events
          .send(DispatcherEvent::Blocked(session_id, close.clone()))
          .await;
      } else {
        warn!(?session_id, error = %error, "WebTransport session task ended");
        let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
      }
    }
  }
}
