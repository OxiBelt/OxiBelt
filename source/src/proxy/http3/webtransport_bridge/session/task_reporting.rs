//! Task-result reporting for WebTransport stream workers.
//! Reporting is best effort and must not hide the primary session close reason.

use h3_webtransport::SessionId;
use tokio::sync::mpsc;
use tracing::warn;

use super::super::{DispatcherEvent, UpstreamWebTransportSession};
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
  if let Err(error) = result {
    if stream_waf_bridge::blocked_silent_close(&error) {
      let _ = events
        .send(DispatcherEvent::SilentBlocked(session_id))
        .await;
    } else if let Some(close) = stream_waf_bridge::blocked_close(&error) {
      let _ = events
        .send(DispatcherEvent::Blocked(session_id, close.clone()))
        .await;
    }
  }
}

pub(super) async fn report_session_task_result<F>(
  session_id: SessionId,
  future: F,
  upstream: std::sync::Arc<UpstreamWebTransportSession>,
  events: mpsc::Sender<DispatcherEvent>,
) where
  F: std::future::Future<Output = anyhow::Result<()>>,
{
  let result = future.await;
  match result {
    Ok(()) => {}
    Err(error) => {
      if stream_waf_bridge::blocked_silent_close(&error) {
        let _ = events
          .send(DispatcherEvent::SilentBlocked(session_id))
          .await;
        return;
      } else if let Some(close) = stream_waf_bridge::blocked_close(&error) {
        let _ = events
          .send(DispatcherEvent::Blocked(session_id, close.clone()))
          .await;
        return;
      } else {
        warn!(?session_id, error = %error, "WebTransport session task ended");
      }
    }
  }
  // Stream accept/read can fail before the CONNECT reader publishes its close.
  // The single ordered control task owns that event, including a preceding
  // drain capsule. Only a still-open session after a bounded grace is failed.
  if tokio::time::timeout(std::time::Duration::from_secs(1), upstream.closed())
    .await
    .is_err()
  {
    let _ = events.send(DispatcherEvent::SessionEnded(session_id)).await;
  }
}
