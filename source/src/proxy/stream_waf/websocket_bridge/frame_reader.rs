use fastwebsockets::WebSocketRead;
use tokio::io::AsyncRead;
#[cfg(test)]
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[cfg(test)]
use std::sync::Arc;

use super::super::{OwnedWebSocketFrame, read_owned_frame};

/// Completes each parser read in one task so quota races cannot cancel after
/// fastwebsockets has consumed a partial frame header.
pub(super) struct WebSocketFrameReader {
  permit_tx: mpsc::Sender<usize>,
  result_rx: mpsc::Receiver<Result<OwnedWebSocketFrame, String>>,
  task: JoinHandle<()>,
  outstanding: bool,
  #[cfg(test)]
  ready: Arc<Notify>,
}

impl WebSocketFrameReader {
  pub(super) fn spawn<R>(mut reader: WebSocketRead<R>) -> Self
  where
    R: AsyncRead + Unpin + Send + 'static,
  {
    let (permit_tx, mut permit_rx) = mpsc::channel::<usize>(1);
    let (result_tx, result_rx) = mpsc::channel(1);
    #[cfg(test)]
    let ready = Arc::new(Notify::new());
    #[cfg(test)]
    let task_ready = ready.clone();
    let task = tokio::spawn(async move {
      while let Some(max_payload_bytes) = permit_rx.recv().await {
        reader.set_max_message_size(max_payload_bytes.saturating_add(1).max(1));
        let result = read_owned_frame(&mut reader)
          .await
          .map_err(|error| error.to_string());
        let terminal = result.is_err();
        if result_tx.send(result).await.is_err() {
          return;
        }
        #[cfg(test)]
        task_ready.notify_one();
        if terminal {
          return;
        }
      }
    });
    Self {
      permit_tx,
      result_rx,
      task,
      outstanding: false,
      #[cfg(test)]
      ready,
    }
  }

  pub(super) async fn prepare(&mut self, max_payload_bytes: usize) -> anyhow::Result<()> {
    if self.outstanding {
      // An in-progress parse keeps the limit selected by its original permit.
      return Ok(());
    }
    self.outstanding = true;
    if self.permit_tx.send(max_payload_bytes).await.is_err() {
      self.outstanding = false;
      anyhow::bail!("WebSocket frame reader stopped");
    }
    Ok(())
  }

  pub(super) async fn receive_prepared(&mut self) -> anyhow::Result<OwnedWebSocketFrame> {
    let result = self
      .result_rx
      .recv()
      .await
      .ok_or_else(|| anyhow::anyhow!("WebSocket frame reader stopped"))?;
    self.outstanding = false;
    result.map_err(anyhow::Error::msg)
  }

  pub(super) async fn next(
    &mut self,
    max_payload_bytes: usize,
  ) -> anyhow::Result<OwnedWebSocketFrame> {
    self.prepare(max_payload_bytes).await?;
    self.receive_prepared().await
  }

  #[cfg(test)]
  pub(super) async fn wait_until_ready(&self) {
    while self.result_rx.is_empty() {
      self.ready.notified().await;
    }
  }
}

impl Drop for WebSocketFrameReader {
  fn drop(&mut self) {
    self.task.abort();
  }
}
