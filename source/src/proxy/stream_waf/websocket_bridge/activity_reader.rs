use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

use super::BridgeActivity;

pub(super) struct ActivityReader<R> {
  inner: R,
  activity: mpsc::Sender<BridgeActivity>,
}

impl<R> ActivityReader<R> {
  pub(super) fn new(inner: R, activity: mpsc::Sender<BridgeActivity>) -> Self {
    Self { inner, activity }
  }
}

impl<R> AsyncRead for ActivityReader<R>
where
  R: AsyncRead + Unpin,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    let before = buffer.filled().len();
    let result = Pin::new(&mut self.inner).poll_read(context, buffer);
    if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
      // Network activity is coalescable; a full channel already guarantees a
      // pending supervisor wakeup without stalling the socket read.
      let _ = self.activity.try_send(BridgeActivity::Network);
    }
    result
  }
}

#[cfg(test)]
mod tests {
  use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
  use tokio::sync::mpsc;

  use super::*;

  #[tokio::test]
  async fn reports_partial_socket_reads_before_a_frame_completes() {
    let (mut peer, bridge) = duplex(16);
    let (activity, mut observed) = mpsc::channel(1);
    let mut reader = ActivityReader::new(bridge, activity);
    peer.write_all(b"partial").await.unwrap();

    let mut bytes = [0; 7];
    reader.read_exact(&mut bytes).await.unwrap();

    assert_eq!(bytes, *b"partial");
    assert!(matches!(
      observed.recv().await,
      Some(BridgeActivity::Network)
    ));
  }
}
