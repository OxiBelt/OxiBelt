use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;

struct MockRecv {
  stopped: Arc<Mutex<Vec<u32>>>,
}

impl AsyncRead for MockRecv {
  fn poll_read(
    self: Pin<&mut Self>,
    _: &mut Context<'_>,
    _: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    Poll::Pending
  }
}

impl StoppableRecv for MockRecv {
  fn stop(&mut self, code: u32) -> io::Result<()> {
    self
      .stopped
      .lock()
      .map_err(|_| io::Error::other("mock receive stop lock poisoned"))?
      .push(code);
    Ok(())
  }
}

struct MockSend {
  queued: Vec<u8>,
  flushed: Arc<Mutex<Vec<u8>>>,
  resets: Arc<Mutex<Vec<u32>>>,
  stopped: Option<u32>,
}

impl AsyncWrite for MockSend {
  fn poll_write(
    mut self: Pin<&mut Self>,
    _: &mut Context<'_>,
    bytes: &[u8],
  ) -> Poll<io::Result<usize>> {
    self.queued.extend_from_slice(bytes);
    Poll::Ready(Ok(bytes.len()))
  }

  fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
    let queued = std::mem::take(&mut self.queued);
    self
      .flushed
      .lock()
      .map_err(|_| io::Error::other("mock send flush lock poisoned"))?
      .extend_from_slice(&queued);
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    self.poll_flush(context)
  }
}

impl ResettableSend for MockSend {
  fn reset(&mut self, code: u32) -> io::Result<()> {
    self.queued.clear();
    self
      .resets
      .lock()
      .map_err(|_| io::Error::other("mock send reset lock poisoned"))?
      .push(code);
    Ok(())
  }
}

impl StopAwareSend for MockSend {
  fn poll_stopped(&mut self, _: &mut Context<'_>) -> Poll<io::Result<u32>> {
    self
      .stopped
      .map_or(Poll::Pending, |code| Poll::Ready(Ok(code)))
  }
}

#[tokio::test]
async fn copy_forwards_stop_while_receive_is_idle() {
  let stopped = Arc::new(Mutex::new(Vec::new()));
  let recv = MockRecv {
    stopped: stopped.clone(),
  };
  let send = MockSend {
    queued: Vec::new(),
    flushed: Arc::new(Mutex::new(Vec::new())),
    resets: Arc::new(Mutex::new(Vec::new())),
    stopped: Some(73),
  };

  let mut recv = recv;
  let mut send = send;
  let mut buffer = [0_u8; 1];
  let result = tokio::time::timeout(
    Duration::from_secs(1),
    read_or_stop(&mut recv, &mut send, &mut buffer),
  )
  .await
  .expect("idle receive must not hide STOP_SENDING")
  .unwrap();
  assert!(matches!(result, ReadControl::Stopped));
  assert_eq!(*stopped.lock().unwrap(), vec![73]);
}

#[tokio::test]
async fn reset_forwarding_flushes_accepted_prefix() {
  let stopped = Arc::new(Mutex::new(Vec::new()));
  let recv = MockRecv { stopped };
  let flushed = Arc::new(Mutex::new(Vec::new()));
  let resets = Arc::new(Mutex::new(Vec::new()));
  let send = MockSend {
    queued: Vec::new(),
    flushed: flushed.clone(),
    resets: resets.clone(),
    stopped: None,
  };

  let mut recv = recv;
  let mut send = send;
  assert!(matches!(
    write_all_or_stop(&mut send, b"accepted prefix")
      .await
      .unwrap(),
    SendControl::Complete
  ));
  assert!(matches!(
    forward_reset(&mut recv, &mut send, 47).await.unwrap(),
    SendControl::Complete
  ));

  assert_eq!(*flushed.lock().unwrap(), b"accepted prefix");
  assert_eq!(*resets.lock().unwrap(), vec![47]);
}

struct ResetRecv {
  prefix: Option<&'static [u8]>,
}

impl AsyncRead for ResetRecv {
  fn poll_read(
    mut self: Pin<&mut Self>,
    _: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if let Some(prefix) = self.prefix.take() {
      buffer.put_slice(prefix);
      Poll::Ready(Ok(()))
    } else {
      Poll::Ready(Err(io::Error::new(
        io::ErrorKind::ConnectionReset,
        crate::webtransport::StreamResetCode(47),
      )))
    }
  }
}

impl StoppableRecv for ResetRecv {
  fn stop(&mut self, _: u32) -> io::Result<()> {
    Ok(())
  }
}

#[tokio::test]
async fn copy_forwards_h3_reset_error_and_flushes_its_delivered_prefix() {
  let flushed = Arc::new(Mutex::new(Vec::new()));
  let resets = Arc::new(Mutex::new(Vec::new()));
  let send = MockSend {
    queued: Vec::new(),
    flushed: flushed.clone(),
    resets: resets.clone(),
    stopped: None,
  };
  copy(
    ResetRecv {
      prefix: Some(b"delivered prefix"),
    },
    send,
    WafStreamDirection::UpstreamToDownstream,
    WafWebTransportStreamKind::Uni,
    None,
    None,
    RouteBandwidthLimiter::new(crate::bandwidth::BandwidthPolicy::UNLIMITED),
    Metrics::new(),
    Activity::new(),
  )
  .await
  .unwrap();
  assert_eq!(*flushed.lock().unwrap(), b"delivered prefix");
  assert_eq!(*resets.lock().unwrap(), [47]);
}
