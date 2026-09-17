//! Cancellation after the capsule writer selects data but before its carrier
//! can accept it. A gated real H2 peer makes this scheduling boundary observable.

use super::*;
use std::pin::Pin;
use std::sync::{
  Arc, Mutex,
  atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Gate {
  paused: AtomicBool,
  reader: Mutex<Option<Waker>>,
}

struct GatedIo {
  io: tokio::io::DuplexStream,
  gate: Arc<Gate>,
}

impl AsyncRead for GatedIo {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    if self.gate.paused.load(Ordering::Acquire) {
      *self.gate.reader.lock().unwrap() = Some(cx.waker().clone());
      if self.gate.paused.load(Ordering::Acquire) {
        return Poll::Pending;
      }
    }
    Pin::new(&mut self.io).poll_read(cx, buf)
  }
}

impl AsyncWrite for GatedIo {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    data: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Pin::new(&mut self.io).poll_write(cx, data)
  }
  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.io).poll_flush(cx)
  }
  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
    Pin::new(&mut self.io).poll_shutdown(cx)
  }
}

async fn cancel_selected_output(peer_stop: bool) {
  let (client_io, server_io) = tokio::io::duplex(4096);
  let gate = Arc::new(Gate::default());
  let pair = pair_with_transport_window(
    GatedIo {
      io: client_io,
      gate: gate.clone(),
    },
    server_io,
    WebTransportSettings {
      enabled: true,
      initial_max_data: Some(4096),
      initial_max_streams_bidi: Some(2),
      initial_max_streams_uni: Some(2),
      initial_max_stream_data_uni: Some(1024),
      initial_max_stream_data_bidi_local: Some(1024),
      initial_max_stream_data_bidi_remote: Some(1024),
    },
    64,
  )
  .await;
  let mut send = pair.server.open_uni().await.unwrap();
  let mut recv = pair.client.accept_uni().await.unwrap();
  gate.paused.store(true, Ordering::Release);
  let id = recv.id();
  {
    let fill = async {
      for _ in 0..16 {
        send.write_all(&[7; 64]).await.unwrap();
        send.flush().await.unwrap();
      }
    };
    let selected = async {
      loop {
        let blocked = pair
          .server
          .shared
          .lock()
          .unwrap()
          .pending_output
          .as_ref()
          .is_some_and(|pending| pending.id == id && !pending.bytes.is_empty());
        if blocked {
          break;
        }
        tokio::task::yield_now().await;
      }
    };
    tokio::select! {
      _ = selected => {},
      _ = fill => panic!("gated H2 peer must block a selected capsule"),
    }
  }
  let prefix = pair.server.shared.lock().unwrap().streams[&id].wire_sent;
  assert!(prefix > 0);
  if peer_stop {
    recv.stop(9876).unwrap();
  } else {
    send.reset(9876).unwrap();
  }
  loop {
    {
      let state = pair.server.shared.lock().unwrap();
      if state.streams[&id].send_reset == Some(9876) {
        assert!(state.pending_output.is_none());
        assert_eq!(state.streams[&id].wire_sent, prefix);
        assert_eq!(state.streams[&id].sent, prefix);
        assert_eq!(state.sent, prefix);
        assert_eq!(state.queued_send, 0);
        break;
      }
    }
    tokio::task::yield_now().await;
  }
  gate.paused.store(false, Ordering::Release);
  if let Some(reader) = gate.reader.lock().unwrap().take() {
    reader.wake();
  }
  if !peer_stop {
    let mut data = Vec::new();
    let error = recv.read_to_end(&mut data).await.unwrap_err();
    assert_eq!(crate::webtransport::stream_reset_code(&error), Some(9876));
    assert_eq!(data, vec![7; prefix as usize]);
  }
  let mut next = pair.server.open_uni().await.unwrap();
  next.write_all(b"still live").await.unwrap();
  next.shutdown().await.unwrap();
  let mut next_recv = pair.client.accept_uni().await.unwrap();
  let mut data = Vec::new();
  next_recv.read_to_end(&mut data).await.unwrap();
  assert_eq!(data, b"still live");
  assert!(pair.client.shared.lock().unwrap().failure.is_none());
}

#[tokio::test]
async fn local_reset_discards_selected_capsule_without_double_refunding_credit() {
  tokio::time::timeout(
    std::time::Duration::from_secs(10),
    cancel_selected_output(false),
  )
  .await
  .expect("local reset must interrupt selected output");
}

#[tokio::test]
async fn peer_stop_discards_selected_capsule_without_double_refunding_credit() {
  tokio::time::timeout(
    std::time::Duration::from_secs(10),
    cancel_selected_output(true),
  )
  .await
  .expect("peer STOP must interrupt selected output");
}
