//! In-memory HTTP/2 connections exercise the actual typed carrier and capsule engine.

use super::*;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Empty;
use hyper::ext::WebTransportSettings;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

struct Pair {
  client: Session,
  server: Session,
  sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
  tasks: Vec<JoinHandle<()>>,
}

impl Drop for Pair {
  fn drop(&mut self) {
    self.client.silent_close();
    self.server.silent_close();
    for task in &self.tasks {
      task.abort();
    }
  }
}

async fn pair() -> Pair {
  let (client_io, server_io) = tokio::io::duplex(65_536);
  let settings = WebTransportSettings {
    enabled: true,
    initial_max_data: Some(0),
    initial_max_streams_bidi: Some(0),
    initial_max_streams_uni: Some(0),
    initial_max_stream_data_uni: Some(1024),
    initial_max_stream_data_bidi_local: Some(1024),
    initial_max_stream_data_bidi_remote: Some(1024),
  };
  pair_with_settings(client_io, server_io, settings).await
}

async fn pair_with_settings(
  client_io: tokio::io::DuplexStream,
  server_io: tokio::io::DuplexStream,
  settings: WebTransportSettings,
) -> Pair {
  pair_with_transport_window(client_io, server_io, settings, 65_535).await
}

async fn pair_with_transport_window<I>(
  client_io: I,
  server_io: tokio::io::DuplexStream,
  settings: WebTransportSettings,
  window: u32,
) -> Pair
where
  I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
  let (accepted, mut receiver) = tokio::sync::mpsc::channel(1);
  let service = hyper::service::service_fn(move |mut request| {
    let accepted = accepted.clone();
    async move {
      if request.method() != http::Method::CONNECT {
        return Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()));
      }
      let session = hyper::ext::on_webtransport(&mut request);
      accepted.send(session).await.unwrap();
      Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
    }
  });
  let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
  builder
    .enable_connect_protocol()
    .webtransport_settings(settings);
  let server_driver = tokio::spawn(async move {
    let _ = builder
      .serve_connection(TokioIo::new(server_io), service)
      .await;
  });
  let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
  builder.initial_stream_window_size(window);
  // Client support advertising is not required by draft-15; every paired
  // session also exercises that asymmetric SETTINGS negotiation.
  builder.webtransport_settings(WebTransportSettings {
    enabled: false,
    ..settings
  });
  let (mut sender, driver) = builder.handshake(TokioIo::new(client_io)).await.unwrap();
  let client_driver = tokio::spawn(async move {
    let _ = driver.await;
  });
  let request = Request::builder()
    .method("CONNECT")
    .uri("https://localhost/session")
    .body(Empty::<Bytes>::new())
    .unwrap();
  let (_, client_carrier) = sender.send_webtransport_request(request).await.unwrap();
  let server_carrier = receiver.recv().await.unwrap().await.unwrap();
  let limits = crate::config::H2WebTransportConfig {
    max_stream_buffer_bytes: 1024,
    max_session_buffer_bytes: 4096,
    max_concurrent_uni_streams: 2,
    max_concurrent_bidi_streams: 2,
    ..Default::default()
  };
  let (client, client_actor) = Session::start(
    client_carrier,
    SessionOptions::proxy(limits, Role::Client),
    Budget::new(),
  )
  .unwrap();
  let (server, server_actor) = Session::start(
    server_carrier,
    SessionOptions::proxy(limits, Role::Server),
    Budget::new(),
  )
  .unwrap();
  Pair {
    client,
    server,
    sender,
    tasks: vec![
      client_driver,
      server_driver,
      tokio::spawn(async move {
        let _ = client_actor.await;
      }),
      tokio::spawn(async move {
        let _ = server_actor.await;
      }),
    ],
  }
}

#[tokio::test]
async fn real_h2_carrier_bidi_bootstraps_all_zero_settings() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let (client_io, server_io) = tokio::io::duplex(65_536);
    let pair = pair_with_settings(
      client_io,
      server_io,
      WebTransportSettings {
        enabled: true,
        initial_max_data: Some(0),
        initial_max_streams_bidi: Some(0),
        initial_max_streams_uni: Some(0),
        initial_max_stream_data_uni: Some(0),
        initial_max_stream_data_bidi_local: Some(0),
        initial_max_stream_data_bidi_remote: Some(0),
      },
    )
    .await;
    let (mut client_send, mut client_receive) = pair.client.open_bi().await.unwrap();
    let (mut server_send, mut server_receive) = pair.server.accept_bi().await.unwrap();
    let client_write = async {
      client_send.write_all(b"client").await.unwrap();
      client_send.shutdown().await.unwrap();
    };
    let server_write = async {
      server_send.write_all(b"server").await.unwrap();
      server_send.shutdown().await.unwrap();
    };
    let server_read = async {
      let mut bytes = Vec::new();
      server_receive.read_to_end(&mut bytes).await.unwrap();
      assert_eq!(bytes, b"client");
    };
    let client_read = async {
      let mut bytes = Vec::new();
      client_receive.read_to_end(&mut bytes).await.unwrap();
      assert_eq!(bytes, b"server");
    };
    tokio::join!(client_write, server_write, server_read, client_read);
  })
  .await
  .expect("zero initial settings must bootstrap both bidi directions");
}

#[tokio::test]
async fn real_h2_carrier_streams_progress_beyond_both_credit_windows() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let pair = pair().await;
    let payload = vec![0x59; 65_537];
    let (mut client_send, mut client_receive) = pair.client.open_bi().await.unwrap();
    let (mut server_send, mut server_receive) = pair.server.accept_bi().await.unwrap();
    let echo = async {
      tokio::io::copy(&mut server_receive, &mut server_send)
        .await
        .unwrap();
      server_send.shutdown().await.unwrap();
    };
    let write = async {
      client_send.write_all(&payload).await.unwrap();
      client_send.shutdown().await.unwrap();
    };
    let read = async {
      let mut actual = Vec::new();
      client_receive.read_to_end(&mut actual).await.unwrap();
      assert_eq!(actual, payload);
    };
    tokio::join!(echo, write, read);
  })
  .await
  .expect("flow control must make progress");
}

#[tokio::test]
async fn cumulative_stream_credit_replenishes_and_datagrams_and_close_survive() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let pair = pair().await;
    for index in 0..8 {
      let mut send = pair.server.open_uni().await.unwrap();
      send.write_all(&[index]).await.unwrap();
      send.shutdown().await.unwrap();
      drop(send);
      let mut receive = pair.client.accept_uni().await.unwrap();
      let mut actual = Vec::new();
      receive.read_to_end(&mut actual).await.unwrap();
      assert_eq!(actual, [index]);
    }
    pair
      .client
      .send_datagram(Bytes::from_static(b"datagram"))
      .unwrap();
    assert_eq!(pair.server.read_datagram().await.unwrap(), "datagram");
    pair.server.close(1234, b"finished");
    assert_eq!(
      pair.client.closed().await.unwrap(),
      (1234, Bytes::from_static(b"finished"))
    );
  })
  .await
  .expect("closed streams must replenish peer stream slots");
}

#[tokio::test]
async fn stream_reset_exposes_the_application_code_without_closing_the_session() {
  let pair = pair().await;
  let (mut client_send, _) = pair.client.open_bi().await.unwrap();
  client_send.write_all(b"x").await.unwrap();
  let (_, mut server_receive) = pair.server.accept_bi().await.unwrap();
  let mut prefix = [0_u8; 1];
  server_receive.read_exact(&mut prefix).await.unwrap();
  client_send.reset(4321).unwrap();
  // A bridge drops its send handle immediately after forwarding RESET. The
  // destructor's cancellation must preserve the application code before the
  // independently driven writer gets another poll.
  drop(client_send);
  let error = tokio::io::AsyncReadExt::read(&mut server_receive, &mut [0_u8; 1])
    .await
    .unwrap_err();
  assert_eq!(crate::webtransport::stream_reset_code(&error), Some(4321));
  pair
    .client
    .send_datagram(Bytes::from_static(b"still-live"))
    .unwrap();
  assert_eq!(
    pair.server.read_datagram().await.unwrap(),
    Bytes::from_static(b"still-live")
  );
}

#[tokio::test]
async fn late_credit_cannot_open_local_or_receive_only_streams() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    for (from_client, id, rejected) in [(false, 2, false), (false, 6, true), (true, 2, true)] {
      let pair = pair().await;
      let mut send = pair.client.open_uni().await.unwrap();
      send.shutdown().await.unwrap();
      let mut receive = pair.server.accept_uni().await.unwrap();
      assert_eq!(receive.read(&mut [0]).await.unwrap(), 0);
      drop(send);
      drop(receive);
      let (sender, receiver) = if from_client {
        (&pair.client, &pair.server)
      } else {
        (&pair.server, &pair.client)
      };
      sender
        .shared
        .lock()
        .unwrap()
        .controls
        .push_back(codec::control(codec::MAX_STREAM_DATA, &[id, 2048]).unwrap());
      sender.shared.wake();
      if rejected {
        assert!(receiver.closed().await.is_err());
        assert_eq!(receiver.shared.lock().unwrap().failure.unwrap().reset, 1);
      } else {
        sender
          .send_datagram(Bytes::from_static(b"after-credit"))
          .unwrap();
        assert_eq!(receiver.read_datagram().await.unwrap(), b"after-credit"[..]);
        assert!(receiver.shared.lock().unwrap().streams.is_empty());
      }
    }
  })
  .await
  .expect("terminal credit must not resurrect streams or stall the session");
}

#[tokio::test]
async fn malformed_session_reset_keeps_ordinary_h2_request_usable() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let mut pair = pair().await;
    // One more byte than the negotiated initial per-stream receive credit.
    let wire = codec::stream(0, &vec![0; 1025], false).unwrap();
    pair.client.shared.lock().unwrap().controls.push_back(wire);
    pair.client.shared.wake();
    assert!(pair.server.closed().await.is_err());
    assert_eq!(pair.server.shared.lock().unwrap().failure.unwrap().reset, 3);
    let request = Request::builder()
      .uri("https://localhost/ordinary")
      .body(Empty::<Bytes>::new())
      .unwrap();
    let response = pair.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
  })
  .await
  .expect("one bad session must not block unrelated HTTP/2 traffic");
}

#[tokio::test]
async fn stream_reset_validates_reliable_size_and_application_code() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    let pair = pair().await;
    let mut send = pair.client.open_uni().await.unwrap();
    send.write_all(b"reliable").await.unwrap();
    send.flush().await.unwrap();
    send.reset(0x1020_3040).unwrap();
    drop(send);
    let mut receive = pair.server.accept_uni().await.unwrap();
    let mut actual = Vec::new();
    assert!(receive.read_to_end(&mut actual).await.is_err());
    assert_eq!(actual, b"reliable");
    assert_eq!(
      pair
        .server
        .shared
        .lock()
        .unwrap()
        .streams
        .get(&receive.id())
        .unwrap()
        .receive_reset,
      Some(0x1020_3040)
    );
  })
  .await
  .expect("valid reset must preserve the reliable stream prefix");
}

#[tokio::test]
async fn close_preserves_queued_stream_data_fin_and_drain() {
  tokio::time::timeout(std::time::Duration::from_secs(10), async {
    for _ in 0..32 {
      let pair = pair().await;
      let mut send = pair.server.open_uni().await.unwrap();
      let mut recv = pair.client.accept_uni().await.unwrap();
      send.write_all(b"terminal event\n").await.unwrap();
      // Queue FIN without yielding to the actor, then close in the same turn.
      // This is the race between an application close and pending carrier output.
      std::future::poll_fn(|cx| {
        let _ = std::pin::Pin::new(&mut send).poll_shutdown(cx);
        std::task::Poll::Ready(())
      })
      .await;
      pair.server.drain();
      pair.server.close(42, b"completed");
      let mut received = Vec::new();
      recv.read_to_end(&mut received).await.unwrap();
      assert_eq!(received, b"terminal event\n");
      assert_eq!(
        pair.client.closed().await.unwrap(),
        (42, Bytes::from_static(b"completed"))
      );
      assert!(pair.client.shared.lock().unwrap().draining);
    }
  })
  .await
  .expect("queued terminal stream and drain must precede CLOSE_SESSION");
}

mod backpressure;
