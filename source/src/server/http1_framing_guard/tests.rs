use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

use super::*;

#[derive(Clone, Copy)]
enum TunnelRequest {
  Connect,
  Upgrade,
}

impl TunnelRequest {
  fn request(self) -> &'static [u8] {
    match self {
      Self::Connect => b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n",
      Self::Upgrade => {
        b"GET /tunnel HTTP/1.1\r\nHost: example.test\r\n\
Connection: upgrade\r\nUpgrade: websocket\r\n\r\n"
      }
    }
  }

  fn accepted_status(self) -> u16 {
    match self {
      Self::Connect => 200,
      Self::Upgrade => 101,
    }
  }
}

struct CappedWriteIo<I> {
  inner: I,
  max_write: usize,
}

impl<I> CappedWriteIo<I> {
  fn new(inner: I, max_write: usize) -> Self {
    Self {
      inner,
      max_write: max_write.max(1),
    }
  }
}

impl<I> AsyncRead for CappedWriteIo<I>
where
  I: AsyncRead + Unpin,
{
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    destination: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_read(cx, destination)
  }
}

impl<I> AsyncWrite for CappedWriteIo<I>
where
  I: AsyncWrite + Unpin,
{
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    let limit = self.max_write.min(buf.len());
    Pin::new(&mut self.inner).poll_write(cx, &buf[..limit])
  }

  fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

async fn exchange(parts: &[&[u8]]) -> (String, usize) {
  let (mut client, server) = tokio::io::duplex(32 * 1024);
  let calls = Arc::new(AtomicUsize::new(0));
  let service_calls = calls.clone();
  let server = tokio::spawn(async move {
    let service = service_fn(move |request: hyper::Request<Incoming>| {
      let service_calls = service_calls.clone();
      async move {
        service_calls.fetch_add(1, Ordering::Relaxed);
        let _ = request.into_body().collect().await;
        Ok::<_, Infallible>(
          hyper::Response::builder()
            .status(200)
            .body(Full::new(Bytes::new()))
            .expect("test response"),
        )
      }
    });
    let io = Http1FramingGuard::new(server, 8192);
    let _ = hyper::server::conn::http1::Builder::new()
      .serve_connection(TokioIo::new(io), service)
      .await;
  });
  for part in parts {
    if let Err(error) = client.write_all(part).await {
      assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
      break;
    }
    tokio::task::yield_now().await;
  }
  let _ = client.shutdown().await;
  let mut response = Vec::new();
  client
    .read_to_end(&mut response)
    .await
    .expect("response read");
  server.await.expect("server task");
  (
    String::from_utf8(response).expect("ASCII response"),
    calls.load(Ordering::Relaxed),
  )
}

async fn rejected_tunnel_exchange(
  tunnel: TunnelRequest,
  with_upgrades: bool,
  max_response_write: usize,
) -> (String, usize) {
  let (mut client, server) = tokio::io::duplex(32 * 1024);
  let calls = Arc::new(AtomicUsize::new(0));
  let service_calls = calls.clone();
  let server = tokio::spawn(async move {
    let service = service_fn(move |request: hyper::Request<Incoming>| {
      let service_calls = service_calls.clone();
      async move {
        let call = service_calls.fetch_add(1, Ordering::Relaxed);
        let _ = request.into_body().collect().await;
        Ok::<_, Infallible>(
          hyper::Response::builder()
            .status(if call == 0 { 403 } else { 200 })
            .body(Full::new(Bytes::new()))
            .expect("test response"),
        )
      }
    });
    let io = CappedWriteIo::new(server, max_response_write);
    let io = Http1FramingGuard::new(io, 8192);
    let connection =
      hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(io), service);
    if with_upgrades {
      let _ = connection.with_upgrades().await;
    } else {
      let _ = connection.await;
    }
  });

  client
    .write_all(tunnel.request())
    .await
    .expect("tunnel request write");
  client
    .write_all(
      b"POST /ambiguous HTTP/1.1\r\nHost: example.test\r\n\
Content-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
    )
    .await
    .expect("ambiguous request write");
  client.shutdown().await.expect("input shutdown");
  let mut response = Vec::new();
  client
    .read_to_end(&mut response)
    .await
    .expect("response read");
  server.await.expect("server task");
  (
    String::from_utf8(response).expect("ASCII response"),
    calls.load(Ordering::Relaxed),
  )
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
  haystack
    .windows(needle.len())
    .any(|window| window == needle)
}

async fn accepted_tunnel_exchange(tunnel: TunnelRequest) {
  const OPAQUE: &[u8] = b"POST /opaque HTTP/1.1\r\n\
Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nraw tunnel bytes";
  const ACKNOWLEDGEMENT: &[u8] = b"tunnel-ok";

  let (mut client, server) = tokio::io::duplex(32 * 1024);
  let (observed_sender, observed_receiver) = oneshot::channel();
  let observed_sender = Arc::new(Mutex::new(Some(observed_sender)));
  let service_sender = observed_sender.clone();
  let server = tokio::spawn(async move {
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
      let on_upgrade = hyper::upgrade::on(&mut request);
      let observed_sender = service_sender
        .lock()
        .expect("sender lock")
        .take()
        .expect("single tunnel request");
      async move {
        tokio::spawn(async move {
          let upgraded = on_upgrade.await.expect("accepted Hyper upgrade");
          let mut upgraded = TokioIo::new(upgraded);
          let mut observed = vec![0_u8; OPAQUE.len()];
          upgraded
            .read_exact(&mut observed)
            .await
            .expect("opaque tunnel read");
          upgraded
            .write_all(ACKNOWLEDGEMENT)
            .await
            .expect("opaque tunnel acknowledgement");
          observed_sender
            .send(observed)
            .expect("observed tunnel bytes");
        });

        let mut response = hyper::Response::builder().status(tunnel.accepted_status());
        if matches!(tunnel, TunnelRequest::Upgrade) {
          response = response
            .header("connection", "upgrade")
            .header("upgrade", "websocket");
        }
        Ok::<_, Infallible>(
          response
            .body(Full::new(Bytes::new()))
            .expect("upgrade response"),
        )
      }
    });
    let io = Http1FramingGuard::new(server, 8192);
    let _ = hyper::server::conn::http1::Builder::new()
      .serve_connection(TokioIo::new(io), service)
      .with_upgrades()
      .await;
  });

  client
    .write_all(tunnel.request())
    .await
    .expect("tunnel request write");
  client.write_all(OPAQUE).await.expect("opaque tunnel write");

  let response = tokio::time::timeout(Duration::from_secs(5), async {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 512];
    while !contains_bytes(&response, ACKNOWLEDGEMENT) {
      let read = client.read(&mut chunk).await.expect("tunnel response read");
      assert_ne!(read, 0, "tunnel closed before acknowledgement");
      response.extend_from_slice(&chunk[..read]);
    }
    response
  })
  .await
  .expect("accepted tunnel response timeout");
  let expected_status = match tunnel {
    TunnelRequest::Connect => b"HTTP/1.1 200".as_slice(),
    TunnelRequest::Upgrade => b"HTTP/1.1 101".as_slice(),
  };
  assert!(response.starts_with(expected_status));
  assert!(contains_bytes(&response, ACKNOWLEDGEMENT));
  assert_eq!(
    tokio::time::timeout(Duration::from_secs(5), observed_receiver)
      .await
      .expect("observed tunnel timeout")
      .expect("observed tunnel sender"),
    OPAQUE,
  );
  client.shutdown().await.expect("tunnel shutdown");
  server.await.expect("server task");
}

#[tokio::test]
async fn rejects_both_ambiguous_header_orders_before_dispatch() {
  for request in [
    b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
      .as_slice(),
    b"POST / HTTP/1.1\r\nHost: example.test\r\ntransfer-encoding: chunked\r\ncontent-length: 4\r\n\r\n0\r\n\r\n"
      .as_slice(),
  ] {
    let (response, calls) = exchange(&[request]).await;
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert_eq!(calls, 0);
  }
}

#[tokio::test]
async fn rejects_an_ambiguous_head_split_across_every_byte() {
  let request =
    b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
  let parts = request
    .iter()
    .map(std::slice::from_ref)
    .collect::<Vec<&[u8]>>();
  let (response, calls) = exchange(&parts).await;
  assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
  assert_eq!(calls, 0);
}

#[tokio::test]
async fn preserves_fixed_and_chunked_body_boundaries() {
  let fixed = b"POST /one HTTP/1.1\r\nHost: example.test\r\nContent-Length: 53\r\n\r\n\
Transfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\nbody";
  assert_eq!(fixed.len(), 115);
  let (response, calls) = exchange(&[
    fixed,
    b"GET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
  ])
  .await;
  assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
  assert_eq!(calls, 2);

  let (response, calls) = exchange(&[
    b"POST /one HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"35\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\nbody\r\n0\r\nX-Trailer: ok\r\n\r\n",
    b"GET /two HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
  ])
  .await;
  assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
  assert_eq!(calls, 2);
}

#[tokio::test]
async fn rejects_an_ambiguous_pipelined_request_before_dispatch() {
  let (response, calls) = exchange(&[b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n\
POST /two HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n"])
    .await;
  assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
  assert_eq!(calls, 0);
}

#[tokio::test]
async fn rejected_tunnels_keep_follow_up_requests_framed() {
  for tunnel in [TunnelRequest::Upgrade, TunnelRequest::Connect] {
    for with_upgrades in [false, true] {
      let (response, calls) = rejected_tunnel_exchange(tunnel, with_upgrades, usize::MAX).await;
      assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
      assert!(response.contains("HTTP/1.1 400 Bad Request\r\n"));
      assert_eq!(calls, 1);
    }
  }
}

#[tokio::test]
async fn rejected_upgrade_waits_for_a_split_response_head() {
  let (response, calls) = rejected_tunnel_exchange(TunnelRequest::Upgrade, true, 1).await;
  assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
  assert!(response.contains("HTTP/1.1 400 Bad Request\r\n"));
  assert_eq!(calls, 1);
}

#[tokio::test]
async fn accepted_tunnels_preserve_opaque_bytes() {
  for tunnel in [TunnelRequest::Upgrade, TunnelRequest::Connect] {
    accepted_tunnel_exchange(tunnel).await;
  }
}

#[tokio::test]
async fn preserves_head_and_body_boundaries_with_one_byte_reads() {
  let (mut client, server) = tokio::io::duplex(4096);
  let mut guarded = Http1FramingGuard::new(server, 8192);
  let input = b"POST /one HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbody\
GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
  client.write_all(input).await.expect("input write");
  client.shutdown().await.expect("input shutdown");
  let mut output = Vec::new();
  let mut byte = [0_u8; 1];
  loop {
    let read = guarded.read(&mut byte).await.expect("guarded read");
    if read == 0 {
      break;
    }
    output.extend_from_slice(&byte[..read]);
  }
  assert_eq!(output, input);
}

#[test]
fn rejects_malformed_or_indeterminate_heads() {
  for head in [
    b"GET  / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice(),
    b"GET / HTTP/1.2\r\nHost: example.test\r\n\r\n".as_slice(),
    b"GET / HTTP/1.1\r\nBroken\r\n\r\n".as_slice(),
    b"POST / HTTP/1.1\r\nContent-Length: nope\r\n\r\n".as_slice(),
    b"POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\n".as_slice(),
    b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n".as_slice(),
    b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked, chunked\r\n\r\n".as_slice(),
    b"CONNECT example.test:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\n".as_slice(),
  ] {
    assert_eq!(classify_head(head), HeadDisposition::Reject);
  }
}

#[tokio::test]
async fn invalid_chunk_framing_fails_closed() {
  let (response, calls) = exchange(&[
    b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"4\r\nbodyX\r\n",
  ])
  .await;
  assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
  assert_eq!(calls, 1);
}

struct LimitedVectoredSink {
  max_write: usize,
}

impl AsyncWrite for LimitedVectoredSink {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Poll::Ready(Ok(self.max_write.min(buf.len())))
  }

  fn poll_write_vectored(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
    bufs: &[IoSlice<'_>],
  ) -> Poll<io::Result<usize>> {
    let available = bufs.iter().map(|buf| buf.len()).sum::<usize>();
    Poll::Ready(Ok(self.max_write.min(available)))
  }

  fn is_write_vectored(&self) -> bool {
    true
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    Poll::Ready(Ok(()))
  }
}

#[tokio::test]
async fn observes_only_successfully_written_vectored_response_bytes() {
  let response = b"HTTP/1.1 404 Not Found\r\n\r\n";
  let mut guarded = Http1FramingGuard::new(LimitedVectoredSink { max_write: 10 }, 256);
  guarded.state =
    ReadState::AwaitingTunnelResponse(ResponseHeadParser::new(TunnelKind::Upgrade, 256));
  let bufs = [IoSlice::new(&response[..12]), IoSlice::new(&response[12..])];
  assert_eq!(
    guarded
      .write_vectored(&bufs)
      .await
      .expect("partial vectored write"),
    10,
  );
  assert!(matches!(
    guarded.state,
    ReadState::AwaitingTunnelResponse(_)
  ));

  guarded.inner.max_write = usize::MAX;
  guarded
    .write_all(&response[10..])
    .await
    .expect("remaining response write");
  assert!(matches!(guarded.state, ReadState::Head));
}

#[tokio::test]
async fn observes_informational_responses_across_vectored_writes() {
  let mut guarded = Http1FramingGuard::new(
    LimitedVectoredSink {
      max_write: usize::MAX,
    },
    256,
  );
  guarded.state =
    ReadState::AwaitingTunnelResponse(ResponseHeadParser::new(TunnelKind::Upgrade, 256));
  let bufs = [
    IoSlice::new(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 4"),
    IoSlice::new(b"03 Forbidden\r\n\r\n"),
  ];
  let expected = bufs.iter().map(|buf| buf.len()).sum::<usize>();
  assert_eq!(
    guarded
      .write_vectored(&bufs)
      .await
      .expect("informational vectored write"),
    expected,
  );
  assert!(matches!(guarded.state, ReadState::Head));
}
