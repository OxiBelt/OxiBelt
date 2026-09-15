//! HTTP/1 capacity rejection must finish without an upload EOF and retire the socket.

use super::*;
use crate::config::CapacitySetting;
use pretty_assertions::assert_eq;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn decoded_response_body(head: &str, mut wire: &[u8]) -> Vec<u8> {
  if !head.contains("transfer-encoding: chunked\r\n") {
    return wire.to_vec();
  }
  let mut body = Vec::new();
  loop {
    let end = wire.windows(2).position(|bytes| bytes == b"\r\n").unwrap();
    let length = usize::from_str_radix(std::str::from_utf8(&wire[..end]).unwrap(), 16).unwrap();
    wire = &wire[end + 2..];
    if length == 0 {
      assert_eq!(wire, b"\r\n", "complete final chunk and no second response");
      return body;
    }
    body.extend_from_slice(&wire[..length]);
    assert_eq!(&wire[length..length + 2], b"\r\n");
    wire = &wire[length + 2..];
  }
}

#[tokio::test]
async fn incremental_capacity_partial_http1_upload_gets_complete_rejection_and_eof() {
  for (version, framing, partial, remainder) in [
    ("HTTP/1.0", "Content-Length: 8", "ab", "cdefgh"),
    ("HTTP/1.1", "Content-Length: 8", "ab", "cdefgh"),
    (
      "HTTP/1.1",
      "Transfer-Encoding: chunked",
      "8\r\nab",
      "cdefgh\r\n0\r\n\r\n",
    ),
  ] {
    let temp = common::TempDir::new("incremental-capacity-wire");
    let (cert, key) = common::create_self_signed_cert(temp.path(), "incremental-capacity-wire");
    let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert, &key)).unwrap();
    config.circuit_breakers.global.max_active_requests = CapacitySetting::Fixed(1);
    config.circuit_breakers.global.max_pending_requests = CapacitySetting::Fixed(0);
    config.proxy.status_headers.proxy_status = false;
    config.validate().unwrap();
    let state = Arc::new(AppSnapshot::new(config).await.unwrap());
    let lease = state
      .circuit_breakers
      .admit_global_request(None)
      .await
      .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let served = requests.clone();
    let service_state = state.clone();
    let server = tokio::spawn(async move {
      let (stream, peer) = listener.accept().await.unwrap();
      let service = hyper::service::service_fn(move |request| {
        served.fetch_add(1, Ordering::SeqCst);
        let state = service_state.clone();
        async move {
          Ok::<_, Infallible>(
            handle_inner(
              request,
              peer,
              None,
              WafTransportMetadataInput::default(),
              Arc::new(WafTlsMetadata::default()),
              None,
              None,
              state,
              WafProtocol::Http,
              WafTransportNetwork::Tcp,
              true,
              "http",
              test_drain(),
            )
            .await,
          )
        }
      });
      hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), service)
        .await
    });
    // Abort the server on assertion failure as well as cleaning up normally.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
      fn drop(&mut self) {
        self.0.abort();
      }
    }
    let _server_guard = AbortOnDrop(server.abort_handle());
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(format!(
      "POST /upload {version}\r\nHost: example.com\r\nIncremental: ?1\r\nConnection: keep-alive\r\n{framing}\r\n\r\n{partial}"
    ).as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
      while !response.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let mut byte = [0];
        let read = client.read(&mut byte).await.unwrap();
        assert_eq!(read, 1, "server must send a complete rejection head");
        response.push(byte[0]);
        assert!(response.len() < 8192, "bounded response head");
      }
    })
    .await
    .expect("rejection must arrive before the remaining upload is sent");
    let head = String::from_utf8(response.clone())
      .unwrap()
      .to_ascii_lowercase();
    assert!(
      head.starts_with(&format!("{} 429 ", version.to_ascii_lowercase())),
      "{head}"
    );
    for header in [
      "connection: close\r\n",
      "cache-control: no-store\r\n",
      "retry-after: 1\r\n",
      "proxy-status: oxibelt; error=connection_limit_reached\r\n",
    ] {
      assert!(head.contains(header), "missing {header:?}: {head}");
    }
    // If the server has already closed, writing can fail. If the bytes reach
    // it, neither the remaining upload nor the next request may be reused.
    let _ = client
      .write_all(format!("{remainder}GET /next {version}\r\nHost: example.com\r\n\r\n").as_bytes())
      .await;
    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
      .await
      .expect("HTTP/1 capacity rejection must close the connection")
      .unwrap();
    let body_start = response
      .windows(4)
      .position(|bytes| bytes == b"\r\n\r\n")
      .unwrap()
      + 4;
    assert_eq!(
      decoded_response_body(&head, &response[body_start..]),
      b"request admission unavailable"
    );
    tokio::time::timeout(Duration::from_secs(3), server)
      .await
      .unwrap()
      .unwrap()
      .unwrap();
    assert_eq!(
      requests.load(Ordering::SeqCst),
      1,
      "socket must not serve another request"
    );
    drop(lease);
    drop(client);
  }
}
