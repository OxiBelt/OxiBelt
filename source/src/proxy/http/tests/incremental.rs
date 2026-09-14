use super::*;
use hyper::body::{Frame, SizeHint};
use pretty_assertions::assert_eq;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct UnpolledBody;

#[tokio::test]
async fn incremental_waf_header_actions_select_full_pipeline_before_evaluation() {
  for (phase, action) in [
    ("request", "set_request_header"),
    ("response", "set_response_header"),
  ] {
    for name in ["InCrEmEnTaL", "x-ordinary-test"] {
      let extra = format!(
        r#"
[waf]
enabled = true
[[waf.rules]]
name = "mark-stream"
phase = "{phase}"
priority = 100
when = "true"
[[waf.rules.actions]]
type = "{action}"
name = "{name}"
value = "?1"
"#
      );
      let (state, _temp) = snapshot(&extra, |config| config.compression.enabled = false).await;
      let resolved = state
        .route_table
        .resolve("example.com", "/", &state.upstreams)
        .unwrap();
      assert_eq!(
        resolved.execution_plan.fast_path.plain_proxy_h1,
        name == "x-ordinary-test"
      );
      if name == "InCrEmEnTaL" {
        assert!(!resolved.execution_plan.fast_path.plain_proxy_h2);
        assert!(!resolved.execution_plan.fast_path.plain_proxy_h3);
      }
    }
  }
}

impl Body for UnpolledBody {
  type Data = bytes::Bytes;
  type Error = body::BoxError;
  fn poll_frame(
    self: Pin<&mut Self>,
    _: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    panic!("incremental refusal must not poll the upload")
  }
  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

async fn snapshot(
  extra: &str,
  configure: impl FnOnce(&mut Config),
) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp = common::TempDir::new("incremental-policy");
  let (cert, key) = common::create_self_signed_cert(temp.path(), "incremental-policy");
  let mut config: Config = toml::from_str(&format!(
    "{}\n{extra}",
    common::minimal_config_toml(&cert, &key)
  ))
  .unwrap();
  configure(&mut config);
  config.validate().unwrap();
  (Arc::new(AppSnapshot::new(config).await.unwrap()), temp)
}

async fn send<B>(state: Arc<AppSnapshot>, request: Request<B>) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes, Error = body::BoxError> + Send + Sync + Unpin + 'static,
{
  tokio::time::timeout(
    Duration::from_secs(3),
    handle_inner(
      request,
      "203.0.113.10:49152".parse().unwrap(),
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
    ),
  )
  .await
  .expect("headers must complete without body EOF")
}

#[tokio::test]
async fn incremental_request_refuses_memory_and_spool_before_body_poll() {
  for mode in [
    crate::config::BufferingMode::Memory,
    crate::config::BufferingMode::Spool,
    crate::config::BufferingMode::RejectIfTooLarge,
  ] {
    let (state, temp) = snapshot("", |config| {
      config.proxy.buffering.request = mode;
      config.proxy.buffering.temp_dir = Some(std::env::temp_dir());
      config.proxy.buffering.max_temp_file_bytes = 1024 * 1024;
    })
    .await;
    let response = send(
      state,
      Request::builder()
        .method("POST")
        .uri("/upload")
        .header("host", "example.com")
        .header("incremental", "?1;future=token")
        .body(UnpolledBody)
        .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{mode:?}");
    assert_eq!(
      response.headers()["proxy-status"],
      "oxibelt; error=incremental_refused"
    );
    drop(temp);
  }
}

fn inspection(phase: &str) -> String {
  let action = if phase == "request" {
    "reject"
  } else {
    "reject_response"
  };
  let subject = if phase == "request" {
    "Request"
  } else {
    "Response"
  };
  format!(
    r#"
[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"
[[waf.pattern_sets]]
name = "incremental-test"
kind = "contains"
patterns = ["forbidden"]
[[waf.rules]]
name = "inspect-incremental"
priority = 100
phase = "{phase}"
when = "{subject}.Body.scan('incremental-test').Matched"
[[waf.rules.actions]]
type = "{action}"
status = 403
body = "blocked"
"#
  )
}

#[tokio::test]
async fn incremental_request_refuses_prefix_inspection_before_body_poll() {
  let (state, _temp) = snapshot(&inspection("request"), |_| {}).await;
  let response = send(
    state,
    Request::builder()
      .method("POST")
      .uri("/upload")
      .header("host", "example.com")
      .header("incremental", "?1")
      .body(UnpolledBody)
      .unwrap(),
  )
  .await;
  assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn incremental_request_refuses_external_auth_body_capture() {
  let extra = r#"
[[external_auth]]
name = "body-auth"
provider = "gateway_ext_auth_http"
endpoint = "http://127.0.0.1:1/auth"
max_request_body_bytes = 1024
allowed_content_types = ["application/octet-stream"]
"#;
  let (state, _temp) = snapshot(extra, |config| {
    config.routes[0].external_auth = Some("body-auth".into())
  })
  .await;
  let response = send(
    state,
    Request::builder()
      .method("POST")
      .uri("/upload")
      .header("host", "example.com")
      .header("incremental", "?1")
      .header("content-type", "application/octet-stream")
      .body(UnpolledBody)
      .unwrap(),
  )
  .await;
  assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn incremental_h3_connect_failure_completes_unstarted_exchange() {
  // Keep a UDP port open without answering QUIC so failure is deterministic
  // and occurs before the request body can be handed to an uploader.
  let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
  let address = sink.local_addr().unwrap();
  let (state, _temp) = snapshot("", |config| {
    config.proxy.auto_upgrade.enabled = true;
    config.proxy.auto_upgrade.max_http_version = HttpVersion::H3;
    config.upstreams[0].origin = format!("https://{address}").parse().unwrap();
    config.upstreams[0].max_http_version = HttpVersion::H3;
    config.upstreams[0].connect_timeout_ms = 25;
    config.upstreams[0].request_timeout_ms = 100;
  })
  .await;
  let response = send(
    state,
    Request::builder()
      .method("POST")
      .uri("/upload")
      .header("host", "example.com")
      .header("incremental", "?1")
      .body(UnpolledBody)
      .unwrap(),
  )
  .await;
  assert!(response.status().is_server_error());
  let exchange = response
    .extensions()
    .get::<incremental_exchange::IncrementalExchange>()
    .expect("dispatched incremental request carries its lifetime controller");
  assert!(exchange.is_cancelled());
  assert!(
    exchange.is_complete(),
    "failed connect must release unstarted upload accounting"
  );
  assert!(
    !response
      .into_body()
      .collect()
      .await
      .unwrap()
      .to_bytes()
      .is_empty()
  );
}

#[tokio::test]
async fn incremental_response_streams_or_refuses_before_upstream_eof() {
  for scenario in ["stream", "buffer", "inspect"] {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (done, wait) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
      let (mut socket, _) = listener.accept().await.unwrap();
      let mut head = Vec::new();
      while !head.ends_with(b"\r\n\r\n") {
        head.push(socket.read_u8().await.unwrap());
      }
      socket.write_all(b"HTTP/1.1 200 OK\r\nIncremental: ?1\r\nContent-Length: 4\r\nContent-Type: text/plain\r\n\r\na").await.unwrap();
      let _ = wait.await;
    });
    let extra = if scenario == "inspect" {
      inspection("response")
    } else {
      String::new()
    };
    let (state, _temp) = snapshot(&extra, |config| {
      config.upstreams[0].origin = format!("http://{address}").parse().unwrap();
      config.upstreams[0].max_http_version = HttpVersion::H1;
      config.compression.min_size_bytes = 0;
      config.cache.enabled = true;
      if scenario == "buffer" {
        config.proxy.buffering.response = crate::config::BufferingMode::Memory;
      }
    })
    .await;
    let response = send(
      state,
      Request::builder()
        .uri("/stream")
        .header("host", "example.com")
        .header("accept-encoding", "gzip")
        .body(empty_test_body())
        .unwrap(),
    )
    .await;
    if scenario == "stream" {
      assert_eq!(response.status(), StatusCode::OK);
      assert!(!response.headers().contains_key("content-encoding"));
      let mut body = response.into_body();
      let frame = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
      assert_eq!(frame.data_ref().unwrap().as_ref(), b"a");
    } else {
      assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED, "{scenario}");
      assert_eq!(
        response.headers()["proxy-status"],
        "oxibelt; error=incremental_refused"
      );
    }
    let _ = done.send(());
    server.await.unwrap();
  }
}
