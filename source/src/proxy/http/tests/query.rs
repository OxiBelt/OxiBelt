//! End-to-end QUERY admission, body identity, and cache behavior through the handler.

use super::*;
use http::{HeaderMap, HeaderValue, Version};
use pretty_assertions::assert_eq;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Fixture {
  state: Arc<AppSnapshot>,
  received: Arc<AtomicUsize>,
  server: tokio::task::JoinHandle<()>,
  _temp: common::TempDir,
}

impl Drop for Fixture {
  fn drop(&mut self) {
    self.server.abort();
  }
}

async fn fixture(upstream_version: crate::config::HttpVersion, memory: usize) -> Fixture {
  fixture_with_cache_control(upstream_version, memory, "public, max-age=3600").await
}

async fn fixture_with_cache_control(
  upstream_version: crate::config::HttpVersion,
  memory: usize,
  cache_control: &'static str,
) -> Fixture {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let received = Arc::new(AtomicUsize::new(0));
  let count = received.clone();
  let server = tokio::spawn(async move {
    let mut connections = tokio::task::JoinSet::new();
    loop {
      let (stream, _) = listener.accept().await.unwrap();
      let count = count.clone();
      connections.spawn(async move {
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
          let count = count.clone();
          async move {
            count.fetch_add(1, Ordering::SeqCst);
            let method = request.method().clone();
            let collected = request.into_body().collect().await.unwrap();
            let trailer_values = collected
              .trailers()
              .map(|trailers| {
                trailers
                  .get_all("x-query-proof")
                  .iter()
                  .map(|value| value.to_str().unwrap())
                  .collect::<Vec<_>>()
                  .join(",")
              })
              .unwrap_or_default();
            let bytes = collected.to_bytes();
            Ok::<_, Infallible>(
              Response::builder()
                .header("cache-control", cache_control)
                .header("content-type", "text/plain")
                .header("etag", "W/\"query,representation\"")
                .header("x-received-query-proof", trailer_values)
                .body(full_body(if method.as_str() == "QUERY" {
                  bytes
                } else {
                  bytes::Bytes::from_static(b"changed")
                }))
                .unwrap(),
            )
          }
        });
        if upstream_version == crate::config::HttpVersion::H2 {
          let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
        } else {
          let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
        }
      });
    }
  });
  let temp = common::TempDir::new("query-handler");
  let (cert, key) = common::create_self_signed_cert(temp.path(), "query-handler");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert, &key)).unwrap();
  config.upstreams[0].origin = format!("http://{address}").parse().unwrap();
  config.upstreams[0].max_http_version = upstream_version;
  config.routes[0].upstream_http_version = Some(upstream_version);
  config.routes[0].cache = Some("default".into());
  config.cache.enabled = true;
  config.cache.background_refresh = true;
  config.cache.cache_methods = vec!["GET".into(), "HEAD".into(), "QUERY".into()];
  config.proxy.buffering.max_memory_body_bytes = memory;
  config.validate().unwrap();
  Fixture {
    state: Arc::new(AppSnapshot::new(config).await.unwrap()),
    received,
    server,
    _temp: temp,
  }
}

async fn send(fixture: &Fixture, request: Request<ProxyBody>) -> Response<ProxyBody> {
  tokio::time::timeout(
    Duration::from_secs(10),
    handle_inner(
      request,
      "127.0.0.1:49152".parse().unwrap(),
      None,
      WafTransportMetadataInput::default(),
      Arc::new(WafTlsMetadata::default()),
      None,
      None,
      fixture.state.clone(),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      true,
      "http",
      test_drain(),
    ),
  )
  .await
  .unwrap()
}

fn request(version: Version, body: &'static [u8]) -> Request<ProxyBody> {
  Request::builder()
    .method("QUERY")
    .uri("/search")
    .version(version)
    .header("host", "example.com")
    .header("content-type", "application/json")
    .body(full_body(bytes::Bytes::from_static(body)))
    .unwrap()
}

#[tokio::test]
async fn query_body_separates_cache_entries_across_request_versions_and_upstream_transports() {
  for upstream in [
    crate::config::HttpVersion::H1,
    crate::config::HttpVersion::H2,
  ] {
    let fixture = fixture(upstream, 4096).await;
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
      for content in [b"one".as_slice(), b"two".as_slice()] {
        let response = send(&fixture, request(version, content)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
          response.into_body().collect().await.unwrap().to_bytes(),
          content
        );
      }
    }
    assert_eq!(fixture.received.load(Ordering::SeqCst), 2);
  }
}

#[tokio::test]
async fn query_conditional_range_and_unsafe_invalidation_use_matching_body() {
  let fixture = fixture(crate::config::HttpVersion::H1, 4096).await;
  send(&fixture, request(Version::HTTP_11, b"abcdef"))
    .await
    .into_body()
    .collect()
    .await
    .unwrap();
  let mut conditional = request(Version::HTTP_11, b"abcdef");
  conditional.headers_mut().insert(
    "if-none-match",
    "\"other\", \"query,representation\"".parse().unwrap(),
  );
  assert_eq!(
    send(&fixture, conditional).await.status(),
    StatusCode::NOT_MODIFIED
  );
  let mut range = request(Version::HTTP_11, b"abcdef");
  range
    .headers_mut()
    .insert("range", "bytes=1-3".parse().unwrap());
  let response = send(&fixture, range).await;
  assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
  assert_eq!(
    response.into_body().collect().await.unwrap().to_bytes(),
    "bcd"
  );
  assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
  let mut mutation = request(Version::HTTP_11, b"changed");
  *mutation.method_mut() = Method::POST;
  send(&fixture, mutation)
    .await
    .into_body()
    .collect()
    .await
    .unwrap();
  send(&fixture, request(Version::HTTP_11, b"abcdef"))
    .await
    .into_body()
    .collect()
    .await
    .unwrap();
  assert_eq!(fixture.received.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn query_streaming_overflow_forwards_without_storing_or_rejecting() {
  let fixture = fixture(crate::config::HttpVersion::H1, 3).await;
  for _ in 0..2 {
    let response = send(&fixture, request(Version::HTTP_11, b"abcdef")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.into_body().collect().await.unwrap().to_bytes(),
      "abcdef"
    );
  }
  assert_eq!(fixture.received.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn query_invalid_content_type_rejects_before_upstream_dispatch() {
  let fixture = fixture(crate::config::HttpVersion::H1, 4096).await;
  for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
    let mut missing = request(version, b"query");
    missing.headers_mut().remove("content-type");
    assert_eq!(
      send(&fixture, missing).await.status(),
      StatusCode::BAD_REQUEST
    );
    let mut duplicate = request(version, b"query");
    duplicate
      .headers_mut()
      .append("content-type", "application/json".parse().unwrap());
    assert_eq!(
      send(&fixture, duplicate).await.status(),
      StatusCode::BAD_REQUEST
    );
  }
  assert_eq!(fixture.received.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn query_background_refresh_replays_content_then_serves_the_refreshed_body() {
  let fixture = fixture_with_cache_control(
    crate::config::HttpVersion::H2,
    4096,
    "public, max-age=1, stale-while-revalidate=60",
  )
  .await;
  send(&fixture, request(Version::HTTP_2, b"query-content"))
    .await
    .into_body()
    .collect()
    .await
    .unwrap();
  tokio::time::sleep(Duration::from_millis(1100)).await;
  let stale = send(&fixture, request(Version::HTTP_2, b"query-content")).await;
  assert_eq!(
    stale.headers()["x-oxibelt-cache-reason"],
    "background_refresh"
  );
  assert_eq!(
    stale.into_body().collect().await.unwrap().to_bytes(),
    "query-content"
  );
  tokio::time::timeout(Duration::from_secs(3), async {
    loop {
      if fixture
        .state
        .metrics
        .prometheus(&Default::default(), Default::default(), Default::default())
        .contains("oxibelt_cache_background_refresh_success_total 1\n")
      {
        break;
      }
      tokio::time::sleep(Duration::from_millis(2)).await;
    }
  })
  .await
  .unwrap();
  // The refresh has committed; verify the stored response through the public handler.
  let refreshed = send(&fixture, request(Version::HTTP_2, b"query-content")).await;
  assert_eq!(refreshed.status(), StatusCode::OK);
  assert_eq!(
    refreshed.into_body().collect().await.unwrap().to_bytes(),
    "query-content"
  );
}

#[tokio::test]
async fn query_duplicate_trailer_order_reaches_upstream_and_separates_cache_hits() {
  for upstream in [
    crate::config::HttpVersion::H1,
    crate::config::HttpVersion::H2,
  ] {
    let fixture = fixture(upstream, 4096).await;
    for version in [Version::HTTP_2, Version::HTTP_3] {
      for (values, expected) in [(["z", "a"], "z,a"), (["a", "z"], "a,z")] {
        for expected_cache in ["miss", "hit"] {
          let mut trailers = HeaderMap::new();
          for value in values {
            trailers.append("x-query-proof", HeaderValue::from_static(value));
          }
          let body = http_body_util::StreamBody::new(futures_util::stream::iter(vec![
            Ok::<_, super::super::body::BoxError>(hyper::body::Frame::data(
              bytes::Bytes::from_static(b"query"),
            )),
            Ok(hyper::body::Frame::trailers(trailers)),
          ]))
          .boxed();
          let mut input = request(version, b"");
          *input.uri_mut() = format!("/trailers/{version:?}").parse().unwrap();
          *input.body_mut() = body;
          let response = send(&fixture, input).await;
          assert_eq!(response.headers()["x-received-query-proof"], expected);
          assert_eq!(response.headers()["x-oxibelt-cache"], expected_cache);
          assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "query"
          );
        }
      }
    }
    assert_eq!(fixture.received.load(Ordering::SeqCst), 4);
  }
}
