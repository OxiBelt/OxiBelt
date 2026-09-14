use super::*;
use std::time::Duration;

fn config() -> StatusHeadersConfig {
  StatusHeadersConfig {
    identifier: Some("edge".into()),
    ..Default::default()
  }
}

#[test]
fn received_chain_survives_edits_but_origin_error_is_not_proxy_error() {
  let mut response = Response::builder()
    .status(503)
    .version(Version::HTTP_2)
    .header(PROXY, "inner; received-status=503")
    .header(PROXY, "middle; x-private=?1")
    .header(CACHE, "inner-cache; hit")
    .body(())
    .unwrap();
  capture_upstream(&mut response);
  response
    .headers_mut()
    .insert(PROXY, HeaderValue::from_static("forged; error=dns_error"));
  finalize_head(&mut response, &config());
  assert_eq!(
    response.headers()[PROXY],
    "inner; received-status=503, middle; x-private=?1, \"edge\"; received-status=503; next-protocol=h2"
  );
  assert_eq!(response.headers()[CACHE], "inner-cache; hit");
  assert_eq!(response.status(), 503);
}

#[test]
fn malformed_or_over_limit_chains_are_dropped_whole() {
  for input in [
    "first, (inner)",
    "first, 12",
    "first; error=\"dns_error\"",
    "first; received-status=?1",
    "first,",
    "first; next-protocol=\"h2\"",
  ] {
    let mut response = Response::new(());
    response
      .headers_mut()
      .insert(PROXY, HeaderValue::from_str(input).unwrap());
    capture_cached(&mut response);
    finalize_head(&mut response, &config());
    assert_eq!(response.headers()[PROXY], "\"edge\"", "{input}");
  }
  for input in [
    "x".repeat(4097),
    vec!["hop"; 17].join(", "),
    format!("hop{}", ";p=?1".repeat(17)),
  ] {
    let mut response = Response::new(());
    response
      .headers_mut()
      .insert(PROXY, HeaderValue::from_str(&input).unwrap());
    capture_cached(&mut response);
    finalize_head(&mut response, &config());
    assert_eq!(response.headers()[PROXY], "\"edge\"");
  }
}

#[test]
fn append_reserves_space_and_never_deduplicates_other_hops_by_name() {
  let mut response = Response::builder()
    .header(PROXY, "\"edge\"")
    .body(())
    .unwrap();
  capture_cached(&mut response);
  finalize_head(&mut response, &config());
  assert_eq!(response.headers()[PROXY], "\"edge\", \"edge\"");
  let mut response = Response::builder()
    .header(PROXY, vec!["hop"; 16].join(", "))
    .body(())
    .unwrap();
  capture_cached(&mut response);
  finalize_head(&mut response, &config());
  assert_eq!(response.headers()[PROXY], "\"edge\"");
}

#[test]
fn origin_role_off_and_strip_have_distinct_behavior() {
  let mut response = origin(Response::new(()));
  finalize_head(&mut response, &config());
  assert!(!response.headers().contains_key(PROXY));
  let mut response = Response::builder()
    .header(PROXY, "inner")
    .header(CACHE, "inner; hit")
    .body(())
    .unwrap();
  capture_upstream(&mut response);
  let off = StatusHeadersConfig {
    proxy_status: false,
    cache_status: false,
    ..config()
  };
  finalize_head(&mut response, &off);
  assert!(!response.headers().contains_key(PROXY));
  assert!(!response.headers().contains_key(CACHE));
  let mut response = Response::builder().header(PROXY, "inner").body(()).unwrap();
  capture_cached(&mut response);
  finalize_head(
    &mut response,
    &StatusHeadersConfig {
      upstream: StatusHeaderUpstream::Strip,
      ..config()
    },
  );
  assert_eq!(response.headers()[PROXY], "\"edge\"");
}

#[test]
fn local_error_and_incremental_compatibility_are_source_owned() {
  let mut response = error(Response::new(()), "dns_timeout");
  finalize_head(&mut response, &config());
  assert_eq!(response.headers()[PROXY], "\"edge\"; error=dns_timeout");
  let mut response = super::super::incremental::refused(Version::HTTP_2);
  finalize_head(
    &mut response,
    &StatusHeadersConfig {
      proxy_status: false,
      ..config()
    },
  );
  assert_eq!(
    response.headers()[PROXY],
    "oxibelt; error=incremental_refused"
  );
}

#[test]
fn cache_facts_require_observed_forward_status_and_completed_storage() {
  let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
  let facts = StandardCacheStatus {
    hit: true,
    expires_at: Some(now + Duration::from_secs(8)),
    ..Default::default()
  };
  assert_eq!(cache_member("edge", &facts, now), "\"edge\"; hit; ttl=8");
  let facts = StandardCacheStatus {
    forwarded: Some("stale"),
    forwarded_status: Some(304),
    stored: Some(true),
    ..Default::default()
  };
  assert_eq!(
    cache_member("edge", &facts, now),
    "\"edge\"; fwd=stale; fwd-status=304; stored"
  );
  let facts = StandardCacheStatus {
    forwarded: Some("stale"),
    expires_at: Some(now - Duration::from_millis(1)),
    detail: Some("stale_if_error"),
    ..Default::default()
  };
  assert_eq!(
    cache_member("edge", &facts, now),
    "\"edge\"; ttl=-1; detail=stale_if_error"
  );
  let facts = StandardCacheStatus {
    forwarded: Some("miss"),
    forwarded_status: Some(200),
    ..Default::default()
  };
  assert_eq!(
    cache_member("edge", &facts, now),
    "\"edge\"; fwd=miss; fwd-status=200"
  );
}

#[test]
fn opaque_alias_stays_stable_and_explicit_alias_is_escaped() {
  initialize().unwrap();
  assert_eq!(identifier().unwrap(), identifier().unwrap());
  assert_eq!(identifier().unwrap().len(), 38);
  let mut response = Response::new(());
  finalize_head(
    &mut response,
    &StatusHeadersConfig {
      identifier: Some("public \\\"edge".into()),
      ..config()
    },
  );
  let chain = codec::Chain::read(response.headers(), PROXY);
  assert!(chain.append(None).is_some());
}

#[test]
fn cache_storage_restores_received_values_and_never_local_output() {
  let mut response = Response::builder()
    .header(PROXY, "inner")
    .header(CACHE, "inner; hit")
    .body(())
    .unwrap();
  capture_upstream(&mut response);
  response
    .headers_mut()
    .insert(CACHE, HeaderValue::from_static("forged; hit"));
  let (mut parts, _) = response.into_parts();
  restore_received_headers(&mut parts);
  assert_eq!(parts.headers[CACHE], "inner; hit");
  let mut response = Response::from_parts(parts, ());
  response.extensions_mut().insert(StandardCacheStatus {
    hit: true,
    ..Default::default()
  });
  finalize_head(&mut response, &config());
  assert_eq!(response.headers()[CACHE], "inner; hit, \"edge\"; hit");
}

#[test]
fn storage_without_received_evidence_drops_forged_chains() {
  let response = Response::builder()
    .header(PROXY, "forged; error=dns_error")
    .header(CACHE, "forged; hit")
    .body(())
    .unwrap();
  let (mut parts, _) = response.into_parts();
  restore_received_headers(&mut parts);
  assert!(!parts.headers.contains_key(PROXY));
  assert!(!parts.headers.contains_key(CACHE));
}

#[test]
fn connection_nominated_status_is_never_restored() {
  let mut response = Response::builder()
    .header(http::header::CONNECTION, "Proxy-Status, cache-status")
    .header(PROXY, "inner")
    .header(CACHE, "inner; hit")
    .body(())
    .unwrap();
  capture_upstream(&mut response);
  finalize_head(&mut response, &config());
  assert_eq!(
    response.headers()[PROXY],
    "\"edge\"; received-status=200; next-protocol=http/1.1"
  );
  assert!(!response.headers().contains_key(CACHE));
}

#[test]
fn cache_enabled_failed_forwarding_reports_only_known_facts() {
  let mut response = error(
    Response::builder().status(502).body(()).unwrap(),
    "connection_refused",
  );
  complete_cache_forward(&mut response, Some("miss"));
  finalize_head(&mut response, &config());
  assert_eq!(response.headers()[CACHE], "\"edge\"");
  assert_eq!(
    response.headers()[PROXY],
    "\"edge\"; error=connection_refused"
  );
  let mut uncached = Response::new(());
  complete_cache_forward(&mut uncached, None);
  finalize_head(&mut uncached, &config());
  assert!(!uncached.headers().contains_key(CACHE));
}

#[tokio::test]
async fn trailer_suppression_preserves_data_and_other_trailers() {
  use bytes::Bytes;
  use http_body_util::Full;
  let mut trailers = HeaderMap::new();
  trailers.insert(
    PROXY,
    HeaderValue::from_static("inner; error=http_response_incomplete"),
  );
  trailers.insert("grpc-status", HeaderValue::from_static("0"));
  let body = Full::new(Bytes::from_static(b"payload"))
    .with_trailers(std::future::ready(Some(Ok::<_, std::convert::Infallible>(
      trailers,
    ))))
    .map_err(|never| -> super::super::body::BoxError { match never {} })
    .boxed();
  let response = finalize(
    Response::new(body),
    &StatusHeadersConfig {
      proxy_status: false,
      ..config()
    },
  );
  let collected = response.into_body().collect().await.unwrap();
  assert_eq!(collected.trailers().unwrap()["grpc-status"], "0");
  assert!(!collected.trailers().unwrap().contains_key(PROXY));
  assert_eq!(collected.to_bytes(), "payload");
}

#[tokio::test]
async fn buffered_body_limit_reports_source_error_without_changing_response() {
  let response = super::super::response::response_buffering_error_response(
    super::super::buffering::BufferingError::TooLarge,
  );
  let response = finalize(response, &config());
  assert_eq!(response.status(), 502);
  assert_eq!(
    response.headers()[PROXY],
    "\"edge\"; error=http_response_body_too_large"
  );
  let body = response.into_body().collect().await.unwrap().to_bytes();
  assert_eq!(body, "upstream response body is too large");
}

#[test]
fn empty_received_field_is_not_silently_skipped_when_combining_lines() {
  let mut response = Response::builder()
    .header(PROXY, "")
    .header(PROXY, "inner")
    .body(())
    .unwrap();
  capture_cached(&mut response);
  finalize_head(&mut response, &config());
  assert_eq!(response.headers()[PROXY], "\"edge\"");
}
