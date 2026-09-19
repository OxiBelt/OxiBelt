use super::super::body::channel_body;
use super::*;
use http::HeaderName;
use http_body_util::{BodyExt, Full};

fn request(value: &str) -> DigestRequest {
  let mut headers = HeaderMap::new();
  headers.insert(WANT_CONTENT_DIGEST, HeaderValue::from_str(value).unwrap());
  DigestRequest::new(&Method::GET, Version::HTTP_2, &headers, TrailerMode::Pass)
}
fn body(bytes: &'static [u8]) -> ProxyBody {
  Full::new(Bytes::from_static(bytes))
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

#[test]
fn want_selection_prefers_highest_positive_and_sha256_ties() {
  let mut headers = HeaderMap::new();
  headers.insert(
    WANT_CONTENT_DIGEST,
    HeaderValue::from_static("sha-512=2, sha-256=2, x=9"),
  );
  assert_eq!(
    wanted_algorithm(&headers, WANT_CONTENT_DIGEST),
    Some(Algorithm::Sha256)
  );
  headers.insert(
    WANT_CONTENT_DIGEST,
    HeaderValue::from_static("sha-512=3, sha-256=2"),
  );
  assert_eq!(
    wanted_algorithm(&headers, WANT_CONTENT_DIGEST),
    Some(Algorithm::Sha512)
  );
}

#[test]
fn want_rejects_invalid_members_without_an_error_response() {
  for value in [
    "sha-256=11",
    "sha-256=-1",
    "sha-256=1.5",
    "sha-256=?1",
    "sha-256=(1)",
    "unknown=?1, sha-256=1",
    "sha-256=1, sha-256=?1",
  ] {
    let mut headers = HeaderMap::new();
    headers.insert(WANT_CONTENT_DIGEST, HeaderValue::from_str(value).unwrap());
    assert_eq!(
      wanted_algorithm(&headers, WANT_CONTENT_DIGEST),
      None,
      "{value}"
    );
  }
  let mut values = Vec::new();
  for index in 0..65 {
    values.push(format!("x{index}=1"));
  }
  let mut headers = HeaderMap::new();
  headers.insert(
    WANT_CONTENT_DIGEST,
    HeaderValue::from_str(&values.join(", ")).unwrap(),
  );
  assert_eq!(wanted_algorithm(&headers, WANT_CONTENT_DIGEST), None);
}

#[test]
fn invalidation_keeps_unencoded_for_coding_only() {
  let mut headers = HeaderMap::new();
  headers.insert(
    TRAILER,
    HeaderValue::from_static("Content-Digest, Repr-Digest, Unencoded-Digest, x-kept"),
  );
  invalidate(&mut headers, true);
  assert_eq!(headers[TRAILER], "Unencoded-Digest, x-kept");
  invalidate_content(&mut headers);
  assert_eq!(headers[TRAILER], "Unencoded-Digest, x-kept");
}

#[tokio::test]
async fn streamed_digest_is_one_trailer_after_clean_eof() {
  let context = request("sha-256=1");
  let response = finalize(Response::new(body(b"abc")), &context);
  let collected = response.into_body().collect().await.unwrap();
  let trailers = collected.trailers().cloned().unwrap();
  assert_eq!(collected.to_bytes(), Bytes::from_static(b"abc"));
  assert_eq!(
    trailers[CONTENT_DIGEST],
    "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:"
  );
}

#[tokio::test]
async fn bodyless_responses_without_available_representation_omit_repr_and_unencoded() {
  let mut headers = HeaderMap::new();
  for name in [WANT_CONTENT_DIGEST, WANT_REPR_DIGEST, WANT_UNENCODED_DIGEST] {
    headers.insert(name, HeaderValue::from_static("sha-256=1"));
  }

  let get = DigestRequest::new(&Method::GET, Version::HTTP_2, &headers, TrailerMode::Pass);
  let mut origin_304 = Response::new(body(b""));
  *origin_304.status_mut() = StatusCode::NOT_MODIFIED;
  let origin_304 = finalize(origin_304, &get);
  assert!(origin_304.headers().contains_key(CONTENT_DIGEST));
  assert!(!origin_304.headers().contains_key(REPR_DIGEST));
  assert!(!origin_304.headers().contains_key(UNENCODED_DIGEST));
  assert!(
    origin_304
      .into_body()
      .collect()
      .await
      .unwrap()
      .trailers()
      .is_none()
  );

  let head = DigestRequest::new(&Method::HEAD, Version::HTTP_2, &headers, TrailerMode::Pass);
  let mut local_head = Response::new(body(b""));
  local_head.extensions_mut().insert(Representation::Complete);
  let local_head = finalize(local_head, &head);
  assert!(local_head.headers().contains_key(CONTENT_DIGEST));
  assert!(!local_head.headers().contains_key(REPR_DIGEST));
  assert!(!local_head.headers().contains_key(UNENCODED_DIGEST));
  assert!(
    local_head
      .into_body()
      .collect()
      .await
      .unwrap()
      .trailers()
      .is_none()
  );
}

#[tokio::test]
async fn trailer_incapable_native_grpc_streams_remain_opaque() {
  let mut headers = HeaderMap::new();
  for name in [WANT_CONTENT_DIGEST, WANT_REPR_DIGEST, WANT_UNENCODED_DIGEST] {
    headers.insert(name, HeaderValue::from_static("sha-256=1"));
  }

  for (version, trailer_mode) in [
    (Version::HTTP_11, TrailerMode::Drop),
    (Version::HTTP_2, TrailerMode::Drop),
    (Version::HTTP_3, TrailerMode::Drop),
    // HTTP/1.1 also needs an explicit TE: trailers permission.
    (Version::HTTP_11, TrailerMode::Pass),
  ] {
    let (sender, body) = channel_body(4);
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"grpc payload"))))
      .await
      .unwrap();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
    drop(sender);

    let context = DigestRequest::new(&Method::GET, version, &headers, trailer_mode);
    let mut response = Response::new(body);
    response
      .headers_mut()
      .insert("content-type", HeaderValue::from_static("application/grpc"));
    let response = finalize(response, &context);
    assert!(!response.headers().contains_key(CONTENT_DIGEST));
    assert!(!response.headers().contains_key(REPR_DIGEST));
    assert!(!response.headers().contains_key(UNENCODED_DIGEST));
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(collected.trailers().unwrap()["grpc-status"], "0");
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"grpc payload"));
  }
}

#[tokio::test]
async fn http10_streaming_omits_digests_but_materialized_content_is_a_header() {
  let mut headers = HeaderMap::new();
  headers.insert(WANT_CONTENT_DIGEST, HeaderValue::from_static("sha-256=1"));
  let context = DigestRequest::new(&Method::GET, Version::HTTP_10, &headers, TrailerMode::Pass);

  let (sender, stream_body) = channel_body(4);
  sender
    .send(Ok(Frame::data(Bytes::from_static(b"streaming"))))
    .await
    .unwrap();
  let mut trailers = HeaderMap::new();
  trailers.insert("x-origin", HeaderValue::from_static("preserved"));
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  drop(sender);
  let streamed = finalize(Response::new(stream_body), &context);
  assert!(!streamed.headers().contains_key(CONTENT_DIGEST));
  let collected = streamed.into_body().collect().await.unwrap();
  assert_eq!(collected.trailers().unwrap()["x-origin"], "preserved");
  assert_eq!(collected.to_bytes(), Bytes::from_static(b"streaming"));

  let mut materialized = Response::new(body(b"materialized"));
  materialized
    .extensions_mut()
    .insert(InlinedKnownSmallResponseBody::new(
      Bytes::from_static(b"materialized"),
      None,
    ));
  let materialized = finalize(materialized, &context);
  assert_eq!(
    materialized.headers()[CONTENT_DIGEST],
    digest_header(Algorithm::Sha256, b"materialized").unwrap()
  );
  assert!(
    materialized
      .into_body()
      .collect()
      .await
      .unwrap()
      .trailers()
      .is_none()
  );
}

#[tokio::test]
async fn unknown_content_encoding_omits_unencoded_and_hashes_final_bytes() {
  let mut headers = HeaderMap::new();
  for name in [WANT_CONTENT_DIGEST, WANT_REPR_DIGEST, WANT_UNENCODED_DIGEST] {
    headers.insert(name, HeaderValue::from_static("sha-256=1"));
  }
  let context = DigestRequest::new(&Method::GET, Version::HTTP_2, &headers, TrailerMode::Pass);
  let encoded = b"opaque encoded wire bytes";
  let mut response = Response::new(body(encoded));
  response.headers_mut().insert(
    CONTENT_ENCODING,
    HeaderValue::from_static("x-unknown-coding"),
  );
  let collected = finalize(response, &context)
    .into_body()
    .collect()
    .await
    .unwrap();
  let trailers = collected.trailers().unwrap();
  let expected = digest_header(Algorithm::Sha256, encoded).unwrap();
  assert_eq!(trailers.get(CONTENT_DIGEST), Some(&expected));
  assert_eq!(trailers.get(REPR_DIGEST), Some(&expected));
  assert!(!trailers.contains_key(UNENCODED_DIGEST));
}

#[tokio::test]
async fn large_origin_trailers_are_preserved_while_optional_digests_are_omitted() {
  let context = request("sha-256=1");
  let (sender, body) = channel_body(4);
  sender
    .send(Ok(Frame::data(Bytes::from_static(b"abc"))))
    .await
    .unwrap();
  let large = "x".repeat(MAX_FIELD_BYTES + 1);
  let mut trailers = HeaderMap::new();
  trailers.insert("x-origin", HeaderValue::from_str(&large).unwrap());
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  drop(sender);
  let collected = finalize(Response::new(body), &context)
    .into_body()
    .collect()
    .await
    .unwrap();
  let trailers = collected.trailers().unwrap();
  assert_eq!(trailers["x-origin"].len(), large.len());
  assert!(!trailers.contains_key(CONTENT_DIGEST));
}

#[test]
fn head_content_digest_is_a_header_without_trailer_permission() {
  let mut headers = HeaderMap::new();
  headers.insert(WANT_CONTENT_DIGEST, HeaderValue::from_static("sha-256=1"));
  let context = DigestRequest::new(&Method::HEAD, Version::HTTP_10, &headers, TrailerMode::Pass);
  let response = finalize(Response::new(body(b"")), &context);
  assert_eq!(
    response.headers()[CONTENT_DIGEST],
    "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
  );
}

#[tokio::test]
async fn compression_carrier_preserves_unrequested_duplicate_unencoded_trailers() {
  let context = DigestRequest::new(
    &Method::GET,
    Version::HTTP_2,
    &HeaderMap::new(),
    TrailerMode::Pass,
  );
  let (sender, body) = channel_body(4);
  let (body, state) = prehash_unencoded_body(body, None);
  sender
    .send(Ok(Frame::data(Bytes::from_static(b"abc"))))
    .await
    .unwrap();
  let mut trailers = HeaderMap::new();
  trailers.append(
    UNENCODED_DIGEST,
    HeaderValue::from_static("sha-256=:first=:"),
  );
  trailers.append(
    UNENCODED_DIGEST,
    HeaderValue::from_static("sha-512=:second=:"),
  );
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  drop(sender);
  let mut response = Response::new(body);
  response.extensions_mut().insert(state);
  let collected = finalize(response, &context)
    .into_body()
    .collect()
    .await
    .unwrap();
  let values = collected.trailers().unwrap().get_all(UNENCODED_DIGEST);
  assert_eq!(values.iter().count(), 2);
  assert_eq!(values.iter().next().unwrap(), "sha-256=:first=:");
}

#[tokio::test]
async fn compression_carrier_preserves_large_origin_unencoded_trailers() {
  let context = DigestRequest::new(
    &Method::GET,
    Version::HTTP_2,
    &HeaderMap::new(),
    TrailerMode::Pass,
  );
  let (sender, body) = channel_body(4);
  let (body, state) = prehash_unencoded_body(body, None);
  let value = "x".repeat(MAX_FIELD_BYTES + 1);
  let mut trailers = HeaderMap::new();
  trailers.append(UNENCODED_DIGEST, HeaderValue::from_str(&value).unwrap());
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  drop(sender);
  let mut response = Response::new(body);
  response.extensions_mut().insert(state);
  let collected = finalize(response, &context)
    .into_body()
    .collect()
    .await
    .unwrap();
  assert_eq!(
    collected.trailers().unwrap()[UNENCODED_DIGEST].len(),
    value.len()
  );
}

#[tokio::test]
async fn prehash_does_not_complete_after_trailers_followed_by_an_error() {
  let (sender, body) = channel_body(4);
  let (body, state) = prehash_unencoded_body(body, Some(Algorithm::Sha256));
  let mut trailers = HeaderMap::new();
  trailers.append(
    UNENCODED_DIGEST,
    HeaderValue::from_static("sha-256=:opaque=:"),
  );
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  sender
    .send(Err(Box::new(std::io::Error::other("late body error"))))
    .await
    .unwrap();
  drop(sender);
  assert!(body.collect().await.is_err());
  assert_eq!(state.source().len(), 1);
  assert!(state.digest(Algorithm::Sha256).is_none());
}

#[tokio::test]
async fn trailers_followed_by_data_are_rejected_without_a_generated_digest() {
  let (sender, body) = channel_body(4);
  let mut trailers = HeaderMap::new();
  trailers.insert("x-origin", HeaderValue::from_static("kept-until-error"));
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  sender
    .send(Ok(Frame::data(Bytes::from_static(
      b"invalid after trailers",
    ))))
    .await
    .unwrap();
  drop(sender);
  assert!(
    finalize(Response::new(body), &request("sha-256=1"))
      .into_body()
      .collect()
      .await
      .is_err()
  );

  let (sender, body) = channel_body(4);
  let (body, state) = prehash_unencoded_body(body, Some(Algorithm::Sha256));
  let mut trailers = HeaderMap::new();
  trailers.append(
    UNENCODED_DIGEST,
    HeaderValue::from_static("sha-256=:opaque=:"),
  );
  sender.send(Ok(Frame::trailers(trailers))).await.unwrap();
  sender
    .send(Ok(Frame::data(Bytes::from_static(
      b"invalid after trailers",
    ))))
    .await
    .unwrap();
  drop(sender);
  assert!(body.collect().await.is_err());
  assert_eq!(state.source().len(), 1);
  assert!(state.digest(Algorithm::Sha256).is_none());
}

#[test]
fn dropping_a_prehash_body_never_marks_the_digest_complete() {
  let (_sender, body) = channel_body(1);
  let (body, state) = prehash_unencoded_body(body, Some(Algorithm::Sha256));
  drop(body);
  assert!(state.digest(Algorithm::Sha256).is_none());
}

#[test]
fn mutation_remove_suppresses_later_generation_but_set_clears_it() {
  let suppression = DigestFieldSuppression::default();
  suppression.record_mutations(&[HeaderMutation::Remove {
    name: HeaderName::from_static(CONTENT_DIGEST),
  }]);
  assert!(suppression.contains(CONTENT_DIGEST));
  suppression.record_mutations(&[HeaderMutation::Set {
    name: HeaderName::from_static(CONTENT_DIGEST),
    value: HeaderValue::from_static("opaque"),
  }]);
  assert!(!suppression.contains(CONTENT_DIGEST));
}
