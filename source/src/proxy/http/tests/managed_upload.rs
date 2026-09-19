use super::*;
use crate::waf::metadata::WafClientCertificateMetadata;
use pretty_assertions::assert_eq;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

async fn snapshot(waf: &str) -> (Arc<AppSnapshot>, common::TempDir) {
  snapshot_with_destination(waf, "{ kind = \"object\" }", None).await
}

async fn snapshot_with_destination(
  waf: &str,
  destination: &str,
  origin: Option<std::net::SocketAddr>,
) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp = common::TempDir::new("managed-upload-http");
  let (cert, key) = common::create_self_signed_cert(temp.path(), "managed-upload-http");
  let raw = format!(
    r#"{}
[[upload_stores]]
name = "local"
kind = "local"
[upload_stores.local]
root = "{root}/store"
[[upload_profiles]]
name = "media"
store = "local"
public_base_url = "https://example.com/"
staging_dir = "{root}"
max_staging_bytes = 128
control_path_prefix = "/uploads"
object_path_prefix = "/objects"
destination = {destination}
identity = {{ kind = "mtls", source = "test-ca" }}
max_upload_bytes = 64
max_part_bytes = 16
max_storage_bytes = 512
max_sessions = 8
max_parts = 8
inspection_bytes = 16
ttl_seconds = 60
object_ttl_seconds = 60
max_concurrent_uploads = 4
max_concurrent_parts = 4
{waf}
"#,
    common::minimal_config_toml(&cert, &key),
    root = temp.path().display()
  );
  let mut config: Config = toml::from_str(&raw).unwrap();
  if let Some(origin) = origin {
    config.upstreams[0].origin = format!("http://{origin}").parse().unwrap();
    config.upstreams[0].max_http_version = crate::config::HttpVersion::H1;
  }
  config.routes[0].upstream = None;
  config.routes[0].resumable_upload = Some("media".to_owned());
  config.routes[0].r#match.tls.client_cert.present = Some(true);
  config.compression.enabled = false;
  config.runtime.memory_only_state = false;
  config.validate().unwrap();
  (Arc::new(AppSnapshot::new(config).await.unwrap()), temp)
}

struct OriginFixture {
  address: std::net::SocketAddr,
  requests: Arc<AtomicUsize>,
  server: tokio::task::JoinHandle<()>,
}

impl Drop for OriginFixture {
  fn drop(&mut self) {
    self.server.abort();
  }
}

async fn origin(status: StatusCode) -> OriginFixture {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let requests = Arc::new(AtomicUsize::new(0));
  let count = requests.clone();
  let server = tokio::spawn(async move {
    loop {
      let (stream, _) = listener.accept().await.unwrap();
      let count = count.clone();
      tokio::spawn(async move {
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
          let count = count.clone();
          async move {
            count.fetch_add(1, Ordering::SeqCst);
            let _ = request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(
              Response::builder()
                .status(status)
                .body(full_body(bytes::Bytes::new()))
                .unwrap(),
            )
          }
        });
        let _ = hyper::server::conn::http1::Builder::new()
          .serve_connection(TokioIo::new(stream), service)
          .await;
      });
    }
  });
  OriginFixture {
    address,
    requests,
    server,
  }
}

async fn send(
  state: Arc<AppSnapshot>,
  method: &str,
  path: &str,
  data: &'static [u8],
  headers: &[(&str, &str)],
  fingerprint: &str,
) -> (Response<ProxyBody>, informational::H3Receiver) {
  send_with_content_length(state, method, path, data, headers, fingerprint, true).await
}

async fn send_with_content_length(
  state: Arc<AppSnapshot>,
  method: &str,
  path: &str,
  data: &'static [u8],
  headers: &[(&str, &str)],
  fingerprint: &str,
  content_length: bool,
) -> (Response<ProxyBody>, informational::H3Receiver) {
  send_body(
    state,
    method,
    path,
    body::known_small_no_trailers_body(bytes::Bytes::from_static(data)),
    headers,
    fingerprint,
    content_length.then_some(data.len()),
  )
  .await
}

async fn send_body(
  state: Arc<AppSnapshot>,
  method: &str,
  path: &str,
  body: ProxyBody,
  headers: &[(&str, &str)],
  fingerprint: &str,
  content_length: Option<usize>,
) -> (Response<ProxyBody>, informational::H3Receiver) {
  let mut builder = Request::builder()
    .method(method)
    .uri(path)
    .header("host", "example.com");
  if let Some(content_length) = content_length {
    builder = builder.header("content-length", content_length);
  }
  for (name, value) in headers {
    builder = builder.header(*name, *value);
  }
  let mut request = builder.body(body).unwrap();
  let receiver = informational::install_h3(request.extensions_mut());
  let tls = WafTlsMetadata {
    enabled: true,
    version: Some("TLSv1_3".to_owned()),
    sni: Some("example.com".to_owned()),
    client_certificate: Some(WafClientCertificateMetadata {
      fingerprint_sha256: fingerprint.to_owned(),
      ..Default::default()
    }),
    ..Default::default()
  };
  let response = handle_inner(
    request,
    "203.0.113.10:49152".parse().unwrap(),
    None,
    WafTransportMetadataInput::default(),
    Arc::new(tls),
    None,
    None,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    true,
    "https",
    test_drain(),
  )
  .await;
  (response, receiver)
}

async fn create(state: Arc<AppSnapshot>, data: &'static [u8]) -> String {
  let (result, mut receiver) = send(
    state,
    "POST",
    "/submit",
    data,
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("content-type", "text/plain"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(result.status(), StatusCode::CREATED);
  let location = result.headers()["location"].to_str().unwrap().to_owned();
  let first = receiver.recv().await.unwrap();
  assert_eq!(first.status().as_u16(), 104);
  assert_eq!(first.headers()["upload-offset"], "0");
  assert_eq!(first.headers()["location"], location);
  assert!(!first.headers().contains_key("content-length"));
  http::Uri::try_from(location).unwrap().path().to_owned()
}

#[tokio::test]
async fn managed_create_resume_object_and_owner_isolation() {
  let (state, _temp) = snapshot("").await;
  let path = create(state.clone(), b"hello").await;
  let (wrong_owner, _) = send(state.clone(), "HEAD", &path, b"", &[], "owner-b").await;
  assert_eq!(wrong_owner.status(), StatusCode::NOT_FOUND);
  let (head, _) = send(state.clone(), "HEAD", &path, b"", &[], "owner-a").await;
  assert_eq!(head.status(), StatusCode::NO_CONTENT);
  assert_eq!(head.headers()["upload-offset"], "5");
  let (complete, _) = send(
    state.clone(),
    "PATCH",
    &path,
    b" world",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("upload-offset", "5"),
      ("content-type", "application/partial-upload"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(complete.status(), StatusCode::CREATED);
  assert_eq!(complete.headers()["upload-complete"], "?1");
  let object = complete.headers()["location"]
    .to_str()
    .unwrap()
    .parse::<http::Uri>()
    .unwrap();
  let (get, _) = send(state.clone(), "GET", object.path(), b"", &[], "owner-a").await;
  assert_eq!(get.status(), StatusCode::OK);
  assert_eq!(get.headers()["content-disposition"], "attachment");
  assert_eq!(get.headers()["x-content-type-options"], "nosniff");
  assert_eq!(
    get.into_body().collect().await.unwrap().to_bytes(),
    "hello world"
  );
  let (deleted, _) = send(state.clone(), "DELETE", object.path(), b"", &[], "owner-a").await;
  assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
  let (missing, _) = send(state, "GET", object.path(), b"", &[], "owner-a").await;
  assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn managed_unknown_length_parts_commit_the_inspected_size() {
  let (state, _temp) = snapshot("").await;
  let (created, _) = send_with_content_length(
    state.clone(),
    "POST",
    "/submit",
    b"hello",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("content-type", "text/plain"),
    ],
    "owner-a",
    false,
  )
  .await;
  assert_eq!(created.status(), StatusCode::CREATED);
  assert_eq!(created.headers()["upload-offset"], "5");
  let path = created.headers()["location"]
    .to_str()
    .unwrap()
    .parse::<http::Uri>()
    .unwrap();

  let (appended, _) = send_with_content_length(
    state.clone(),
    "PATCH",
    path.path(),
    b" world",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("upload-offset", "5"),
      ("content-type", "application/partial-upload"),
    ],
    "owner-a",
    false,
  )
  .await;
  assert_eq!(appended.status(), StatusCode::NO_CONTENT);
  assert_eq!(appended.headers()["upload-offset"], "11");
  let (head, _) = send(state, "HEAD", path.path(), b"", &[], "owner-a").await;
  assert_eq!(head.headers()["upload-offset"], "11");
}

#[tokio::test]
async fn managed_unknown_length_empty_part_releases_its_reservation() {
  let (state, _temp) = snapshot("").await;
  let (sender, empty_unknown_length) = body::channel_body(1);
  drop(sender);
  let (created, _) = send_body(
    state.clone(),
    "POST",
    "/submit",
    empty_unknown_length,
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("content-type", "text/plain"),
    ],
    "owner-a",
    None,
  )
  .await;
  assert_eq!(created.status(), StatusCode::CREATED);
  assert_eq!(created.headers()["upload-offset"], "0");
  let path = created.headers()["location"]
    .to_str()
    .unwrap()
    .parse::<http::Uri>()
    .unwrap();
  let (appended, _) = send(
    state,
    "PATCH",
    path.path(),
    b"data",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("upload-offset", "0"),
      ("content-type", "application/partial-upload"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(appended.status(), StatusCode::NO_CONTENT);
  assert_eq!(appended.headers()["upload-offset"], "4");
}

#[tokio::test]
async fn managed_binding_is_stable_across_equivalent_snapshots() {
  let (state, _temp) = snapshot("").await;
  let path = create(state.clone(), b"hello").await;
  let config = state.config.clone();
  drop(state);
  let reopened = Arc::new(AppSnapshot::new(config).await.unwrap());
  let (head, _) = send(reopened, "HEAD", &path, b"", &[], "owner-a").await;
  assert_eq!(head.status(), StatusCode::NO_CONTENT);
  assert_eq!(head.headers()["upload-offset"], "5");
}

#[tokio::test]
async fn managed_upstream_final_error_is_complete_and_never_replayed() {
  let origin = origin(StatusCode::INTERNAL_SERVER_ERROR).await;
  let (state, _temp) = snapshot_with_destination(
    "",
    "{ kind = \"upstream\", upstream = \"app\" }",
    Some(origin.address),
  )
  .await;
  let (result, mut receiver) = send(
    state.clone(),
    "POST",
    "/submit",
    b"hello",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("content-type", "text/plain"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(result.headers()["upload-complete"], "?1");
  assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
  let path = receiver.recv().await.unwrap().headers()["location"]
    .to_str()
    .unwrap()
    .parse::<http::Uri>()
    .unwrap()
    .path()
    .to_owned();
  let (status, _) = send(state, "GET", &format!("{path}/status"), b"", &[], "owner-a").await;
  assert_eq!(status.status(), StatusCode::OK);
  assert!(
    status
      .into_body()
      .collect()
      .await
      .unwrap()
      .to_bytes()
      .windows(b"\"state\":\"complete\"".len())
      .any(|window| window == b"\"state\":\"complete\"")
  );
}

#[tokio::test]
async fn managed_pre_origin_failure_is_indeterminate_and_never_replayed() {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  drop(listener);
  let (state, _temp) = snapshot_with_destination(
    "",
    "{ kind = \"upstream\", upstream = \"app\" }",
    Some(address),
  )
  .await;
  let (result, mut receiver) = send(
    state.clone(),
    "POST",
    "/submit",
    b"hello",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("content-type", "text/plain"),
    ],
    "owner-a",
  )
  .await;
  assert!(result.status().is_server_error());
  assert_eq!(result.headers()["upload-complete"], "?0");
  let path = receiver.recv().await.unwrap().headers()["location"]
    .to_str()
    .unwrap()
    .parse::<http::Uri>()
    .unwrap()
    .path()
    .to_owned();
  let (status, _) = send(state, "GET", &format!("{path}/status"), b"", &[], "owner-a").await;
  assert_eq!(status.status(), StatusCode::OK);
  assert!(
    status
      .into_body()
      .collect()
      .await
      .unwrap()
      .to_bytes()
      .windows(b"\"state\":\"indeterminate\"".len())
      .any(|window| window == b"\"state\":\"indeterminate\"")
  );
}

#[tokio::test]
async fn managed_whole_upload_waf_detects_cross_part_content() {
  let (state, _temp) = snapshot(
    r#"
[waf]
enabled = true
[[waf.rules]]
name = "deny-secret"
priority = 1
phase = "request"
when = "Request.Body.Text.contains('secret')"
[[waf.rules.actions]]
type = "reject"
status = 403
"#,
  )
  .await;
  let path = create(state.clone(), b"sec").await;
  let (denied, _) = send(
    state.clone(),
    "PATCH",
    &path,
    b"ret",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("upload-offset", "3"),
      ("content-type", "application/partial-upload"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(denied.status(), StatusCode::FORBIDDEN);
  let (head, _) = send(state, "HEAD", &path, b"", &[], "owner-a").await;
  assert_eq!(head.headers()["upload-offset"], "6");
  assert_eq!(head.headers()["upload-complete"], "?0");
}

#[tokio::test]
async fn managed_encoded_body_and_inspection_overflow_fail_closed() {
  let (state, _temp) = snapshot("").await;
  let (encoded, _) = send(
    state,
    "POST",
    "/submit",
    b"encoded",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("content-encoding", "gzip"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(encoded.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
  let (state, _temp) = snapshot(
    r#"
[waf]
enabled = true
[[waf.rules]]
name = "inspect-body"
priority = 1
phase = "request"
when = "Request.Body.Text.contains('blocked')"
[[waf.rules.actions]]
type = "reject"
status = 403
"#,
  )
  .await;
  let path = create(state.clone(), b"0123456789").await;
  let (large, _) = send(
    state,
    "PATCH",
    &path,
    b"abcdefghij",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("upload-offset", "10"),
      ("content-type", "application/partial-upload"),
    ],
    "owner-a",
  )
  .await;
  assert_eq!(large.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn managed_dictionary_ready_retry_uses_published_decoded_object() {
  managed_dictionary_completion(
    true,
    crate::compression_dictionary::codec::DictionaryCoding::Dcz,
  )
  .await;
}

#[tokio::test]
async fn managed_dictionary_fresh_completion_publishes_decoded_object() {
  use crate::compression_dictionary::codec::DictionaryCoding;
  for coding in [DictionaryCoding::Dcb, DictionaryCoding::Dcz] {
    managed_dictionary_completion(false, coding).await;
  }
}

async fn managed_dictionary_completion(
  ready_retry: bool,
  coding: crate::compression_dictionary::codec::DictionaryCoding,
) {
  use crate::compression_dictionary::fields::DictionaryHash;
  use sha2::{Digest, Sha256};
  let origin = origin(StatusCode::OK).await;
  let (initial, temp) = snapshot_with_destination(
    "",
    if ready_retry {
      "{ kind = \"upstream\", upstream = \"app\" }"
    } else {
      "{ kind = \"object\" }"
    },
    Some(origin.address),
  )
  .await;
  let mut config = initial.config.clone();
  drop(initial);
  let dictionary = b"public dictionary";
  let dictionary_path = temp.path().join("dictionary");
  std::fs::write(&dictionary_path, dictionary).unwrap();
  let digest: String = Sha256::digest(dictionary)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
  config.compression_dictionary = toml::from_str(&format!(
    r#"
enabled = true
[[dictionaries]]
name = "public"
path = "dictionary"
sha256 = "{digest}"
public = true
url = "https://example.com/dictionary"
[[stores]]
name = "memory"
kind = "memory"
quota_bytes = 1024
[[profiles]]
name = "decode"
request_decode = true
dictionaries = ["public"]
store = "memory"
max_dictionary_bytes = 128
max_dictionaries = 4
max_total_dictionary_bytes = 1024
max_pending_dictionary_bytes = 128
max_codec_concurrency = 1
max_codec_memory_bytes = 536870912
max_decoded_size_bytes = 128
max_expansion_ratio = 10
codec_timeout_ms = 1000
"#
  ))
  .unwrap();
  config.upload_profiles[0].max_upload_bytes = 64;
  config.upload_profiles[0].max_part_bytes = 64;
  config.upload_profiles[0].compression_dictionary =
    Some(crate::config::ManagedUploadDictionaryConfig {
      profile: "decode".into(),
      dictionary: "public".into(),
    });
  config.validate().unwrap();
  // As after the ordinary config loader has resolved the validated path.
  config.compression_dictionary.dictionaries[0].path = dictionary_path;
  let state = Arc::new(AppSnapshot::new(config).await.unwrap());
  let plain: &[u8] = if ready_retry { b"plain" } else { &[b'a'; 96] };
  let mut encoded = Vec::new();
  if ready_retry {
    encoded.extend_from_slice(b"wire");
  } else {
    crate::compression_dictionary::codec::encode(coding, dictionary, plain, &mut encoded).unwrap();
  }
  let coding_name = match coding {
    crate::compression_dictionary::codec::DictionaryCoding::Dcb => "dcb",
    crate::compression_dictionary::codec::DictionaryCoding::Dcz => "dcz",
  };
  let encoded_length = encoded.len().to_string();
  let (created, _) = send_body(
    state.clone(),
    "POST",
    "/submit",
    body::known_small_no_trailers_body(bytes::Bytes::copy_from_slice(&encoded)),
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?0"),
      ("content-encoding", coding_name),
      ("upload-length", &encoded_length),
    ],
    "owner-a",
    Some(encoded.len()),
  )
  .await;
  assert_eq!(created.status(), StatusCode::CREATED);
  let path = created.headers()["location"]
    .to_str()
    .unwrap()
    .parse::<http::Uri>()
    .unwrap()
    .path()
    .to_owned();
  let id = path.rsplit('/').next().unwrap();
  let journal: serde_json::Value = serde_json::from_slice(
    &std::fs::read(temp.path().join("store/journal/upload-state-v2.json")).unwrap(),
  )
  .unwrap();
  let persisted = &journal["uploads"][id];
  let owner: crate::uploads::UploadOwner =
    serde_json::from_value(persisted["owner"].clone()).unwrap();
  let binding = persisted["binding"].clone();
  let pin = state
    .uploads
    .profile("media")
    .unwrap()
    .store()
    .request_metadata(id, &owner, &binding)
    .await
    .unwrap()
    .dictionary
    .unwrap();
  assert_eq!(
    pin.hash,
    DictionaryHash::from_slice(&Sha256::digest(dictionary)).unwrap()
  );
  let store = state.uploads.profile("media").unwrap().store();
  if ready_retry {
    store.claim_complete(id, &owner, &binding, 4).await.unwrap();
    let plain_digest: String = Sha256::digest(b"plain")
      .iter()
      .map(|byte| format!("{byte:02x}"))
      .collect();
    let published = store
      .publish_decoded_object(
        id,
        &owner,
        &binding,
        5,
        &plain_digest,
        Box::pin(futures_util::stream::once(async {
          Ok(bytes::Bytes::from_static(b"plain"))
        })),
      )
      .await
      .unwrap();
    assert_eq!(published.state, crate::uploads::UploadState::Ready);
    // The encoded fragments deliberately are not a valid dcz stream. A retry
    // must use the already inspected decoded object instead of decoding again.
  }
  let (completed, _) = send(
    state.clone(),
    "PATCH",
    &path,
    b"",
    &[
      ("upload-draft-interop-version", "9"),
      ("upload-complete", "?1"),
      ("upload-offset", &encoded_length),
      ("content-type", "application/partial-upload"),
      ("content-encoding", coding_name),
    ],
    "owner-a",
  )
  .await;
  if ready_retry {
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
  } else {
    assert_eq!(completed.status(), StatusCode::CREATED);
    assert_eq!(completed.headers()["upload-offset"], encoded_length);
    let object = completed.headers()["location"]
      .to_str()
      .unwrap()
      .parse::<http::Uri>()
      .unwrap();
    let (head, _) = send(state.clone(), "HEAD", object.path(), b"", &[], "owner-a").await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()["content-length"], plain.len().to_string());
    assert!(
      head
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .is_empty()
    );
    let (get, _) = send(state.clone(), "GET", object.path(), b"", &[], "owner-a").await;
    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get.headers()["content-length"], plain.len().to_string());
    assert_eq!(
      get.into_body().collect().await.unwrap().to_bytes().as_ref(),
      plain
    );
    assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
  }
  assert_eq!(
    store.lookup(id, &owner, &binding).await.unwrap().state,
    crate::uploads::UploadState::Complete
  );
}
