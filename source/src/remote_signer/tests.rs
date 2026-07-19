use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;

use super::protocol::{RemoteSignerRequest, RemoteSignerResponse, SignContext};
use super::*;

const TEST_TOKEN: [u8; 32] = [7u8; 32];
const ROTATED_TEST_TOKEN: [u8; 32] = [9u8; 32];

#[test]
fn tls13_server_certificate_verify_detection_is_strict() {
  let mut message = vec![b' '; 64];
  message.extend_from_slice(TLS13_SERVER_CERT_VERIFY_CONTEXT);
  message.extend_from_slice(&[7u8; 32]);
  assert!(is_tls13_server_certificate_verify_message(&message));

  message[0] = b'!';
  assert!(!is_tls13_server_certificate_verify_message(&message));
}

#[test]
fn pooled_client_reuses_socket_for_describe_key_then_sign() {
  let (client, connects) = test_client(1, Duration::from_secs(5));
  let mut request_kinds = Vec::new();

  let describe = client
    .request_with_transport(describe_request(), |_, request| {
      request_kinds.push(request_kind(request).to_string());
      Ok(ok_response())
    })
    .expect("describe_key should complete");
  assert!(matches!(describe, RemoteSignerResponse::Error { .. }));

  let sign = client
    .request_with_transport(sign_request(), |_, request| {
      request_kinds.push(request_kind(request).to_string());
      Ok(ok_response())
    })
    .expect("sign should complete on the pooled socket");
  assert!(matches!(sign, RemoteSignerResponse::Error { .. }));

  assert_eq!(connects.load(Ordering::SeqCst), 1);
  assert_eq!(
    request_kinds,
    vec!["describe_key".to_string(), "sign".to_string()]
  );
}

#[test]
fn pool_max_idle_zero_opens_fresh_socket_per_request() {
  let (client, connects) = test_client(0, Duration::from_secs(5));

  for _ in 0..2 {
    client
      .request_with_transport(describe_request(), |_, _| Ok(ok_response()))
      .expect("describe_key should complete");
  }

  assert_eq!(connects.load(Ordering::SeqCst), 2);
}

#[test]
fn stale_pooled_socket_is_discarded_and_retried_once() {
  let (client, connects) = test_client(1, Duration::from_secs(5));
  let mut attempts = 0usize;

  client
    .request_with_transport(describe_request(), |_, _| {
      attempts += 1;
      Ok(ok_response())
    })
    .expect("first request should complete");
  client
    .request_with_transport(describe_request(), |_, _| {
      attempts += 1;
      if attempts == 2 {
        Err(anyhow::anyhow!("stale pooled socket"))
      } else {
        Ok(ok_response())
      }
    })
    .expect("second request should retry on a fresh socket");

  assert_eq!(attempts, 3);
  assert_eq!(connects.load(Ordering::SeqCst), 2);
}

#[test]
fn pool_discards_sockets_idle_longer_than_sign_timeout() {
  let pool = RemoteSignerConnectionPool::new(1);
  let (stream, _peer) = UnixStream::pair().expect("Unix stream pair should create");
  pool.put(stream);
  std::thread::sleep(Duration::from_millis(5));

  assert!(pool.take(Duration::from_millis(1)).is_none());
}

#[test]
fn socket_mode_allows_private_modes_and_rejects_world_access() {
  validate_socket_mode(0o600).expect("0600 should be accepted");
  validate_socket_mode(0o660).expect("0660 should be accepted");
  let error = validate_socket_mode(0o666).expect_err("world-accessible sockets must be rejected");
  assert!(
    error.to_string().contains("0600 or 0660"),
    "unexpected error: {error}"
  );
}

#[test]
fn peer_uid_or_gid_allowlist_controls_socket_access() {
  assert!(peer_credentials_are_allowed(10001, 10001, &[10001], &[]));
  assert!(peer_credentials_are_allowed(10001, 10002, &[], &[10002]));
  assert!(!peer_credentials_are_allowed(
    10001,
    10001,
    &[10002],
    &[10003]
  ));
}

#[test]
fn token_file_provider_reloads_and_preserves_last_good_token() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    None,
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial token file should load");

  assert_eq!(provider.current_token(), TEST_TOKEN);

  write_token_file(&token_file, &ROTATED_TEST_TOKEN);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(provider.current_token(), ROTATED_TEST_TOKEN);

  std::fs::write(&token_file, b"not-base64").expect("invalid token should write");
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(
    provider.current_token(),
    ROTATED_TEST_TOKEN,
    "invalid rotations should preserve the last good token"
  );
}

#[test]
fn pinned_token_file_is_verified_at_the_consumer_read() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let raw = std::fs::read(&token_file).expect("token fixture should be readable");
  let expected = crate::crypto::sha256(&raw)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
  let provider = RemoteSignerTokenProvider::from_sources_with_reload(
    Some(PathBuf::from("keysigner-token.b64")),
    Some(temp_dir.path().to_path_buf()),
    Some(&expected),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
    false,
  )
  .expect("matching token pin should load");
  assert_eq!(provider.current_token(), TEST_TOKEN);
  assert!(!provider.reloadable());

  let error = RemoteSignerTokenProvider::from_sources_with_reload(
    Some(token_file),
    None,
    Some(&"0".repeat(64)),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
    false,
  )
  .expect_err("mismatched token pin must fail before activation");
  assert!(error.to_string().contains("digest"));
}

#[test]
fn token_file_provider_follows_symlink_retargets_with_base_guard() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  let first_target = temp_dir.path().join("token-a.b64");
  let rotated_target = temp_dir.path().join("token-b.b64");
  write_token_file(&first_target, &TEST_TOKEN);
  write_token_file(&rotated_target, &ROTATED_TEST_TOKEN);
  replace_symlink("token-a.b64", &token_file);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    Some(temp_dir.path().to_path_buf()),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial symlinked token file should load");

  assert_eq!(provider.current_token(), TEST_TOKEN);

  replace_symlink("token-b.b64", &token_file);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(provider.current_token(), ROTATED_TEST_TOKEN);
}

#[test]
fn token_file_provider_preserves_last_good_token_for_unsafe_symlink_retargets() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_dir = temp_dir.path().join("tokens");
  let outside_dir = temp_dir.path().join("outside");
  std::fs::create_dir_all(&token_dir).expect("token dir should create");
  std::fs::create_dir_all(&outside_dir).expect("outside dir should create");
  let token_file = token_dir.join("keysigner-token.b64");
  let first_target = token_dir.join("token-a.b64");
  let invalid_target = token_dir.join("token-invalid.b64");
  let outside_target = outside_dir.join("token-outside.b64");
  write_token_file(&first_target, &TEST_TOKEN);
  std::fs::write(&invalid_target, b"not-base64").expect("invalid token should write");
  write_token_file(&outside_target, &ROTATED_TEST_TOKEN);
  replace_symlink("token-a.b64", &token_file);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    Some(token_dir.clone()),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial symlinked token file should load");

  replace_symlink("token-invalid.b64", &token_file);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(
    provider.current_token(),
    TEST_TOKEN,
    "invalid symlink retargets should preserve the last good token"
  );

  replace_symlink(&outside_target, &token_file);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(
    provider.current_token(),
    TEST_TOKEN,
    "outside-base symlink retargets should preserve the last good token"
  );
}

#[test]
fn client_retries_once_after_token_file_rotation_unauthorized() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let token_provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    None,
    "UNUSED_TOKEN_ENV",
    Duration::from_secs(60),
  )
  .expect("initial token file should load");
  let (client, _connects) =
    test_client_with_token_provider(0, Duration::from_secs(5), token_provider);
  write_token_file(&token_file, &ROTATED_TEST_TOKEN);
  let mut observed_tokens = Vec::new();
  let mut attempts = 0usize;
  let response = client
    .request_authenticated_with_transport(
      |token| RemoteSignerRequest::DescribeKey {
        token: token_to_wire(&token),
        key_id: "edge-default".to_string(),
      },
      |_, request| {
        attempts += 1;
        observed_tokens.push(decode_wire_token(request.token()));
        if attempts == 1 {
          Ok(RemoteSignerResponse::Error {
            code: "unauthorized".to_string(),
            message: "invalid signer token".to_string(),
          })
        } else {
          Ok(ok_response())
        }
      },
    )
    .expect("request should retry with the rotated token");
  assert!(matches!(response, RemoteSignerResponse::Error { code, .. } if code == "ok"));
  assert_eq!(observed_tokens, vec![TEST_TOKEN, ROTATED_TEST_TOKEN]);

  observed_tokens.clear();
  client
    .request_authenticated_with_transport(
      |token| RemoteSignerRequest::DescribeKey {
        token: token_to_wire(&token),
        key_id: "edge-default".to_string(),
      },
      |_, request| {
        observed_tokens.push(decode_wire_token(request.token()));
        Ok(ok_response())
      },
    )
    .expect("second request should use rotated cached token");
  assert_eq!(observed_tokens, vec![ROTATED_TEST_TOKEN]);
}

#[test]
fn token_file_startup_rejects_missing_or_invalid_files() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let missing = temp_dir.path().join("missing.b64");
  let error = RemoteSignerTokenProvider::from_sources(
    Some(missing),
    None,
    "UNUSED",
    Duration::from_millis(1),
  )
  .expect_err("missing token file should fail startup");
  assert!(
    error.to_string().contains("failed to read"),
    "unexpected error: {error}"
  );

  let invalid = temp_dir.path().join("invalid.b64");
  std::fs::write(&invalid, b"short").expect("invalid token should write");
  let error = RemoteSignerTokenProvider::from_sources(
    Some(invalid),
    None,
    "UNUSED",
    Duration::from_millis(1),
  )
  .expect_err("invalid token file should fail startup");
  assert!(
    error.to_string().contains("exactly 32 bytes") || error.to_string().contains("base64"),
    "unexpected error: {error}"
  );
}

#[test]
fn process_request_uses_latest_token_file_value() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    None,
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial token file should load");
  let keys = HashMap::new();

  assert!(matches!(
    process_request(describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));

  write_token_file(&token_file, &ROTATED_TEST_TOKEN);
  std::thread::sleep(Duration::from_millis(2));
  assert!(matches!(
    process_request(describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unauthorized"
  ));
  assert!(matches!(
    process_request(rotated_describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));

  std::fs::write(&token_file, b"not-base64").expect("invalid token should write");
  std::thread::sleep(Duration::from_millis(2));
  assert!(matches!(
    process_request(rotated_describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));
}

fn test_client(max_idle: usize, sign_timeout: Duration) -> (RemoteSignerClient, Arc<AtomicUsize>) {
  test_client_with_token_provider(max_idle, sign_timeout, test_token_provider())
}

fn test_client_with_token_provider(
  max_idle: usize,
  sign_timeout: Duration,
  token_provider: RemoteSignerTokenProvider,
) -> (RemoteSignerClient, Arc<AtomicUsize>) {
  let connects = Arc::new(AtomicUsize::new(0));
  let connect_counter = connects.clone();
  let connect_override: Arc<dyn Fn() -> anyhow::Result<UnixStream> + Send + Sync> =
    Arc::new(move || {
      connect_counter.fetch_add(1, Ordering::SeqCst);
      let (stream, _peer) = UnixStream::pair()
        .map_err(|error| anyhow::anyhow!("mock signer Unix stream pair should create: {error}"))?;
      Ok(stream)
    });
  (
    RemoteSignerClient {
      socket_path: PathBuf::from("/unused/test.sock"),
      token_provider,
      connect_timeout: Duration::from_secs(5),
      sign_timeout,
      pool: Arc::new(RemoteSignerConnectionPool::new(max_idle)),
      connect_override: Some(connect_override),
      allow_tls12_unstructured_signing: false,
    },
    connects,
  )
}

fn test_token_provider() -> RemoteSignerTokenProvider {
  RemoteSignerTokenProvider::from_static_token(decode_wire_token(&test_token()))
}

fn test_token() -> String {
  token_to_wire(&TEST_TOKEN)
}

fn describe_request() -> RemoteSignerRequest {
  RemoteSignerRequest::DescribeKey {
    token: test_token(),
    key_id: "edge-default".to_string(),
  }
}

fn rotated_describe_request() -> RemoteSignerRequest {
  RemoteSignerRequest::DescribeKey {
    token: token_to_wire(&ROTATED_TEST_TOKEN),
    key_id: "edge-default".to_string(),
  }
}

fn sign_request() -> RemoteSignerRequest {
  RemoteSignerRequest::Sign {
    token: test_token(),
    key_id: "edge-default".to_string(),
    scheme: u16::from(SignatureScheme::RSA_PSS_SHA256),
    context: SignContext::Tls12Unstructured,
    message: base64::engine::general_purpose::STANDARD.encode(b"message"),
  }
}

fn ok_response() -> RemoteSignerResponse {
  RemoteSignerResponse::Error {
    code: "ok".to_string(),
    message: "mock response".to_string(),
  }
}

fn write_token_file(path: &std::path::Path, token: &[u8; 32]) {
  std::fs::write(path, token_to_wire(token)).expect("token file should write");
}

fn replace_symlink<P: AsRef<std::path::Path>>(target: P, link: &std::path::Path) {
  let _ = std::fs::remove_file(link);
  std::os::unix::fs::symlink(target, link).expect("token symlink should create");
}

fn decode_wire_token(raw: &str) -> [u8; 32] {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(raw)
    .expect("wire token should decode");
  decoded
    .as_slice()
    .try_into()
    .expect("wire token should be 32 bytes")
}

fn request_kind(request: &RemoteSignerRequest) -> &'static str {
  match request {
    RemoteSignerRequest::DescribeKey { .. } => "describe_key",
    RemoteSignerRequest::Sign { .. } => "sign",
  }
}
