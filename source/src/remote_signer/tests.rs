use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;

use super::protocol::{RemoteSignerRequest, RemoteSignerResponse, SignContext};
use super::*;

const TEST_TOKEN: [u8; 32] = [7u8; 32];

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

fn test_client(max_idle: usize, sign_timeout: Duration) -> (RemoteSignerClient, Arc<AtomicUsize>) {
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
      token: TEST_TOKEN,
      connect_timeout: Duration::from_secs(5),
      sign_timeout,
      pool: Arc::new(RemoteSignerConnectionPool::new(max_idle)),
      connect_override: Some(connect_override),
      allow_tls12_unstructured_signing: false,
    },
    connects,
  )
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

fn request_kind(request: &RemoteSignerRequest) -> &'static str {
  match request {
    RemoteSignerRequest::DescribeKey { .. } => "describe_key",
    RemoteSignerRequest::Sign { .. } => "sign",
  }
}
