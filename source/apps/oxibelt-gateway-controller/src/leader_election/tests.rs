use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use oxibelt_control_http::ControlHttpClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use super::*;

static TOKEN_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn config() -> LeaderElectionConfig {
  LeaderElectionConfig {
    namespace: "controllers".to_string(),
    lease_name: "oxibelt".to_string(),
    lease_duration: Duration::from_secs(15),
    renew_deadline: Duration::from_secs(10),
    retry_period: Duration::from_secs(1),
  }
}

#[test]
fn a_replaced_or_expired_term_invalidates_late_writes() {
  let leadership = Leadership::new(config());
  leadership.confirm(LeadershipTerm {
    lease_uid: "lease-a".to_string(),
    leader_epoch: 4,
    holder_identity: "pod-a".to_string(),
  });
  let old = leadership.write_permit().expect("current permit");
  leadership.confirm(LeadershipTerm {
    lease_uid: "lease-a".to_string(),
    leader_epoch: 5,
    holder_identity: "pod-b".to_string(),
  });
  assert!(leadership.validate(&old).is_err());
  leadership.revoke();
  assert!(leadership.write_permit().is_err());
}

#[test]
fn lease_patch_tests_uid_resource_version_and_previous_holder() {
  let lease = json!({
    "metadata": {"uid":"lease-uid", "resourceVersion":"7"},
    "spec": {"holderIdentity":"pod-a", "leaseTransitions":2, "acquireTime":"2026-01-01T00:00:00Z"}
  });
  let patch = build_lease_patch(&lease, "pod-a", &config(), 2, false).expect("renewal patch");
  assert_eq!(patch[0]["path"], "/metadata/resourceVersion");
  assert_eq!(patch[1]["path"], "/metadata/uid");
  assert_eq!(patch[2]["path"], "/spec/holderIdentity");
  assert_eq!(patch[3]["value"]["leaseTransitions"], 2);
}

#[tokio::test]
async fn leader_acquisition_and_renewal_keep_one_epoch() {
  let acquired = json!({
    "apiVersion":"coordination.k8s.io/v1",
    "kind":"Lease",
    "metadata":{"name":"oxibelt", "namespace":"controllers", "uid":"lease-uid", "resourceVersion":"2"},
    "spec":{"holderIdentity":"pod-a", "leaseDurationSeconds":15, "leaseTransitions":1}
  });
  let renewed = json!({
    "apiVersion":"coordination.k8s.io/v1",
    "kind":"Lease",
    "metadata":{"name":"oxibelt", "namespace":"controllers", "uid":"lease-uid", "resourceVersion":"3"},
    "spec":{"holderIdentity":"pod-a", "leaseDurationSeconds":15, "leaseTransitions":1}
  });
  let responses = vec![
    (
      "200 OK",
      json!({
        "apiVersion":"coordination.k8s.io/v1",
        "kind":"Lease",
        "metadata":{"name":"oxibelt", "namespace":"controllers", "uid":"lease-uid", "resourceVersion":"1"}
      }),
    ),
    ("200 OK", acquired.clone()),
    ("200 OK", acquired),
    ("200 OK", renewed),
  ];
  let (base_url, server) = spawn_json_server(responses).await;
  let token = TokenFile::new();
  let poller = test_poller(base_url, token.path.clone());
  let leadership = Leadership::new(config());
  let mut observed = None;

  assert!(
    election_step(&poller, &config(), "pod-a", &leadership, &mut observed)
      .await
      .expect("initial acquisition")
  );
  assert_eq!(
    leadership.write_permit().expect("leader permit").term,
    LeadershipTerm {
      lease_uid: "lease-uid".to_string(),
      leader_epoch: 1,
      holder_identity: "pod-a".to_string(),
    }
  );
  assert!(
    election_step(&poller, &config(), "pod-a", &leadership, &mut observed)
      .await
      .expect("renewal")
  );
  assert_eq!(
    leadership
      .write_permit()
      .expect("renewed permit")
      .term
      .leader_epoch,
    1
  );
  server.await.expect("mock Lease API should finish");
}

#[tokio::test]
async fn api_timeout_and_gone_watch_both_reconnect_from_a_fresh_get() {
  let (gone_url, gone_server) = spawn_raw_server("410 Gone", b"", Duration::ZERO).await;
  let gone_token = TokenFile::new();
  let gone_poller = test_poller(gone_url, gone_token.path.clone());
  watch_lease_once(&gone_poller, &config())
    .await
    .expect("HTTP 410 should request a fresh GET");
  gone_server.await.expect("410 mock should finish");

  let (timeout_url, timeout_server) = spawn_raw_server("200 OK", b"", Duration::from_secs(3)).await;
  let timeout_token = TokenFile::new();
  let timeout_poller = test_poller(timeout_url, timeout_token.path.clone());
  let error = watch_lease_once(&timeout_poller, &config())
    .await
    .expect_err("a stalled watch must time out and reconnect");
  assert!(format!("{error:#}").contains("watch timed out"));
  timeout_server.await.expect("timeout mock should finish");
}

fn test_poller(base_url: Url, token_path: PathBuf) -> KubernetesPoller {
  KubernetesPoller {
    client: ControlHttpClient::new(&[]).expect("test HTTP client"),
    base_url,
    service_account_token_path: token_path,
    namespace: Some("controllers".to_string()),
    leadership: None,
  }
}

async fn spawn_json_server(
  responses: Vec<(&'static str, Value)>,
) -> (Url, tokio::task::JoinHandle<()>) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("mock Lease API should bind");
  let address = listener.local_addr().expect("mock Lease API address");
  let handle = tokio::spawn(async move {
    for (status, value) in responses {
      let (mut stream, _) = listener.accept().await.expect("mock API should accept");
      read_request(&mut stream).await;
      write_response(
        &mut stream,
        status,
        &serde_json::to_vec(&value).expect("JSON"),
        false,
      )
      .await;
    }
  });
  (
    Url::parse(&format!("http://{address}")).expect("mock URL"),
    handle,
  )
}

async fn spawn_raw_server(
  status: &'static str,
  body: &'static [u8],
  hold_open: Duration,
) -> (Url, tokio::task::JoinHandle<()>) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("mock watch API should bind");
  let address = listener.local_addr().expect("mock watch API address");
  let handle = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("mock API should accept");
    read_request(&mut stream).await;
    write_response(&mut stream, status, body, !hold_open.is_zero()).await;
    if !hold_open.is_zero() {
      tokio::time::sleep(hold_open).await;
    }
  });
  (
    Url::parse(&format!("http://{address}")).expect("mock URL"),
    handle,
  )
}

async fn read_request(stream: &mut TcpStream) {
  let mut received = Vec::new();
  let mut buffer = [0_u8; 4096];
  loop {
    let read = stream.read(&mut buffer).await.expect("mock request read");
    if read == 0 {
      return;
    }
    received.extend_from_slice(&buffer[..read]);
    let Some(headers_end) = received.windows(4).position(|part| part == b"\r\n\r\n") else {
      continue;
    };
    let headers_end = headers_end + 4;
    let headers = String::from_utf8_lossy(&received[..headers_end]);
    let content_length = headers
      .lines()
      .find_map(|line| {
        line
          .to_ascii_lowercase()
          .strip_prefix("content-length: ")
          .map(str::to_owned)
      })
      .and_then(|length| length.trim().parse::<usize>().ok())
      .unwrap_or_default();
    if received.len() >= headers_end + content_length {
      return;
    }
  }
}

async fn write_response(stream: &mut TcpStream, status: &str, body: &[u8], keep_open: bool) {
  let framing = if keep_open {
    "connection: close\r\n".to_string()
  } else {
    format!("content-length: {}\r\nconnection: close\r\n", body.len())
  };
  let headers = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\n{framing}\r\n");
  stream
    .write_all(headers.as_bytes())
    .await
    .expect("mock response headers");
  stream.write_all(body).await.expect("mock response body");
  stream.flush().await.expect("mock response flush");
}

struct TokenFile {
  path: PathBuf,
}

impl TokenFile {
  fn new() -> Self {
    let sequence = TOKEN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
      "oxibelt-gateway-controller-token-{}-{sequence}",
      std::process::id()
    ));
    std::fs::write(&path, "test-token\n").expect("test token should be written");
    Self { path }
  }
}

impl Drop for TokenFile {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.path);
  }
}
