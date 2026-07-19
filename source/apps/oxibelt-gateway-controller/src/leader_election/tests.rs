use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use oxibelt_control_http::ControlHttpClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
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
    "spec": {"holderIdentity":"pod-a", "leaseTransitions":2, "acquireTime":"2026-01-01T00:00:00.000000Z"}
  });
  let patch = build_lease_patch(&lease, "pod-a", &config(), 2, false).expect("renewal patch");
  assert_eq!(patch[0]["path"], "/metadata/resourceVersion");
  assert_eq!(patch[1]["path"], "/metadata/uid");
  assert_eq!(patch[2]["path"], "/spec/holderIdentity");
  assert_eq!(patch[3]["value"]["leaseTransitions"], 2);
  assert_eq!(
    patch[3]["value"]["acquireTime"],
    "2026-01-01T00:00:00.000000Z"
  );
  assert_kubernetes_micro_time(
    patch[3]["value"]["renewTime"]
      .as_str()
      .expect("renewTime should be a string"),
  );

  let acquisition =
    build_lease_patch(&lease, "pod-b", &config(), 3, true).expect("acquisition patch");
  let acquire_time = acquisition[3]["value"]["acquireTime"]
    .as_str()
    .expect("acquireTime should be a string");
  let renew_time = acquisition[3]["value"]["renewTime"]
    .as_str()
    .expect("renewTime should be a string");
  assert_kubernetes_micro_time(acquire_time);
  assert_eq!(acquire_time, renew_time);
}

#[tokio::test]
async fn leader_acquisition_and_renewal_keep_one_epoch() {
  let acquired = json!({
    "apiVersion":"coordination.k8s.io/v1",
    "kind":"Lease",
    "metadata":{"name":"oxibelt", "namespace":"controllers", "uid":"lease-uid", "resourceVersion":"2"},
    "spec":{
      "holderIdentity":"pod-a",
      "leaseDurationSeconds":15,
      "leaseTransitions":1,
      "acquireTime":"2026-01-01T00:00:00.000000Z",
      "renewTime":"2026-01-01T00:00:00.000000Z"
    }
  });
  let renewed = json!({
    "apiVersion":"coordination.k8s.io/v1",
    "kind":"Lease",
    "metadata":{"name":"oxibelt", "namespace":"controllers", "uid":"lease-uid", "resourceVersion":"3"},
    "spec":{
      "holderIdentity":"pod-a",
      "leaseDurationSeconds":15,
      "leaseTransitions":1,
      "acquireTime":"2026-01-01T00:00:00.000000Z",
      "renewTime":"2026-01-01T00:00:01.000000Z"
    }
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
  let requests = server.await.expect("mock Lease API should finish");
  assert_eq!(requests.len(), 4);
  assert_eq!(requests[0].method, "GET");
  assert_eq!(requests[1].method, "PATCH");
  assert_eq!(
    requests[1].content_type.as_deref(),
    Some("application/json-patch+json")
  );
  assert_eq!(requests[2].method, "GET");
  assert_eq!(requests[3].method, "PATCH");

  let acquisition_patch: Value =
    serde_json::from_slice(&requests[1].body).expect("acquisition JSON Patch");
  let acquisition_spec = &acquisition_patch
    .as_array()
    .and_then(|operations| operations.last())
    .expect("acquisition spec operation")["value"];
  let acquire_time = acquisition_spec["acquireTime"]
    .as_str()
    .expect("acquireTime string");
  assert_kubernetes_micro_time(acquire_time);
  assert_eq!(acquisition_spec["renewTime"].as_str(), Some(acquire_time));

  let renewal_patch: Value = serde_json::from_slice(&requests[3].body).expect("renewal JSON Patch");
  let renewal_spec = &renewal_patch
    .as_array()
    .and_then(|operations| operations.last())
    .expect("renewal spec operation")["value"];
  assert_eq!(renewal_spec["acquireTime"], "2026-01-01T00:00:00.000000Z");
  assert_kubernetes_micro_time(
    renewal_spec["renewTime"]
      .as_str()
      .expect("renewTime string"),
  );
}

#[tokio::test]
async fn api_timeout_and_gone_watch_both_reconnect_from_a_fresh_get() {
  let (gone_url, gone_server) = spawn_raw_server("410 Gone", Vec::new(), Duration::ZERO).await;
  let gone_token = TokenFile::new();
  let gone_poller = test_poller(gone_url, gone_token.path.clone());
  watch_lease_once(&gone_poller, &config(), "17")
    .await
    .expect("HTTP 410 should request a fresh GET");
  let gone_request = gone_server.await.expect("410 mock should finish");
  assert_watch_request(&gone_request, "17");

  let (timeout_url, timeout_server) =
    spawn_raw_server("200 OK", Vec::new(), Duration::from_secs(3)).await;
  let timeout_token = TokenFile::new();
  let timeout_poller = test_poller(timeout_url, timeout_token.path.clone());
  let error = watch_lease_once(&timeout_poller, &config(), "18")
    .await
    .expect_err("a stalled watch must time out and reconnect");
  assert!(format!("{error:#}").contains("watch timed out"));
  let timeout_request = timeout_server.await.expect("timeout mock should finish");
  assert_watch_request(&timeout_request, "18");
}

#[tokio::test]
async fn watch_ignores_bookmarks_and_reassembles_material_events() {
  let first = br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"19"}}}
{"type":"MOD"#
    .to_vec();
  let second = br#"IFIED","object":{"metadata":{"resourceVersion":"20"}}}
"#
  .to_vec();
  let (url, server, first_sent, continue_stream) = spawn_scripted_watch_server(first, second).await;
  let token = TokenFile::new();
  let poller = test_poller(url, token.path.clone());
  let watch_config = config();
  let mut watch = tokio::spawn(async move { watch_lease_once(&poller, &watch_config, "18").await });

  first_sent
    .await
    .expect("mock should send the bookmark and partial event");
  assert!(
    tokio::time::timeout(Duration::from_millis(250), &mut watch)
      .await
      .is_err(),
    "a BOOKMARK must not wake the election loop"
  );
  continue_stream
    .send(())
    .expect("mock should accept the material-event signal");
  watch
    .await
    .expect("watch task should finish")
    .expect("a material Lease event should request a fresh GET");

  let request = server.await.expect("scripted watch mock should finish");
  assert_watch_request(&request, "18");
}

#[tokio::test]
async fn malformed_and_oversized_watch_events_fail_closed() {
  let (empty_url, empty_server) = spawn_raw_server("200 OK", Vec::new(), Duration::ZERO).await;
  let empty_token = TokenFile::new();
  let empty_poller = test_poller(empty_url, empty_token.path.clone());
  let error = watch_lease_once(&empty_poller, &config(), "20")
    .await
    .expect_err("an empty successful watch must be paced as an error");
  assert!(format!("{error:#}").contains("before a material event"));
  let empty_request = empty_server.await.expect("empty watch mock should finish");
  assert_watch_request(&empty_request, "20");

  let (malformed_url, malformed_server) =
    spawn_raw_server("200 OK", b"not-json\n".to_vec(), Duration::ZERO).await;
  let malformed_token = TokenFile::new();
  let malformed_poller = test_poller(malformed_url, malformed_token.path.clone());
  let error = watch_lease_once(&malformed_poller, &config(), "21")
    .await
    .expect_err("malformed watch events must fail closed");
  assert!(format!("{error:#}").contains("failed to parse"));
  let malformed_request = malformed_server
    .await
    .expect("malformed watch mock should finish");
  assert_watch_request(&malformed_request, "21");

  let mut oversized = vec![b'x'; MAX_WATCH_EVENT_BYTES];
  oversized.push(b'\n');
  let (oversized_url, oversized_server) =
    spawn_raw_server("200 OK", oversized, Duration::ZERO).await;
  let oversized_token = TokenFile::new();
  let oversized_poller = test_poller(oversized_url, oversized_token.path.clone());
  let error = watch_lease_once(&oversized_poller, &config(), "22")
    .await
    .expect_err("oversized watch events must fail closed");
  assert!(format!("{error:#}").contains("exceeded"));
  let oversized_request = oversized_server
    .await
    .expect("oversized watch mock should finish");
  assert_watch_request(&oversized_request, "22");
}

#[test]
fn watch_error_events_only_refresh_expired_resource_versions() {
  assert!(
    watch_event_requests_refresh(br#"{"type":"ERROR","object":{"code":410}}"#)
      .expect("410 ERROR should request a fresh GET")
  );
  assert!(watch_event_requests_refresh(br#"{"type":"ERROR","object":{"code":500}}"#).is_err());
}

#[tokio::test]
async fn lease_patch_distinguishes_conflicts_from_invalid_payloads() {
  for (status, expected) in [
    ("409 Conflict", "HTTP 409 Conflict"),
    ("422 Unprocessable Entity", "HTTP 422 Unprocessable Entity"),
  ] {
    let (url, server) = spawn_json_server(vec![(status, json!({"kind":"Status"}))]).await;
    let token = TokenFile::new();
    let poller = test_poller(url, token.path.clone());
    let error = patch_lease(&poller, &config(), json!([]))
      .await
      .expect_err("conflict or validation response must fail closed");
    assert!(format!("{error:#}").contains(expected));
    let requests = server.await.expect("PATCH error mock should finish");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "PATCH");
    assert_eq!(
      requests[0].content_type.as_deref(),
      Some("application/json-patch+json")
    );
  }
}

fn assert_kubernetes_micro_time(value: &str) {
  let bytes = value.as_bytes();
  assert_eq!(
    bytes.len(),
    27,
    "MicroTime must have a fixed-width UTC form"
  );
  for (index, byte) in bytes.iter().copied().enumerate() {
    match index {
      4 | 7 => assert_eq!(byte, b'-'),
      10 => assert_eq!(byte, b'T'),
      13 | 16 => assert_eq!(byte, b':'),
      19 => assert_eq!(byte, b'.'),
      26 => assert_eq!(byte, b'Z'),
      _ => assert!(
        byte.is_ascii_digit(),
        "MicroTime field {index} must be a digit"
      ),
    }
  }
}

fn assert_watch_request(request: &CapturedRequest, resource_version: &str) {
  assert_eq!(request.method, "GET");
  let url = if request.target.starts_with("http://") || request.target.starts_with("https://") {
    Url::parse(&request.target).expect("absolute mock request URL")
  } else {
    Url::parse(&format!("http://mock.invalid{}", request.target))
      .expect("origin-form mock request URL")
  };
  assert_eq!(
    url.path(),
    "/apis/coordination.k8s.io/v1/namespaces/controllers/leases"
  );
  let query_value = |name: &str| {
    url
      .query_pairs()
      .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
  };
  assert_eq!(
    query_value("fieldSelector").as_deref(),
    Some("metadata.name=oxibelt")
  );
  assert_eq!(query_value("watch").as_deref(), Some("true"));
  assert_eq!(query_value("allowWatchBookmarks").as_deref(), Some("true"));
  assert_eq!(query_value("timeoutSeconds").as_deref(), Some("1"));
  assert_eq!(
    query_value("resourceVersion").as_deref(),
    Some(resource_version)
  );
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

#[derive(Debug)]
struct CapturedRequest {
  method: String,
  target: String,
  content_type: Option<String>,
  body: Vec<u8>,
}

async fn spawn_json_server(
  responses: Vec<(&'static str, Value)>,
) -> (Url, tokio::task::JoinHandle<Vec<CapturedRequest>>) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("mock Lease API should bind");
  let address = listener.local_addr().expect("mock Lease API address");
  let handle = tokio::spawn(async move {
    let mut requests = Vec::with_capacity(responses.len());
    for (status, value) in responses {
      let (mut stream, _) = listener.accept().await.expect("mock API should accept");
      requests.push(read_request(&mut stream).await);
      write_response(
        &mut stream,
        status,
        &serde_json::to_vec(&value).expect("JSON"),
        false,
      )
      .await;
    }
    requests
  });
  (
    Url::parse(&format!("http://{address}")).expect("mock URL"),
    handle,
  )
}

async fn spawn_raw_server(
  status: &'static str,
  body: Vec<u8>,
  hold_open: Duration,
) -> (Url, tokio::task::JoinHandle<CapturedRequest>) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("mock watch API should bind");
  let address = listener.local_addr().expect("mock watch API address");
  let handle = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("mock API should accept");
    let request = read_request(&mut stream).await;
    write_response(&mut stream, status, &body, !hold_open.is_zero()).await;
    if !hold_open.is_zero() {
      tokio::time::sleep(hold_open).await;
    }
    request
  });
  (
    Url::parse(&format!("http://{address}")).expect("mock URL"),
    handle,
  )
}

async fn spawn_scripted_watch_server(
  first: Vec<u8>,
  second: Vec<u8>,
) -> (
  Url,
  tokio::task::JoinHandle<CapturedRequest>,
  oneshot::Receiver<()>,
  oneshot::Sender<()>,
) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("scripted watch API should bind");
  let address = listener.local_addr().expect("scripted watch API address");
  let (first_sent_tx, first_sent_rx) = oneshot::channel();
  let (continue_tx, continue_rx) = oneshot::channel();
  let handle = tokio::spawn(async move {
    let (mut stream, _) = listener
      .accept()
      .await
      .expect("scripted watch API should accept");
    let request = read_request(&mut stream).await;
    stream
      .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n")
      .await
      .expect("scripted response headers");
    stream
      .write_all(&first)
      .await
      .expect("first watch response fragment");
    stream.flush().await.expect("first watch response flush");
    let _ = first_sent_tx.send(());
    let _ = continue_rx.await;
    stream
      .write_all(&second)
      .await
      .expect("second watch response fragment");
    stream.flush().await.expect("second watch response flush");
    request
  });
  (
    Url::parse(&format!("http://{address}")).expect("mock URL"),
    handle,
    first_sent_rx,
    continue_tx,
  )
}

async fn read_request(stream: &mut TcpStream) -> CapturedRequest {
  let mut received = Vec::new();
  let mut buffer = [0_u8; 4096];
  loop {
    let read = stream.read(&mut buffer).await.expect("mock request read");
    if read == 0 {
      panic!("mock request ended before all headers and body arrived");
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
      let mut lines = headers.lines();
      let mut request_line = lines.next().expect("mock request line").split_whitespace();
      let method = request_line
        .next()
        .expect("mock request method")
        .to_string();
      let target = request_line
        .next()
        .expect("mock request target")
        .to_string();
      let content_type = lines.find_map(|line| {
        line
          .split_once(':')
          .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
          .map(|(_, value)| value.trim().to_string())
      });
      return CapturedRequest {
        method,
        target,
        content_type,
        body: received[headers_end..headers_end + content_length].to_vec(),
      };
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
