use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use http::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::*;

#[test]
fn namespace_snapshot_path_respects_a_scoped_watch_namespace() {
  assert_eq!(
    namespace_snapshot_path(Some("edge")),
    "/api/v1/namespaces/edge"
  );
  assert_eq!(namespace_snapshot_path(None), "/api/v1/namespaces");
}

#[test]
fn watch_namespace_must_be_a_kubernetes_dns_label() {
  assert!(validate_watch_namespace(None).is_ok());
  assert!(validate_watch_namespace(Some("edge-a")).is_ok());
  assert!(validate_watch_namespace(Some("outside/../namespace")).is_err());
  assert!(
    validate_watch_namespace(Some(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ))
    .is_err()
  );
}

#[test]
fn parse_list_accepts_typed_kubernetes_list_envelopes() {
  let gateway_classes = parse_list(Bytes::from_static(
    br#"{
      "apiVersion": "gateway.networking.k8s.io/v1",
      "kind": "GatewayClassList",
      "metadata": {"resourceVersion": "1"},
      "items": [{
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayClass",
        "metadata": {"name": "oxibelt"}
      }]
    }"#,
  ))
  .expect("GatewayClassList should parse");
  assert_eq!(gateway_classes.len(), 1);
  assert_eq!(gateway_classes[0].kind, "GatewayClass");
  assert_eq!(gateway_classes[0].name(), "oxibelt");

  let namespaces = parse_list(Bytes::from_static(
    br#"{
      "apiVersion": "v1",
      "kind": "NamespaceList",
      "metadata": {"resourceVersion": "2"},
      "items": [{
        "metadata": {"name": "default"},
        "spec": {"finalizers": ["kubernetes"]},
        "status": {"phase": "Active"}
      }]
    }"#,
  ))
  .expect("NamespaceList should supply omitted item TypeMeta");
  assert_eq!(namespaces.len(), 1);
  assert_eq!(namespaces[0].api_version, "v1");
  assert_eq!(namespaces[0].kind, "Namespace");
  assert_eq!(namespaces[0].name(), "default");

  let services = parse_list(Bytes::from_static(
    br#"{
      "apiVersion": "v1",
      "kind": "ServiceList",
      "metadata": {"resourceVersion": "3"},
      "items": [{
        "metadata": {"name": "backend", "namespace": "default"},
        "spec": {"ports": [{"port": 8080}]}
      }]
    }"#,
  ))
  .expect("ServiceList should supply omitted item TypeMeta");
  assert_eq!(services.len(), 1);
  assert_eq!(services[0].api_version, "v1");
  assert_eq!(services[0].kind, "Service");
  assert_eq!(services[0].name(), "backend");

  let generic = parse_list(Bytes::from_static(
    br#"{
      "apiVersion": "v1",
      "kind": "List",
      "items": [{
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "base-config"}
      }]
    }"#,
  ))
  .expect("generic List should parse");
  assert_eq!(generic.len(), 1);
  assert_eq!(generic[0].kind, "ConfigMap");
}

#[test]
fn parse_list_rejects_conflicting_typed_item_metadata() {
  assert!(
    parse_list(Bytes::from_static(
      br#"{
        "apiVersion": "v1",
        "kind": "ServiceList",
        "items": [{
          "apiVersion": "apps/v1",
          "kind": "Service",
          "metadata": {"name": "backend"}
        }]
      }"#,
    ))
    .is_err()
  );
  assert!(
    parse_list(Bytes::from_static(
      br#"{
        "apiVersion": "v1",
        "kind": "ServiceList",
        "items": [{
          "apiVersion": "v1",
          "kind": "Namespace",
          "metadata": {"name": "backend"}
        }]
      }"#,
    ))
    .is_err()
  );
}

#[test]
fn parse_list_rejects_malformed_list_envelopes() {
  assert!(
    parse_list(Bytes::from_static(
      br#"{"apiVersion":"v1","kind":"List","metadata":{}}"#
    ))
    .is_err()
  );
  assert!(
    parse_list(Bytes::from_static(
      br#"{"apiVersion":"v1","kind":"ServiceList","metadata":{},"items":{}}"#
    ))
    .is_err()
  );
  assert!(
    parse_list(Bytes::from_static(
      br#"{"kind":"ServiceList","metadata":{},"items":[]}"#
    ))
    .is_err()
  );
  assert!(
    parse_list(Bytes::from_static(
      br#"{"apiVersion":"v1","kind":"List","items":[{"metadata":{"name":"missing-type-meta"}}]}"#
    ))
    .is_err()
  );
}

#[test]
fn parse_list_keeps_named_custom_kind_ending_in_list_as_an_object() {
  let objects = parse_list(Bytes::from_static(
    br#"{
      "apiVersion": "example.test/v1",
      "kind": "AllowList",
      "metadata": {"name": "edge"}
    }"#,
  ))
  .expect("named custom resource should parse");
  assert_eq!(objects.len(), 1);
  assert_eq!(objects[0].kind, "AllowList");
  assert_eq!(objects[0].name(), "edge");
}

#[tokio::test]
async fn oversized_backend_tls_config_map_is_policy_local() {
  let api =
    TestKubernetesApi::spawn("attacker-ca", ConfigMapResponse::Oversized(StatusCode::OK)).await;
  let token = TestToken::new();
  let objects = test_poller(&api, &token)
    .snapshot()
    .await
    .expect("oversized referenced ConfigMap must not fail the whole snapshot");

  assert!(objects.iter().all(|object| object.kind != "ConfigMap"));
  assert!(
    api
      .paths()
      .contains(&"/api/v1/namespaces/default/configmaps/attacker-ca".to_string())
  );

  let rendered = translate::translate_objects(&objects, &shared_args()).expect("translate");
  assert!(
    rendered
      .diagnostics
      .iter()
      .any(|diagnostic| diagnostic.message.contains("referenced ConfigMap")),
    "expected a policy-local ConfigMap diagnostic: {:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("safe.example.test"));
  assert!(!rendered.toml.contains("attacked.example.test"));
  assert!(rendered.assets.is_empty());
}

#[tokio::test]
async fn oversized_backend_tls_config_map_not_found_is_policy_local() {
  let api = TestKubernetesApi::spawn(
    "attacker-ca",
    ConfigMapResponse::Oversized(StatusCode::NOT_FOUND),
  )
  .await;
  let token = TestToken::new();
  let objects = test_poller(&api, &token)
    .snapshot()
    .await
    .expect("oversized ConfigMap 404 must retain missing-reference semantics");

  assert!(objects.iter().all(|object| object.kind != "ConfigMap"));
}

#[tokio::test]
async fn invalid_backend_tls_config_map_name_is_policy_local_without_an_api_get() {
  let api = TestKubernetesApi::spawn("../attacker-ca", ConfigMapResponse::Valid).await;
  let token = TestToken::new();
  let objects = test_poller(&api, &token)
    .snapshot()
    .await
    .expect("invalid ConfigMap reference must not fail the whole snapshot");

  assert!(
    api
      .paths()
      .iter()
      .all(|path| !path.contains("/configmaps/")),
    "invalid path segments must never reach the Kubernetes API"
  );
  let rendered = translate::translate_objects(&objects, &shared_args()).expect("translate");
  assert!(
    rendered
      .diagnostics
      .iter()
      .any(|diagnostic| diagnostic.message.contains("referenced ConfigMap"))
  );
  assert!(rendered.toml.contains("safe.example.test"));
  assert!(!rendered.toml.contains("attacked.example.test"));
}

#[tokio::test]
async fn bounded_backend_tls_config_map_still_generates_exclusive_trust() {
  let api = TestKubernetesApi::spawn("attacker-ca", ConfigMapResponse::Valid).await;
  let token = TestToken::new();
  let objects = test_poller(&api, &token)
    .snapshot()
    .await
    .expect("bounded referenced ConfigMap should remain available");

  assert!(objects.iter().any(|object| object.kind == "ConfigMap"));
  let rendered = translate::translate_objects(&objects, &shared_args()).expect("translate");
  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("safe.example.test"));
  assert!(rendered.toml.contains("attacked.example.test"));
  assert!(rendered.toml.contains("trust = \"exclusive\""));
  assert_eq!(rendered.assets.len(), 1);
}

#[tokio::test]
async fn oversized_backend_tls_config_map_server_error_remains_global() {
  let api = TestKubernetesApi::spawn(
    "attacker-ca",
    ConfigMapResponse::Oversized(StatusCode::INTERNAL_SERVER_ERROR),
  )
  .await;
  let token = TestToken::new();
  let error = test_poller(&api, &token)
    .snapshot()
    .await
    .expect_err("oversized Kubernetes API 500 must fail the snapshot");
  let limit_error = error
    .downcast_ref::<ControlHttpResponseBodyLimitError>()
    .expect("global failure should preserve the typed body-limit error");

  assert_eq!(limit_error.status(), StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(
    limit_error.max_body_bytes(),
    REFERENCED_CONFIG_MAP_MAX_BODY_BYTES
  );
}

#[derive(Clone, Copy)]
enum ConfigMapResponse {
  Valid,
  Oversized(StatusCode),
}

struct TestKubernetesApi {
  base_url: Url,
  paths: Arc<Mutex<Vec<String>>>,
  task: JoinHandle<()>,
}

impl TestKubernetesApi {
  async fn spawn(ca_name: &str, config_map_response: ConfigMapResponse) -> Self {
    let listener = TcpListener::bind(("127.0.0.1", 0))
      .await
      .expect("fake Kubernetes API should bind");
    let address = listener.local_addr().expect("fake API address");
    let base_url =
      Url::parse(&format!("http://{address}")).expect("fake Kubernetes API URL should parse");
    let paths = Arc::new(Mutex::new(Vec::new()));
    let recorded_paths = Arc::clone(&paths);
    let ca_name = ca_name.to_string();
    let task = tokio::spawn(async move {
      loop {
        let Ok((mut stream, _)) = listener.accept().await else {
          return;
        };
        let Some(path) = read_request_path(&mut stream).await else {
          continue;
        };
        recorded_paths
          .lock()
          .expect("request path lock should not be poisoned")
          .push(path.clone());
        let response = kubernetes_response(&path, &ca_name, config_map_response);
        let reason = response.status.canonical_reason().unwrap_or("Unknown");
        let headers = format!(
          "HTTP/1.1 {} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
          response.status.as_u16(),
          response.body.len()
        );
        if stream.write_all(headers.as_bytes()).await.is_ok() {
          let _ = stream.write_all(&response.body).await;
        }
      }
    });
    Self {
      base_url,
      paths,
      task,
    }
  }

  fn paths(&self) -> Vec<String> {
    self
      .paths
      .lock()
      .expect("request path lock should not be poisoned")
      .clone()
  }
}

impl Drop for TestKubernetesApi {
  fn drop(&mut self) {
    self.task.abort();
  }
}

struct ApiResponse {
  status: StatusCode,
  body: Vec<u8>,
}

fn kubernetes_response(
  path: &str,
  ca_name: &str,
  config_map_response: ConfigMapResponse,
) -> ApiResponse {
  let config_map_path = format!("/api/v1/namespaces/default/configmaps/{ca_name}");
  if path == config_map_path {
    return match config_map_response {
      ConfigMapResponse::Valid => json_response(
        StatusCode::OK,
        json!({
          "apiVersion": "v1",
          "kind": "ConfigMap",
          "metadata": {"name": ca_name, "namespace": "default"},
          "data": {
            "ca.crt": "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n"
          }
        }),
      ),
      ConfigMapResponse::Oversized(status) => ApiResponse {
        status,
        body: vec![b'x'; REFERENCED_CONFIG_MAP_MAX_BODY_BYTES + 1],
      },
    };
  }

  let items = match path {
    "/apis/gateway.networking.k8s.io/v1/gatewayclasses" => vec![json!({
      "apiVersion": "gateway.networking.k8s.io/v1",
      "kind": "GatewayClass",
      "metadata": {"name": "oxibelt"},
      "spec": {"controllerName": "oxibelt.dev/gateway-controller"}
    })],
    "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways" => vec![json!({
      "apiVersion": "gateway.networking.k8s.io/v1",
      "kind": "Gateway",
      "metadata": {"name": "edge", "namespace": "default"},
      "spec": {
        "gatewayClassName": "oxibelt",
        "listeners": [{"name": "http", "protocol": "HTTP", "port": 80}]
      }
    })],
    "/apis/gateway.networking.k8s.io/v1/namespaces/default/httproutes" => vec![
      route("attacked", "attacked.example.test", "attacker-backend"),
      route("safe", "safe.example.test", "safe-backend"),
    ],
    "/apis/gateway.networking.k8s.io/v1/namespaces/default/backendtlspolicies" => {
      vec![json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "BackendTLSPolicy",
        "metadata": {"name": "attacker-tls", "namespace": "default"},
        "spec": {
          "targetRefs": [{"group": "", "kind": "Service", "name": "attacker-backend"}],
          "validation": {
            "hostname": "backend.example.test",
            "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": ca_name}]
          }
        }
      })]
    }
    "/api/v1/namespaces/default" => vec![json!({
      "apiVersion": "v1",
      "kind": "Namespace",
      "metadata": {"name": "default"}
    })],
    "/api/v1/namespaces/default/services" => {
      vec![service("attacker-backend"), service("safe-backend")]
    }
    _ => Vec::new(),
  };
  json_response(
    StatusCode::OK,
    json!({"apiVersion": "v1", "kind": "List", "items": items}),
  )
}

fn route(name: &str, hostname: &str, service_name: &str) -> Value {
  json!({
    "apiVersion": "gateway.networking.k8s.io/v1",
    "kind": "HTTPRoute",
    "metadata": {"name": name, "namespace": "default"},
    "spec": {
      "parentRefs": [{"name": "edge", "sectionName": "http"}],
      "hostnames": [hostname],
      "rules": [{"backendRefs": [{"name": service_name, "port": 8080}]}]
    }
  })
}

fn service(name: &str) -> Value {
  json!({
    "apiVersion": "v1",
    "kind": "Service",
    "metadata": {"name": name, "namespace": "default"},
    "spec": {"ports": [{"name": "http", "port": 8080}]}
  })
}

fn json_response(status: StatusCode, value: Value) -> ApiResponse {
  ApiResponse {
    status,
    body: serde_json::to_vec(&value).expect("fake Kubernetes response should serialize"),
  }
}

async fn read_request_path(stream: &mut tokio::net::TcpStream) -> Option<String> {
  let mut buffer = [0_u8; 2048];
  let mut received = Vec::new();
  loop {
    let read = stream.read(&mut buffer).await.ok()?;
    if read == 0 {
      return None;
    }
    received.extend_from_slice(&buffer[..read]);
    if received.windows(4).any(|window| window == b"\r\n\r\n") {
      break;
    }
    if received.len() > 16 * 1024 {
      return None;
    }
  }
  let request = std::str::from_utf8(&received).ok()?;
  request
    .lines()
    .next()?
    .split_whitespace()
    .nth(1)
    .map(str::to_string)
}

fn test_poller(api: &TestKubernetesApi, token: &TestToken) -> KubernetesPoller {
  KubernetesPoller {
    client: ControlHttpClient::new(&[]).expect("control HTTP client should build"),
    base_url: api.base_url.clone(),
    service_account_token_path: token.path().to_path_buf(),
    namespace: Some("default".to_string()),
    leadership: None,
  }
}

fn shared_args() -> SharedArgs {
  SharedArgs {
    controller_name: "oxibelt.dev/gateway-controller".to_string(),
    managed_config_path: "conf.d/gateway-api.generated.toml".to_string(),
    watch_namespace: Some("default".to_string()),
    status_address: Vec::new(),
    status_service: None,
    l4_bind_address: std::net::Ipv4Addr::UNSPECIFIED.into(),
    l4_connect_timeout_ms: 3000,
    l4_idle_timeout_ms: 75_000,
    udp_max_flows: 8192,
    udp_new_flow_rate: "200r/s".to_string(),
    udp_new_flow_burst: 400,
    udp_datagram_rate: "200r/s".to_string(),
    udp_datagram_burst: 400,
    udp_batch: super::super::cli::UdpBatchMode::Auto,
    udp_batch_size: 16,
    backend_resolution: super::super::cli::BackendResolution::ClusterDns,
    dry_run: false,
    health_bind: None,
  }
}

struct TestToken(PathBuf);

impl TestToken {
  fn new() -> Self {
    static NEXT_TOKEN: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
      "oxibelt-gateway-controller-watch-{}-{}.token",
      std::process::id(),
      NEXT_TOKEN.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, "test-token\n").expect("test service account token should be written");
    Self(path)
  }

  fn path(&self) -> &Path {
    &self.0
  }
}

impl Drop for TestToken {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.0);
  }
}
