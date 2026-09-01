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
fn rollout_targets_publish_only_clean_or_fail_closed_deprogram_translations() {
  use crate::translate::TranslationDisposition;

  assert!(TranslationDisposition::Clean.is_publishable());
  assert!(TranslationDisposition::FailClosedDeprogram.is_publishable());
  assert!(!TranslationDisposition::PreserveLastGood.is_publishable());
}

#[test]
fn legacy_final_freshness_binds_source_publishability_and_rollout_inputs() {
  let initial = translate::translate_objects(&[], &shared_args()).expect("translate empty input");
  assert!(legacy_rollout_inputs_are_fresh(
    "source-a", &initial, "source-a", &initial,
  ));
  assert!(!legacy_rollout_inputs_are_fresh(
    "source-a", &initial, "source-b", &initial,
  ));

  let mut unpublishable = initial.clone();
  unpublishable.disposition = translate::TranslationDisposition::PreserveLastGood;
  assert!(!legacy_rollout_inputs_are_fresh(
    "source-a",
    &initial,
    "source-a",
    &unpublishable,
  ));

  let mut changed_toml = initial.clone();
  changed_toml.toml.push_str("# changed\n");
  assert!(!legacy_rollout_inputs_are_fresh(
    "source-a",
    &initial,
    "source-a",
    &changed_toml,
  ));

  let mut changed_capability = initial.clone();
  changed_capability.requires_exact_data_plane = !initial.requires_exact_data_plane;
  assert!(!legacy_rollout_inputs_are_fresh(
    "source-a",
    &initial,
    "source-a",
    &changed_capability,
  ));
}

#[test]
fn static_final_freshness_binds_every_rendered_rollout_input() {
  let initial = translate::translate_objects(&[], &shared_args()).expect("translate empty input");
  let initial_inputs = TargetRolloutInputs::from(&initial);
  assert!(initial_inputs == TargetRolloutInputs::from(&initial));

  let mut changed_toml = initial.clone();
  changed_toml.toml.push_str("# changed\n");
  assert!(initial_inputs != TargetRolloutInputs::from(&changed_toml));

  let mut changed_assets = initial.clone();
  changed_assets.assets.push(translate::RenderedAsset {
    data_key: "asset".to_string(),
    managed_path: "gateway-api-ca/asset.pem".to_string(),
    content: "changed".to_string(),
  });
  assert!(initial_inputs != TargetRolloutInputs::from(&changed_assets));

  let mut changed_identities = initial.clone();
  changed_identities
    .client_identities
    .push(upstream_client_tls::ClientIdentityMaterial {
      derived_secret_name: "identity".to_string(),
      source: crate::model::ObjectKey {
        namespace: "default".to_string(),
        name: "source".to_string(),
      },
      source_uid: "uid".to_string(),
      source_resource_version: "1".to_string(),
      certificate_data: "certificate".to_string(),
      private_key_data: "private-key".to_string(),
    });
  assert!(initial_inputs != TargetRolloutInputs::from(&changed_identities));

  let mut changed_capability = initial;
  changed_capability.requires_exact_data_plane = !changed_capability.requires_exact_data_plane;
  assert!(initial_inputs != TargetRolloutInputs::from(&changed_capability));
}

#[tokio::test]
async fn source_secret_watch_is_exact_name_bounded_and_does_not_echo_event_data() {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("watch mock should bind");
  let address = listener.local_addr().expect("watch mock address");
  let base_url = Url::parse(&format!("http://{address}")).expect("watch URL");
  let body = [
    br#"{"type":"MODIFIED","object":{"metadata":{"name":"client.identity","resourceVersion":"18"},"data":{"tls.key":"sensitive-private-key"}}}"#
      .as_slice(),
    b"\n",
  ]
  .concat();
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("watch connection");
    let path = read_request_path(&mut stream)
      .await
      .expect("watch request path");
    let headers = format!(
      "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
      body.len()
    );
    stream
      .write_all(headers.as_bytes())
      .await
      .expect("watch headers");
    stream.write_all(&body).await.expect("watch body");
    path
  });
  let token = TestToken::new();
  let poller = KubernetesPoller {
    client: ControlHttpClient::new(&[]).expect("control client"),
    base_url,
    service_account_token_path: token.path().to_path_buf(),
    namespace: Some("default".to_string()),
    leadership: None,
    upstream_client_tls_source_secrets: Vec::new(),
    controller_name: crate::cli::DEFAULT_CONTROLLER_NAME.to_string(),
  };

  assert_eq!(
    watch_source_secret_once(&poller, "credentials", "client.identity", "17")
      .await
      .expect("material watch event"),
    SourceSecretWatchOutcome::MaterialEvent
  );
  let target = server.await.expect("watch server");
  let url = Url::parse(&format!("http://mock.invalid{target}")).expect("request URL");
  assert_eq!(url.path(), "/api/v1/namespaces/credentials/secrets");
  let query = |name: &str| {
    url
      .query_pairs()
      .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
  };
  assert_eq!(
    query("fieldSelector").as_deref(),
    Some("metadata.name=client.identity")
  );
  assert_eq!(query("watch").as_deref(), Some("true"));
  assert_eq!(query("resourceVersion").as_deref(), Some("17"));

  let error = source_secret_watch_event(
    br#"{"type":"UNSUPPORTED","object":{"data":{"tls.key":"sensitive-private-key"}}}"#,
    "client.identity",
  )
  .expect_err("unsupported event must fail closed");
  assert!(!error.to_string().contains("sensitive-private-key"));
}

#[tokio::test]
async fn source_secret_watch_rejects_an_oversized_event() {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .await
    .expect("watch mock should bind");
  let address = listener.local_addr().expect("watch mock address");
  let base_url = Url::parse(&format!("http://{address}")).expect("watch URL");
  let mut body = vec![b'x'; MAX_SOURCE_SECRET_WATCH_EVENT_BYTES];
  body.push(b'\n');
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await.expect("watch connection");
    let _ = read_request_path(&mut stream)
      .await
      .expect("watch request path");
    let headers = format!(
      "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
      body.len()
    );
    stream
      .write_all(headers.as_bytes())
      .await
      .expect("watch headers");
    stream.write_all(&body).await.expect("watch body");
  });
  let token = TestToken::new();
  let poller = KubernetesPoller {
    client: ControlHttpClient::new(&[]).expect("control client"),
    base_url,
    service_account_token_path: token.path().to_path_buf(),
    namespace: Some("default".to_string()),
    leadership: None,
    upstream_client_tls_source_secrets: Vec::new(),
    controller_name: crate::cli::DEFAULT_CONTROLLER_NAME.to_string(),
  };

  let error = watch_source_secret_once(&poller, "credentials", "client.identity", "17")
    .await
    .expect_err("oversized source Secret watch event must fail closed");
  assert!(error.to_string().contains("exceeded"));
  server.await.expect("watch server");
}

#[test]
fn source_snapshot_digest_binds_semantics_and_ignores_status_or_map_order() {
  let first = KubernetesObject::from_value(json!({
    "apiVersion": "gateway.networking.k8s.io/v1",
    "kind": "HTTPRoute",
    "metadata": {
      "name": "app",
      "namespace": "default",
      "labels": {"tier": "edge"},
      "annotations": {"example.test/policy": "strict"}
    },
    "spec": {"rules": [{"matches": [{"method": "GET"}]}]},
    "status": {"parents": [{"controllerName": "other.example/controller"}]}
  }))
  .expect("first object")
  .pop()
  .expect("first item");
  let reordered = KubernetesObject::from_value(serde_json::from_str(
    r#"{
      "kind":"HTTPRoute",
      "apiVersion":"gateway.networking.k8s.io/v1",
      "metadata":{"annotations":{"example.test/policy":"strict"},"labels":{"tier":"edge"},"namespace":"default","name":"app"},
      "status":{"parents":[]},
      "spec":{"rules":[{"matches":[{"method":"GET"}]}]}
    }"#,
  ).expect("ordered JSON"))
  .expect("reordered object")
  .pop()
  .expect("reordered item");
  assert_eq!(
    source_snapshot_digest(std::slice::from_ref(&first)),
    source_snapshot_digest(std::slice::from_ref(&reordered)),
    "map insertion order and status written by other controllers are not desired-state identity"
  );

  let mut changed = reordered;
  changed.spec["rules"][0]["matches"][0]["method"] = json!("POST");
  assert_ne!(
    source_snapshot_digest(std::slice::from_ref(&first)),
    source_snapshot_digest(std::slice::from_ref(&changed)),
    "offline objects without resourceVersion still bind their semantic spec"
  );

  let mut metadata_only = first.clone();
  metadata_only.metadata.uid = Some("new-uid".to_string());
  metadata_only.metadata.generation = Some(99);
  metadata_only.metadata.resource_version = Some("12345".to_string());
  assert_eq!(
    source_snapshot_digest(std::slice::from_ref(&first)),
    source_snapshot_digest(std::slice::from_ref(&metadata_only)),
    "API bookkeeping must not create a new semantic rollout artifact"
  );

  let secret = |value: &str, resource_version: &str| {
    KubernetesObject::from_value(json!({
      "apiVersion": "v1",
      "kind": "Secret",
      "metadata": {
        "name": "backend-ca",
        "namespace": "default",
        "uid": "source-secret-uid",
        "resourceVersion": resource_version
      },
      "data": {"ca.crt": value}
    }))
    .expect("secret object")
    .pop()
    .expect("secret item")
  };
  let first_secret = secret("YQ==", "10");
  let second_secret = secret("Yg==", "11");
  assert_ne!(
    source_snapshot_digest(std::slice::from_ref(&first_secret)),
    source_snapshot_digest(std::slice::from_ref(&second_secret)),
    "internal rollout identity must bind the source Secret resourceVersion without hashing data"
  );
  let same_version_different_data = secret("Yw==", "10");
  assert_eq!(
    source_snapshot_digest(std::slice::from_ref(&first_secret)),
    source_snapshot_digest(std::slice::from_ref(&same_version_different_data)),
    "rollout identity must not expose a Secret-data equality oracle"
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
async fn required_gateway_api_endpoint_not_found_fails_the_snapshot() {
  let missing = "/apis/gateway.networking.k8s.io/v1/namespaces/default/tlsroutes";
  let api =
    TestKubernetesApi::spawn_with_missing("unused-ca", ConfigMapResponse::Valid, Some(missing))
      .await;
  let token = TestToken::new();
  let error = test_poller(&api, &token)
    .snapshot()
    .await
    .expect_err("a missing required Gateway API endpoint must fail closed");
  let message = format!("{error:#}");

  assert!(message.contains("required Kubernetes API list endpoint"));
  assert!(message.contains(missing));
}

#[tokio::test]
async fn empty_successful_gateway_api_list_remains_a_valid_empty_collection() {
  let api = TestKubernetesApi::spawn("unused-ca", ConfigMapResponse::Valid).await;
  let token = TestToken::new();
  let objects = test_poller(&api, &token)
    .list_objects("/apis/gateway.networking.k8s.io/v1/namespaces/default/tlsroutes")
    .await
    .expect("an empty 200 List response is legitimate");

  assert!(objects.is_empty());
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
  assert!(rendered.toml.contains("attacked.example.test"));
  assert!(rendered.toml.contains("status = 503"));
  assert_eq!(
    rendered.disposition,
    crate::translate::TranslationDisposition::FailClosedDeprogram
  );
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
  assert!(rendered.toml.contains("attacked.example.test"));
  assert!(rendered.toml.contains("status = 503"));
  assert_eq!(
    rendered.disposition,
    crate::translate::TranslationDisposition::FailClosedDeprogram
  );
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
    Self::spawn_with_missing(ca_name, config_map_response, None).await
  }

  async fn spawn_with_missing(
    ca_name: &str,
    config_map_response: ConfigMapResponse,
    missing_path: Option<&str>,
  ) -> Self {
    let listener = TcpListener::bind(("127.0.0.1", 0))
      .await
      .expect("fake Kubernetes API should bind");
    let address = listener.local_addr().expect("fake API address");
    let base_url =
      Url::parse(&format!("http://{address}")).expect("fake Kubernetes API URL should parse");
    let paths = Arc::new(Mutex::new(Vec::new()));
    let recorded_paths = Arc::clone(&paths);
    let ca_name = ca_name.to_string();
    let missing_path = missing_path.map(str::to_string);
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
        let response = kubernetes_response(
          &path,
          &ca_name,
          config_map_response,
          missing_path.as_deref(),
        );
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
  missing_path: Option<&str>,
) -> ApiResponse {
  if missing_path == Some(path) {
    return json_response(
      StatusCode::NOT_FOUND,
      json!({
        "apiVersion": "v1",
        "kind": "Status",
        "status": "Failure",
        "reason": "NotFound",
        "code": 404
      }),
    );
  }
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
    upstream_client_tls_source_secrets: Vec::new(),
    controller_name: crate::cli::DEFAULT_CONTROLLER_NAME.to_string(),
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
    udp_flow_state: super::super::cli::UdpFlowState::Disabled,
    udp_max_flows: 8192,
    udp_new_flow_rate: "200r/s".to_string(),
    udp_new_flow_burst: 400,
    udp_datagram_rate: "200r/s".to_string(),
    udp_datagram_burst: 400,
    udp_batch: super::super::cli::UdpBatchMode::Auto,
    udp_batch_size: 16,
    backend_resolution: super::super::cli::BackendResolution::ClusterDns,
    request_mirror_max_body_bytes: 0,
    external_auth_max_body_bytes: 0,
    external_auth_allowed_content_types: Vec::new(),
    external_auth_allowed_request_headers: Vec::new(),
    external_auth_allowed_identity_headers: Vec::new(),
    external_auth_allowed_terminal_headers: Vec::new(),
    external_auth_allow_credentials: false,
    route_policy_max_request_body_bytes: 10_485_760,
    route_policy_max_timeout_ms: 30_000,
    upstream_client_tls_source_secrets: Vec::new(),
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
