//! Bounded, credential-free Kubernetes admission webhook for signed bundles.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, ensure};
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::cli::SupplyChainAdmissionServerArgs;
use crate::supply_chain_bundle::{
  AdmissionBundleEnvelope, RevocationSet, bundle_payload_digest, load_bundle, load_public_key,
  load_revocations, now_unix_seconds, verify_bundle,
};
use crate::supply_chain_workload_policy::{
  ContainerClass, validate_container_name, validate_image_reference,
};

const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 128;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct AdmissionState {
  bundle: AdmissionBundleEnvelope,
  public_key: Vec<u8>,
  key_id: String,
  revocations: RevocationSet,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionReviewRequest {
  api_version: String,
  kind: String,
  request: AdmissionRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionRequest {
  uid: String,
  operation: String,
  #[serde(default)]
  sub_resource: String,
  kind: GroupVersionKind,
  resource: GroupVersionResource,
  object: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupVersionKind {
  group: String,
  version: String,
  kind: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupVersionResource {
  group: String,
  version: String,
  resource: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionReviewResponse<'a> {
  api_version: &'static str,
  kind: &'static str,
  response: AdmissionResponse<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionResponse<'a> {
  uid: &'a str,
  allowed: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  status: Option<AdmissionStatus<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionStatus<'a> {
  code: u16,
  reason: &'static str,
  message: &'a str,
}

pub(crate) async fn serve(args: &SupplyChainAdmissionServerArgs) -> anyhow::Result<()> {
  let bundle = load_bundle(&args.bundle)?;
  let public_key = load_public_key(&args.public_key_file)?;
  let (revocations, revocations_sha256) = load_revocations(args.revocations.as_deref())?;
  ensure!(
    bundle.payload.policy.revocations_sha256 == revocations_sha256,
    "admission bundle does not bind the configured revocation policy"
  );
  verify_bundle(
    &bundle,
    &public_key,
    &args.key_id,
    &revocations,
    now_unix_seconds()?,
  )?;
  let tls = load_tls_acceptor(&args.tls_cert, &args.tls_key)?;
  let listener = TcpListener::bind(args.listen)
    .await
    .with_context(|| format!("failed to bind admission server at {}", args.listen))?;
  let state = Arc::new(AdmissionState {
    bundle,
    public_key,
    key_id: args.key_id.clone(),
    revocations,
  });
  let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
  let mut connections = JoinSet::new();
  loop {
    // Completed tasks no longer hold a semaphore permit, so reap them before
    // accepting more work to keep the task set deterministically bounded.
    while connections.try_join_next().is_some() {}
    tokio::select! {
      signal = tokio::signal::ctrl_c() => {
        signal.context("failed to monitor admission shutdown signal")?;
        break;
      }
      accepted = listener.accept() => {
        let (stream, _) = accepted.context("failed to accept admission connection")?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
          drop(stream);
          continue;
        };
        let tls = tls.clone();
        let state = state.clone();
        connections.spawn(async move {
          let _permit = permit;
          let Ok(Ok(stream)) = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(stream)).await else {
            return;
          };
          let service = service_fn(move |request| handle(request, state.clone()));
          let mut builder = hyper::server::conn::http1::Builder::new();
          builder
            .keep_alive(false)
            .header_read_timeout(REQUEST_BODY_TIMEOUT)
            .timer(TokioTimer::new());
          let _ = builder.serve_connection(TokioIo::new(stream), service).await;
        });
      }
      Some(_) = connections.join_next(), if !connections.is_empty() => {}
    }
  }
  connections.abort_all();
  let drain = async { while connections.join_next().await.is_some() {} };
  let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, drain).await;
  Ok(())
}

async fn handle(
  request: Request<Incoming>,
  state: Arc<AdmissionState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
  let response = match (request.method(), request.uri().path()) {
    (&Method::GET, "/livez") => text_response(StatusCode::OK, "ok"),
    (&Method::GET, "/readyz") => match current_bundle(&state) {
      Ok(()) => text_response(StatusCode::OK, "ready"),
      Err(_) => text_response(StatusCode::SERVICE_UNAVAILABLE, "bundle unavailable"),
    },
    (&Method::POST, "/validate") => admission_response(request, &state).await,
    _ => text_response(StatusCode::NOT_FOUND, "not found"),
  };
  Ok(response)
}

async fn admission_response(
  request: Request<Incoming>,
  state: &AdmissionState,
) -> Response<Full<Bytes>> {
  let content_type = request
    .headers()
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .unwrap_or("");
  if !content_type
    .split(';')
    .next()
    .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
  {
    return text_response(
      StatusCode::UNSUPPORTED_MEDIA_TYPE,
      "application/json required",
    );
  }
  let bytes =
    match tokio::time::timeout(REQUEST_BODY_TIMEOUT, collect_bounded(request.into_body())).await {
      Ok(Ok(value)) => value,
      Ok(Err(status)) => return text_response(status, "invalid admission request"),
      Err(_) => return text_response(StatusCode::REQUEST_TIMEOUT, "admission request timed out"),
    };
  let review: AdmissionReviewRequest = match serde_json::from_slice(&bytes) {
    Ok(value) => value,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid admission review"),
  };
  if review.api_version != "admission.k8s.io/v1"
    || review.kind != "AdmissionReview"
    || review.request.uid.is_empty()
    || review.request.uid.len() > 128
  {
    return text_response(StatusCode::BAD_REQUEST, "unsupported admission review");
  }
  let decision = validate_request(&review.request, state);
  let (allowed, message) = match decision {
    Ok(()) => (
      true,
      "exact signed supply-chain bundle matches the admitted workload images",
    ),
    Err(reason) => (false, reason),
  };
  let response = AdmissionReviewResponse {
    api_version: "admission.k8s.io/v1",
    kind: "AdmissionReview",
    response: AdmissionResponse {
      uid: &review.request.uid,
      allowed,
      status: (!allowed).then_some(AdmissionStatus {
        code: 403,
        reason: "SupplyChainAdmissionDenied",
        message,
      }),
    },
  };
  match serde_json::to_vec(&response) {
    Ok(bytes) => json_response(StatusCode::OK, bytes),
    Err(_) => text_response(
      StatusCode::INTERNAL_SERVER_ERROR,
      "admission response failed",
    ),
  }
}

fn validate_request(
  request: &AdmissionRequest,
  state: &AdmissionState,
) -> Result<(), &'static str> {
  if current_bundle(state).is_err() {
    return Err("bundle_invalid_or_expired");
  }
  let supported_operation = matches!(
    (request.operation.as_str(), request.sub_resource.as_str()),
    ("CREATE" | "UPDATE", "") | ("UPDATE", "ephemeralcontainers")
  );
  if !supported_operation
    || !request.kind.group.is_empty()
    || request.kind.version != "v1"
    || request.kind.kind != "Pod"
    || !request.resource.group.is_empty()
    || request.resource.version != "v1"
    || request.resource.resource != "pods"
  {
    return Err("unsupported_admission_resource");
  }
  let annotations = request.object.pointer("/metadata/annotations");
  if annotations
    .and_then(|value| value.get("oxibelt.dev/supply-chain-bundle-digest"))
    .and_then(Value::as_str)
    != Some(bundle_payload_digest(&state.bundle))
  {
    return Err("bundle_digest_mismatch");
  }
  if annotations
    .and_then(|value| value.get("oxibelt.dev/image-role"))
    .and_then(Value::as_str)
    != Some(state.bundle.payload.artifact.role.as_str())
  {
    return Err("image_role_mismatch");
  }
  let executables = collect_executable_containers(&request.object)?;
  if request.operation == "CREATE"
    && executables
      .iter()
      .any(|container| container.class == ContainerClass::Ephemeral)
  {
    return Err("invalid_executable_container_set");
  }
  let oxibelt = executables
    .iter()
    .filter(|container| container.class == ContainerClass::Regular && container.name == "oxibelt")
    .collect::<Vec<_>>();
  if oxibelt.len() != 1 || oxibelt[0].image != state.bundle.payload.artifact.image_reference {
    return Err("image_digest_mismatch");
  }
  let mut names = BTreeSet::new();
  for executable in &executables {
    if !names.insert(executable.name) {
      return Err("invalid_executable_container_set");
    }
  }
  let approvals = state
    .bundle
    .payload
    .workload_policy
    .as_ref()
    .map_or(&[][..], |policy| policy.auxiliary_containers.as_slice());
  for executable in executables
    .iter()
    .filter(|container| container.name != "oxibelt")
  {
    if validate_image_reference(executable.image).is_err()
      || !approvals.iter().any(|approval| {
        approval.class == executable.class
          && approval.name == executable.name
          && approval.image_reference == executable.image
      })
    {
      return Err("unapproved_executable_container");
    }
  }
  Ok(())
}

#[derive(Clone, Copy, Debug)]
struct ExecutableContainer<'a> {
  class: ContainerClass,
  name: &'a str,
  image: &'a str,
}

fn collect_executable_containers(
  object: &Value,
) -> Result<Vec<ExecutableContainer<'_>>, &'static str> {
  let Some(spec) = object.get("spec").and_then(Value::as_object) else {
    return Err("containers_missing");
  };
  let Some(containers) = spec.get("containers").and_then(Value::as_array) else {
    return Err("containers_missing");
  };
  let init_containers = optional_container_array(spec.get("initContainers"))?;
  let ephemeral_containers = optional_container_array(spec.get("ephemeralContainers"))?;
  let total = containers
    .len()
    .saturating_add(init_containers.len())
    .saturating_add(ephemeral_containers.len());
  if total > 64 {
    return Err("container_limit_exceeded");
  }
  let mut executables = Vec::with_capacity(total);
  append_executables(&mut executables, containers, ContainerClass::Regular)?;
  append_init_executables(&mut executables, init_containers)?;
  append_executables(
    &mut executables,
    ephemeral_containers,
    ContainerClass::Ephemeral,
  )?;
  Ok(executables)
}

fn optional_container_array(value: Option<&Value>) -> Result<&[Value], &'static str> {
  match value {
    None | Some(Value::Null) => Ok(&[]),
    Some(Value::Array(containers)) => Ok(containers),
    Some(_) => Err("invalid_executable_container_set"),
  }
}

fn append_executables<'a>(
  output: &mut Vec<ExecutableContainer<'a>>,
  containers: &'a [Value],
  class: ContainerClass,
) -> Result<(), &'static str> {
  for container in containers {
    output.push(parse_executable(container, class)?);
  }
  Ok(())
}

fn append_init_executables<'a>(
  output: &mut Vec<ExecutableContainer<'a>>,
  containers: &'a [Value],
) -> Result<(), &'static str> {
  for container in containers {
    let class = match container.get("restartPolicy") {
      None | Some(Value::Null) => ContainerClass::Init,
      Some(Value::String(value)) if value == "Always" => ContainerClass::NativeSidecar,
      Some(_) => return Err("invalid_executable_container_set"),
    };
    output.push(parse_executable(container, class)?);
  }
  Ok(())
}

fn parse_executable(
  value: &Value,
  class: ContainerClass,
) -> Result<ExecutableContainer<'_>, &'static str> {
  let Some(container) = value.as_object() else {
    return Err("invalid_executable_container_set");
  };
  let Some(name) = container.get("name").and_then(Value::as_str) else {
    return Err("invalid_executable_container_set");
  };
  let Some(image) = container.get("image").and_then(Value::as_str) else {
    return Err("invalid_executable_container_set");
  };
  if validate_container_name(name).is_err() {
    return Err("invalid_executable_container_set");
  }
  Ok(ExecutableContainer { class, name, image })
}

fn current_bundle(state: &AdmissionState) -> anyhow::Result<()> {
  verify_bundle(
    &state.bundle,
    &state.public_key,
    &state.key_id,
    &state.revocations,
    now_unix_seconds()?,
  )
}

async fn collect_bounded(mut body: Incoming) -> Result<Vec<u8>, StatusCode> {
  let mut bytes = Vec::new();
  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
    let Ok(data) = frame.into_data() else {
      continue;
    };
    if bytes.len().saturating_add(data.len()) > MAX_REQUEST_BYTES {
      return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    bytes.extend_from_slice(&data);
  }
  Ok(bytes)
}

fn load_tls_acceptor(
  cert_path: &std::path::Path,
  key_path: &std::path::Path,
) -> anyhow::Result<TlsAcceptor> {
  let cert_bytes = read_tls_file(cert_path, 256 * 1024, "admission TLS certificate")?;
  let certs = CertificateDer::pem_slice_iter(&cert_bytes)
    .collect::<Result<Vec<_>, _>>()
    .context("failed to parse admission TLS certificate")?;
  ensure!(
    !certs.is_empty() && certs.len() <= 16,
    "admission TLS certificate chain must contain 1 to 16 certificates"
  );
  let key_bytes = read_tls_file(key_path, 64 * 1024, "admission TLS key")?;
  let mut keys = PrivateKeyDer::pem_slice_iter(&key_bytes)
    .collect::<Result<Vec<_>, _>>()
    .context("failed to parse admission TLS key")?;
  ensure!(
    keys.len() == 1,
    "admission TLS key must contain exactly one private key"
  );
  let key = keys.pop().context("admission TLS key is missing")?;
  let mut config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("admission TLS certificate and key do not match")?;
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  Ok(TlsAcceptor::from(Arc::new(config)))
}

fn read_tls_file(path: &std::path::Path, limit: u64, label: &str) -> anyhow::Result<Vec<u8>> {
  let metadata = std::fs::metadata(path)
    .with_context(|| format!("failed to inspect {label}: {}", path.display()))?;
  ensure!(metadata.is_file(), "{label} must be a regular file");
  ensure!(
    metadata.len() <= limit,
    "{label} exceeds its {limit}-byte limit"
  );
  std::fs::read(path).with_context(|| format!("failed to read {label}: {}", path.display()))
}

fn text_response(status: StatusCode, value: &'static str) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::from_static(value.as_bytes())));
  *response.status_mut() = status;
  response.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  response
}

fn json_response(status: StatusCode, value: Vec<u8>) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::from(value)));
  *response.status_mut() = status;
  response.headers_mut().insert(
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("application/json"),
  );
  response
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::supply_chain_workload_policy::{
    AdmissionWorkloadPolicy, ContainerApproval, canonicalize_workload_policy,
  };

  fn state() -> AdmissionState {
    let now = now_unix_seconds().expect("clock");
    let (bundle, public_key, revocations) =
      crate::supply_chain_bundle::signed_bundle_for_admission_test(now);
    AdmissionState {
      bundle,
      public_key,
      key_id: "test-key".to_string(),
      revocations,
    }
  }

  fn state_with_approvals(approvals: Vec<ContainerApproval>) -> AdmissionState {
    let now = now_unix_seconds().expect("clock");
    let policy = canonicalize_workload_policy(AdmissionWorkloadPolicy {
      schema_version: 1,
      auxiliary_containers: approvals,
    })
    .expect("test workload policy");
    let (bundle, public_key, revocations) =
      crate::supply_chain_bundle::signed_bundle_for_admission_test_with_policy(now, policy);
    AdmissionState {
      bundle,
      public_key,
      key_id: "test-key".to_string(),
      revocations,
    }
  }

  fn v1_state() -> AdmissionState {
    let now = now_unix_seconds().expect("clock");
    let (bundle, public_key, revocations) =
      crate::supply_chain_bundle::signed_v1_bundle_for_admission_test(now);
    AdmissionState {
      bundle,
      public_key,
      key_id: "test-key".to_string(),
      revocations,
    }
  }

  fn approved_image(name: &str, digest: char) -> String {
    format!(
      "ghcr.io/example/{name}@sha256:{}",
      digest.to_string().repeat(64)
    )
  }

  fn approval(class: ContainerClass, name: &str, digest: char) -> ContainerApproval {
    ContainerApproval {
      class,
      name: name.to_string(),
      image_reference: approved_image(name, digest),
    }
  }

  fn request(state: &AdmissionState) -> AdmissionRequest {
    AdmissionRequest {
      uid: "request-1".to_string(),
      operation: "CREATE".to_string(),
      sub_resource: String::new(),
      kind: GroupVersionKind {
        group: String::new(),
        version: "v1".to_string(),
        kind: "Pod".to_string(),
      },
      resource: GroupVersionResource {
        group: String::new(),
        version: "v1".to_string(),
        resource: "pods".to_string(),
      },
      object: json!({
        "metadata": {"annotations": {
          "oxibelt.dev/supply-chain-bundle-digest": bundle_payload_digest(&state.bundle),
          "oxibelt.dev/image-role": "dataplane-strict"
        }},
        "spec": {"containers": [{
          "name": "oxibelt",
          "image": state.bundle.payload.artifact.image_reference
        }]}
      }),
    }
  }

  #[test]
  fn exact_bundle_digest_role_and_image_are_admitted() {
    let state = state();
    validate_request(&request(&state), &state).expect("admitted");
  }

  #[test]
  fn bundle_image_role_and_container_limits_fail_closed() {
    let state = state();
    let mut cases = Vec::new();
    let mut wrong_bundle = request(&state);
    wrong_bundle.object["metadata"]["annotations"]["oxibelt.dev/supply-chain-bundle-digest"] =
      Value::String(format!("sha256:{}", "f".repeat(64)));
    cases.push((wrong_bundle, "bundle_digest_mismatch"));
    let mut wrong_role = request(&state);
    wrong_role.object["metadata"]["annotations"]["oxibelt.dev/image-role"] =
      Value::String("dataplane".to_string());
    cases.push((wrong_role, "image_role_mismatch"));
    let mut wrong_image = request(&state);
    wrong_image.object["spec"]["containers"][0]["image"] =
      Value::String("ghcr.io/oxibelt/oxibelt-dataplane-strict:latest".to_string());
    cases.push((wrong_image, "image_digest_mismatch"));
    let mut too_many = request(&state);
    too_many.object["spec"]["containers"] = Value::Array(
      (0..65)
        .map(|index| json!({"name": format!("sidecar-{index}"), "image": "example.invalid/x"}))
        .collect(),
    );
    cases.push((too_many, "container_limit_exceeded"));

    for (request, expected) in cases {
      assert_eq!(validate_request(&request, &state), Err(expected));
    }
  }

  #[test]
  fn v1_is_primary_only_and_v2_admits_each_exact_auxiliary_class() {
    let legacy = v1_state();
    validate_request(&request(&legacy), &legacy).expect("v1 primary");
    let mut legacy_sidecar = request(&legacy);
    legacy_sidecar.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .push(json!({"name": "mesh-proxy", "image": approved_image("mesh-proxy", 'a')}));
    assert_eq!(
      validate_request(&legacy_sidecar, &legacy),
      Err("unapproved_executable_container")
    );

    let state = state_with_approvals(vec![
      approval(ContainerClass::Regular, "mesh-proxy", 'a'),
      approval(ContainerClass::Init, "setup", 'b'),
      approval(ContainerClass::NativeSidecar, "log-shipper", 'c'),
      approval(ContainerClass::Ephemeral, "debugger", 'd'),
    ]);
    let mut create = request(&state);
    create.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .push(json!({"name": "mesh-proxy", "image": approved_image("mesh-proxy", 'a')}));
    create.object["spec"]["initContainers"] = json!([
      {"name": "setup", "image": approved_image("setup", 'b')},
      {"name": "log-shipper", "image": approved_image("log-shipper", 'c'), "restartPolicy": "Always"}
    ]);
    create.object["spec"]["ephemeralContainers"] = json!([]);
    validate_request(&create, &state).expect("approved create shape");

    create.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .swap(0, 1);
    create.object["spec"]["initContainers"]
      .as_array_mut()
      .expect("init containers")
      .swap(0, 1);
    validate_request(&create, &state).expect("actual array order is irrelevant");

    let mut update = create;
    update.operation = "UPDATE".to_string();
    update.object["spec"]["ephemeralContainers"] = json!([{
      "name": "debugger",
      "image": approved_image("debugger", 'd')
    }]);
    validate_request(&update, &state).expect("ordinary update final shape");
    update.sub_resource = "ephemeralcontainers".to_string();
    validate_request(&update, &state).expect("ephemeral subresource final shape");

    update.operation = "CREATE".to_string();
    update.sub_resource.clear();
    assert_eq!(
      validate_request(&update, &state),
      Err("invalid_executable_container_set")
    );
  }

  #[test]
  fn unlisted_digest_drift_and_class_confusion_fail_closed() {
    let state = state_with_approvals(vec![
      approval(ContainerClass::Regular, "mesh-proxy", 'a'),
      approval(ContainerClass::Init, "setup", 'b'),
      approval(ContainerClass::NativeSidecar, "log-shipper", 'c'),
      approval(ContainerClass::Ephemeral, "debugger", 'd'),
    ]);
    let mut cases = Vec::new();

    let mut unlisted = request(&state);
    unlisted.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .push(json!({"name": "unlisted", "image": approved_image("unlisted", 'a')}));
    cases.push(unlisted);

    let mut drifted = request(&state);
    drifted.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .push(json!({"name": "mesh-proxy", "image": approved_image("mesh-proxy", 'f')}));
    cases.push(drifted);

    let mut tagged = request(&state);
    tagged.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .push(json!({"name": "mesh-proxy", "image": "ghcr.io/example/mesh-proxy:latest"}));
    cases.push(tagged);

    let mut promoted_init = request(&state);
    promoted_init.object["spec"]["initContainers"] = json!([{
      "name": "setup",
      "image": approved_image("setup", 'b'),
      "restartPolicy": "Always"
    }]);
    cases.push(promoted_init);

    let mut demoted_sidecar = request(&state);
    demoted_sidecar.object["spec"]["initContainers"] = json!([{
      "name": "log-shipper",
      "image": approved_image("log-shipper", 'c')
    }]);
    cases.push(demoted_sidecar);

    let mut wrong_field = request(&state);
    wrong_field.object["spec"]["initContainers"] = json!([{
      "name": "mesh-proxy",
      "image": approved_image("mesh-proxy", 'a')
    }]);
    cases.push(wrong_field);

    let mut ephemeral_drift = request(&state);
    ephemeral_drift.operation = "UPDATE".to_string();
    ephemeral_drift.sub_resource = "ephemeralcontainers".to_string();
    ephemeral_drift.object["spec"]["ephemeralContainers"] = json!([{
      "name": "debugger",
      "image": approved_image("debugger", 'f')
    }]);
    cases.push(ephemeral_drift);

    for request in cases {
      assert_eq!(
        validate_request(&request, &state),
        Err("unapproved_executable_container")
      );
    }
  }

  #[test]
  fn malformed_duplicate_and_mixed_container_limits_fail_closed() {
    let state = state_with_approvals(vec![
      approval(ContainerClass::Regular, "mesh-proxy", 'a'),
      approval(ContainerClass::Init, "setup", 'b'),
    ]);
    let mut malformed = Vec::new();

    let mut wrong_array = request(&state);
    wrong_array.object["spec"]["initContainers"] = json!({});
    malformed.push(wrong_array);

    let mut non_object = request(&state);
    non_object.object["spec"]["initContainers"] = json!(["setup"]);
    malformed.push(non_object);

    let mut missing_name = request(&state);
    missing_name.object["spec"]["initContainers"] =
      json!([{"image": approved_image("setup", 'b')}]);
    malformed.push(missing_name);

    let mut missing_image = request(&state);
    missing_image.object["spec"]["initContainers"] = json!([{"name": "setup"}]);
    malformed.push(missing_image);

    let mut bad_restart = request(&state);
    bad_restart.object["spec"]["initContainers"] = json!([{
      "name": "setup",
      "image": approved_image("setup", 'b'),
      "restartPolicy": "Never"
    }]);
    malformed.push(bad_restart);

    let mut duplicate = request(&state);
    duplicate.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .push(json!({"name": "mesh-proxy", "image": approved_image("mesh-proxy", 'a')}));
    duplicate.object["spec"]["initContainers"] = json!([{
      "name": "mesh-proxy",
      "image": approved_image("mesh-proxy", 'a')
    }]);
    malformed.push(duplicate);

    for request in malformed {
      assert_eq!(
        validate_request(&request, &state),
        Err("invalid_executable_container_set")
      );
    }

    let approvals = (0..63)
      .map(|index| approval(ContainerClass::Regular, &format!("aux-{index}"), 'a'))
      .collect::<Vec<_>>();
    let bounded = state_with_approvals(approvals);
    let mut sixty_four = request(&bounded);
    sixty_four.object["spec"]["containers"]
      .as_array_mut()
      .expect("containers")
      .extend((0..63).map(|index| {
        let name = format!("aux-{index}");
        json!({"name": name, "image": approved_image(&name, 'a')})
      }));
    validate_request(&sixty_four, &bounded).expect("64 total executable containers");
    sixty_four.object["spec"]["ephemeralContainers"] =
      json!([{"name": "overflow", "image": approved_image("overflow", 'a')}]);
    sixty_four.operation = "UPDATE".to_string();
    assert_eq!(
      validate_request(&sixty_four, &bounded),
      Err("container_limit_exceeded")
    );
  }

  #[test]
  fn operation_subresource_and_deserialization_routes_are_exact() {
    let state = state();
    let create = request(&state);
    validate_request(&create, &state).expect("root create");
    let mut update = request(&state);
    update.operation = "UPDATE".to_string();
    validate_request(&update, &state).expect("root update");
    update.sub_resource = "ephemeralcontainers".to_string();
    validate_request(&update, &state).expect("ephemeral update");

    let mut unsupported = Vec::new();
    let mut ephemeral_create = request(&state);
    ephemeral_create.sub_resource = "ephemeralcontainers".to_string();
    unsupported.push(ephemeral_create);
    for subresource in ["status", "resize"] {
      let mut value = request(&state);
      value.operation = "UPDATE".to_string();
      value.sub_resource = subresource.to_string();
      unsupported.push(value);
    }
    let mut delete = request(&state);
    delete.operation = "DELETE".to_string();
    unsupported.push(delete);
    let mut wrong_kind = request(&state);
    wrong_kind.kind.kind = "Service".to_string();
    unsupported.push(wrong_kind);
    let mut wrong_resource = request(&state);
    wrong_resource.resource.resource = "deployments".to_string();
    unsupported.push(wrong_resource);
    let mut wrong_version = request(&state);
    wrong_version.resource.version = "v2".to_string();
    unsupported.push(wrong_version);

    for request in unsupported {
      assert_eq!(
        validate_request(&request, &state),
        Err("unsupported_admission_resource")
      );
    }

    let omitted: AdmissionReviewRequest = serde_json::from_value(json!({
      "apiVersion": "admission.k8s.io/v1",
      "kind": "AdmissionReview",
      "request": {
        "uid": "omitted-subresource",
        "operation": "UPDATE",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "resource": {"group": "", "version": "v1", "resource": "pods"},
        "object": update.object,
        "oldObject": {"spec": {"containers": [{"name": "unlisted", "image": "invalid"}]}}
      }
    }))
    .expect("omitted subresource");
    assert!(omitted.request.sub_resource.is_empty());
    validate_request(&omitted.request, &state).expect("final object only");

    let present: AdmissionReviewRequest = serde_json::from_value(json!({
      "apiVersion": "admission.k8s.io/v1",
      "kind": "AdmissionReview",
      "request": {
        "uid": "ephemeral-subresource",
        "operation": "UPDATE",
        "subResource": "ephemeralcontainers",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "resource": {"group": "", "version": "v1", "resource": "pods"},
        "object": request(&state).object
      }
    }))
    .expect("present subresource");
    assert_eq!(present.request.sub_resource, "ephemeralcontainers");
  }
}
