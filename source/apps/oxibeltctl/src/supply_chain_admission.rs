//! Bounded, credential-free Kubernetes admission webhook for signed bundles.

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
      "exact signed supply-chain bundle matches the admitted image",
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
  if !matches!(request.operation.as_str(), "CREATE" | "UPDATE")
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
  let Some(containers) = request
    .object
    .pointer("/spec/containers")
    .and_then(Value::as_array)
  else {
    return Err("containers_missing");
  };
  if containers.len() > 64 {
    return Err("container_limit_exceeded");
  }
  let oxibelt = containers
    .iter()
    .filter(|container| container.get("name").and_then(Value::as_str) == Some("oxibelt"))
    .collect::<Vec<_>>();
  if oxibelt.len() != 1
    || oxibelt[0].get("image").and_then(Value::as_str)
      != Some(state.bundle.payload.artifact.image_reference.as_str())
  {
    return Err("image_digest_mismatch");
  }
  Ok(())
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

  fn request(state: &AdmissionState) -> AdmissionRequest {
    AdmissionRequest {
      uid: "request-1".to_string(),
      operation: "CREATE".to_string(),
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
}
