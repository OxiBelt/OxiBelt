//! Admin metadata endpoint.
//! Metadata is operational context and must not expose request-plane secrets.

use ::http::{Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};

use crate::dynamic_policy::MAX_DYNAMIC_POLICY_BODY_BYTES;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppSnapshot;

use super::admin::{self, ADMIN_JSON_BODY_LIMIT};
use super::admin_auth::AdminAuthorization;
use super::admin_control::ADMIN_CONFIG_BODY_LIMIT;
use super::admin_ops::OXIRULE_REPLAY_BODY_LIMIT;

const ADMIN_API_VERSION: &str = "v1";
const OPENAPI_JSON: &str = include_str!("../../../docs/admin-openapi.json");

pub(super) fn admin_metadata_response(
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  let resource = match path {
    "/admin/v1/openapi.json" => "metadata/openapi",
    "/admin/v1/capabilities" => "metadata/capabilities",
    "/admin/v1/version" => "metadata/version",
    _ => return None,
  };

  if *method != ::http::Method::GET {
    return Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    ));
  }
  if !authorization.is_allowed("admin:ReadMetadata", resource) {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }

  match path {
    "/admin/v1/openapi.json" => Some(static_json_response(StatusCode::OK, OPENAPI_JSON)),
    "/admin/v1/capabilities" => Some(capabilities_response(snapshot)),
    "/admin/v1/version" => Some(version_response()),
    _ => None,
  }
}

fn capabilities_response(snapshot: &AppSnapshot) -> Response<ProxyBody> {
  let features = json!({
    "config_load": true,
    "file_sync": true,
    "dynamic_policy": snapshot.config.dynamic_policy.automation_api.enabled,
    "ipm_store": snapshot.config.ipm.enabled && snapshot.config.ipm_backend_name().is_some(),
    "waf_devtools": true,
    "runtime_introspection": true,
    "cache_admin": true,
    "person_proof_admin": true,
    "upstream_pool_runtime_control": true,
    "stream_pool_runtime_control": true,
    "admin_operations": snapshot.config.admin.operations.enabled,
    "admin_http3": snapshot.config.admin.http3.enabled,
    "admin_operation_webtransport": snapshot.config.admin.operations.webtransport,
    "admin_audit": snapshot.config.admin.audit.enabled,
  });
  debug_assert_capability_feature_keys(&features);
  let workload_identity = &snapshot.config.admin.workload_identity;

  admin::json_response(
    StatusCode::OK,
    &json!({
      "api_version": ADMIN_API_VERSION,
      "package_version": env!("CARGO_PKG_VERSION"),
      "features": features,
      "authentication": {
        "mtls_workload_identity": {
          "enabled": workload_identity.enabled,
          "bearer_mode": match workload_identity.bearer_mode {
            crate::config::AdminWorkloadIdentityBearerMode::Required => "required",
            crate::config::AdminWorkloadIdentityBearerMode::Optional => "optional",
          },
        },
      },
      "limits": {
        "admin_json_body_bytes": ADMIN_JSON_BODY_LIMIT,
        "config_body_bytes": ADMIN_CONFIG_BODY_LIMIT,
        "oxirule_replay_body_bytes": OXIRULE_REPLAY_BODY_LIMIT,
        "dynamic_policy_body_bytes": MAX_DYNAMIC_POLICY_BODY_BYTES,
      },
    }),
  )
}

fn debug_assert_capability_feature_keys(features: &Value) {
  let mut actual = features
    .as_object()
    .expect("Admin capabilities features must be an object")
    .keys()
    .map(String::as_str)
    .collect::<Vec<_>>();
  let mut expected = super::ADMIN_CAPABILITY_FEATURE_KEYS.to_vec();
  actual.sort_unstable();
  expected.sort_unstable();
  debug_assert_eq!(actual, expected);
}

fn version_response() -> Response<ProxyBody> {
  admin::json_response(
    StatusCode::OK,
    &json!({
      "api_version": ADMIN_API_VERSION,
      "package_name": env!("CARGO_PKG_NAME"),
      "package_version": env!("CARGO_PKG_VERSION"),
    }),
  )
}

fn static_json_response(status: StatusCode, value: &'static str) -> Response<ProxyBody> {
  let body = Full::new(Bytes::from_static(value.as_bytes()))
    .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
    .boxed();
  let mut response = Response::new(body);
  *response.status_mut() = status;
  response.headers_mut().insert(
    ::http::header::CONTENT_TYPE,
    ::http::HeaderValue::from_static("application/json"),
  );
  response
}
