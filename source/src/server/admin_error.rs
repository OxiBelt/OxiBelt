//! Admin error envelope construction.
//! Error responses keep machine-readable codes separate from sensitive internal detail.

use ::http::{Response, StatusCode};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::admin_audit::AdminAuditHandle;
use crate::proxy::http::body::{BoxError, KnownSmallResponseBody, ProxyBody};

const ADMIN_API_VERSION: &str = "v1";
const REQUEST_ID_HEADER: &str = "x-oxibelt-request-id";
const API_VERSION_HEADER: &str = "x-oxibelt-api-version";

#[derive(Debug, Serialize)]
struct AdminError<'a> {
  code: &'static str,
  message: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  details: Option<Value>,
}

#[derive(Debug, Serialize)]
struct AdminErrorEnvelope<'a> {
  error: AdminError<'a>,
  request_id: &'a str,
}

pub(super) async fn finalize_response(
  response: Response<ProxyBody>,
  audit: &AdminAuditHandle,
) -> Response<ProxyBody> {
  let request_id = audit.request_id();
  if response.status().is_success() || response.status() == StatusCode::SWITCHING_PROTOCOLS {
    return with_admin_headers(response, &request_id);
  }

  let status = response.status();
  let mutation_headers = [
    crate::admin_mutation::MUTATION_REQUEST_ID_HEADER,
    crate::admin_mutation::MUTATION_REVISION_HEADER,
    crate::admin_mutation::IDEMPOTENT_REPLAY_HEADER,
  ]
  .into_iter()
  .filter_map(|name| {
    response
      .headers()
      .get(name)
      .cloned()
      .map(|value| (name, value))
  })
  .collect::<Vec<_>>();
  let (code, message, body_details) = error_body(response.into_body(), status).await;
  let details = merge_details(body_details, audit.error_details(status));
  let mut response =
    error_envelope_response_with_code(status, code, &message, &request_id, details);
  for (name, value) in mutation_headers {
    response.headers_mut().insert(name, value);
  }
  response
}

pub(super) fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
  error_response_with_details(status, message, None)
}

pub(super) fn error_response_with_details(
  status: StatusCode,
  message: &str,
  details: Option<Value>,
) -> Response<ProxyBody> {
  let mut body = Map::new();
  body.insert("error".to_string(), Value::String(message.to_string()));
  if let Some(details) = details {
    body.insert("details".to_string(), details);
  }
  json_response(status, &Value::Object(body))
}

pub(super) fn error_envelope_response(
  status: StatusCode,
  message: &str,
  request_id: &str,
  details: Option<Value>,
) -> Response<ProxyBody> {
  error_envelope_response_with_code(
    status,
    code_for_status(status),
    message,
    request_id,
    details,
  )
}

fn error_envelope_response_with_code(
  status: StatusCode,
  code: &'static str,
  message: &str,
  request_id: &str,
  details: Option<Value>,
) -> Response<ProxyBody> {
  let response = json_response(
    status,
    &AdminErrorEnvelope {
      error: AdminError {
        code,
        message,
        details,
      },
      request_id,
    },
  );
  with_admin_headers(response, request_id)
}

fn with_admin_headers(mut response: Response<ProxyBody>, request_id: &str) -> Response<ProxyBody> {
  if let Ok(value) = ::http::HeaderValue::from_str(request_id) {
    response
      .headers_mut()
      .insert(::http::HeaderName::from_static(REQUEST_ID_HEADER), value);
  }
  response.headers_mut().insert(
    ::http::HeaderName::from_static(API_VERSION_HEADER),
    ::http::HeaderValue::from_static(ADMIN_API_VERSION),
  );
  response
}

async fn error_body(body: ProxyBody, status: StatusCode) -> (&'static str, String, Option<Value>) {
  let Ok(collected) = body.collect().await else {
    return (
      code_for_status(status),
      default_message(status).to_string(),
      None,
    );
  };
  parse_error_body(status, &collected.to_bytes())
}

fn parse_error_body(status: StatusCode, bytes: &Bytes) -> (&'static str, String, Option<Value>) {
  if bytes.is_empty() {
    return (
      code_for_status(status),
      default_message(status).to_string(),
      None,
    );
  }
  if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
    let code = json_error_code(&value)
      .and_then(allowlisted_error_code)
      .unwrap_or_else(|| code_for_status(status));
    let message = json_error_message(&value)
      .or_else(|| value.get("message").and_then(Value::as_str))
      .unwrap_or_else(|| default_message(status))
      .to_string();
    return (code, message, json_error_details(&value));
  }
  let message = std::str::from_utf8(bytes)
    .map(str::trim)
    .ok()
    .filter(|value| !value.is_empty())
    .unwrap_or_else(|| default_message(status))
    .to_string();
  (code_for_status(status), message, None)
}

fn json_error_code(value: &Value) -> Option<&str> {
  value.get("code").and_then(Value::as_str).or_else(|| {
    value
      .get("error")
      .and_then(Value::as_object)
      .and_then(|error| error.get("code"))
      .and_then(Value::as_str)
  })
}

fn allowlisted_error_code(candidate: &str) -> Option<&'static str> {
  super::ADMIN_ERROR_CODE_VALUES
    .iter()
    .copied()
    .find(|allowed| *allowed == candidate)
}

fn json_error_message(value: &Value) -> Option<&str> {
  match value.get("error") {
    Some(Value::String(message)) => Some(message),
    Some(Value::Object(error)) => error.get("message").and_then(Value::as_str),
    _ => None,
  }
}

fn json_error_details(value: &Value) -> Option<Value> {
  value
    .get("error")
    .and_then(Value::as_object)
    .and_then(|error| error.get("details"))
    .cloned()
    .or_else(|| value.get("details").cloned())
}

fn merge_details(primary: Option<Value>, secondary: Option<Value>) -> Option<Value> {
  match (primary, secondary) {
    (Some(Value::Object(mut primary)), Some(Value::Object(secondary))) => {
      for (key, value) in secondary {
        primary.entry(key).or_insert(value);
      }
      Some(Value::Object(primary))
    }
    (Some(primary), _) => Some(primary),
    (None, secondary) => secondary,
  }
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<ProxyBody> {
  match serde_json::to_vec(value) {
    Ok(bytes) => {
      let body_len = bytes.len();
      let body = Full::new(Bytes::from(bytes))
        .map_err(|never| -> BoxError { match never {} })
        .boxed();
      let mut response = Response::new(body);
      *response.status_mut() = status;
      response.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        ::http::HeaderValue::from_static("application/json"),
      );
      if body_len <= crate::proxy::http::body::KNOWN_SMALL_BODY_MAX_BYTES {
        response.extensions_mut().insert(KnownSmallResponseBody);
      }
      response
    }
    Err(_) => {
      let body = Full::new(Bytes::from_static(
        br#"{"error":{"code":"internal_error","message":"failed to encode JSON response"},"request_id":"unknown"}"#,
      ))
      .map_err(|never| -> BoxError { match never {} })
      .boxed();
      let mut response = Response::new(body);
      *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
      response.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        ::http::HeaderValue::from_static("application/json"),
      );
      response
    }
  }
}

pub(super) fn code_for_status(status: StatusCode) -> &'static str {
  match status {
    StatusCode::BAD_REQUEST => "invalid_request",
    StatusCode::UNAUTHORIZED => "unauthorized",
    StatusCode::FORBIDDEN => "permission_denied",
    StatusCode::NOT_FOUND => "not_found",
    StatusCode::METHOD_NOT_ALLOWED => "method_not_allowed",
    StatusCode::CONFLICT => "conflict",
    StatusCode::PRECONDITION_FAILED => "etag_mismatch",
    StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
    StatusCode::PRECONDITION_REQUIRED => "precondition_required",
    StatusCode::SERVICE_UNAVAILABLE => "control_plane_unavailable",
    StatusCode::INTERNAL_SERVER_ERROR => "internal_error",
    _ if status.is_server_error() => "internal_error",
    _ => "invalid_request",
  }
}

fn default_message(status: StatusCode) -> &'static str {
  match status {
    StatusCode::BAD_REQUEST => "bad request",
    StatusCode::UNAUTHORIZED => "unauthorized",
    StatusCode::FORBIDDEN => "forbidden",
    StatusCode::NOT_FOUND => "not found",
    StatusCode::METHOD_NOT_ALLOWED => "method not allowed",
    StatusCode::CONFLICT => "conflict",
    StatusCode::PRECONDITION_FAILED => "precondition failed",
    StatusCode::PAYLOAD_TOO_LARGE => "request body is too large",
    StatusCode::PRECONDITION_REQUIRED => "precondition required",
    StatusCode::SERVICE_UNAVAILABLE => "control plane unavailable",
    StatusCode::INTERNAL_SERVER_ERROR => "internal server error",
    _ if status.is_server_error() => "server error",
    _ => "request failed",
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ::http::Method;
  use serde_json::json;

  #[test]
  fn status_codes_map_to_admin_error_codes() {
    assert_eq!(code_for_status(StatusCode::BAD_REQUEST), "invalid_request");
    assert_eq!(code_for_status(StatusCode::FORBIDDEN), "permission_denied");
    assert_eq!(
      code_for_status(StatusCode::PRECONDITION_FAILED),
      "etag_mismatch"
    );
    assert_eq!(
      code_for_status(StatusCode::SERVICE_UNAVAILABLE),
      "control_plane_unavailable"
    );
  }

  #[test]
  fn secret_activation_codes_are_all_allowlisted() {
    for code in crate::secret_activation::SECRET_ACTIVATION_ERROR_CODE_VALUES {
      assert_eq!(
        allowlisted_error_code(code),
        Some(*code),
        "secret activation code {code} must remain a bounded Admin error code"
      );
    }
  }

  #[tokio::test]
  async fn envelope_omits_empty_details_and_sets_headers() {
    let response = error_envelope_response(StatusCode::NOT_FOUND, "not found", "req-1", None);
    assert_eq!(response.headers()[REQUEST_ID_HEADER], "req-1");
    assert_eq!(response.headers()[API_VERSION_HEADER], "v1");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert!(body["error"].get("details").is_none());
  }

  #[tokio::test]
  async fn finalize_wraps_plain_text_with_request_id_and_details() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::GET,
      "/admin/v1/config/status",
      None,
    );
    audit.record_authorization("config:GetStatus", "oxibelt:oxibelt:config:*", false);
    let response = error_response(StatusCode::FORBIDDEN, "forbidden");
    let response = finalize_response(response, &audit).await;
    let request_id = audit.request_id();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()[REQUEST_ID_HEADER], request_id);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "permission_denied");
    assert_eq!(body["error"]["message"], "forbidden");
    assert_eq!(body["error"]["details"]["action"], "config:GetStatus");
    assert_eq!(
      body["error"]["details"]["resource"],
      "oxibelt:oxibelt:config:*"
    );
    assert_eq!(body["request_id"], request_id);
  }

  #[tokio::test]
  async fn finalize_preserves_safe_error_details() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::POST,
      "/admin/v1/config/load",
      None,
    );
    let response = error_response_with_details(
      StatusCode::PRECONDITION_REQUIRED,
      "If-Match is required",
      Some(json!({ "header": "If-Match", "expected": "\"oxibelt-config-1\"" })),
    );
    let response = finalize_response(response, &audit).await;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["error"]["code"], "precondition_required");
    assert_eq!(body["error"]["details"]["header"], "If-Match");
    assert_eq!(body["error"]["details"]["expected"], "\"oxibelt-config-1\"");
  }

  #[tokio::test]
  async fn finalize_preserves_only_allowlisted_handler_codes() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::POST,
      "/admin/v1/config/secret-references/update",
      None,
    );
    let allowed = json_response(
      StatusCode::CONFLICT,
      &json!({
        "error": "secret reference activation is controlled by immutable rollout",
        "code": "immutable_rollout_conflict",
      }),
    );
    let allowed = finalize_response(allowed, &audit).await;
    let body = allowed.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "immutable_rollout_conflict");

    let nested = json_response(
      StatusCode::CONFLICT,
      &json!({
        "error": {
          "code": "secret_activation_snapshot_conflict",
          "message": "secret reference activation failed",
        },
      }),
    );
    let nested = finalize_response(nested, &audit).await;
    let body = nested.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "secret_activation_snapshot_conflict");

    let unknown = json_response(
      StatusCode::CONFLICT,
      &json!({
        "error": "secret reference activation failed",
        "code": "attacker_selected_error_code",
      }),
    );
    let unknown = finalize_response(unknown, &audit).await;
    let body = unknown.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "conflict");

    let nested_unknown = json_response(
      StatusCode::CONFLICT,
      &json!({
        "error": {
          "code": "attacker_selected_nested_error_code",
          "message": "secret reference activation failed",
        },
      }),
    );
    let nested_unknown = finalize_response(nested_unknown, &audit).await;
    let body = nested_unknown
      .into_body()
      .collect()
      .await
      .unwrap()
      .to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "conflict");
  }

  #[tokio::test]
  async fn finalize_preserves_structured_config_reports_in_error_details() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::POST,
      "/admin/v1/config/validate",
      None,
    );
    let response = json_response(
      StatusCode::BAD_REQUEST,
      &crate::server::admin_config_introspection::validation_failure(
        "configuration validation failed",
      ),
    );
    let response = finalize_response(response, &audit).await;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(
      body["error"]["details"]["config_report"]["report_schema_version"],
      crate::config::NATIVE_CONFIG_REPORT_SCHEMA_VERSION
    );
    assert_eq!(body["error"]["details"]["config_report"]["ok"], false);
  }

  #[tokio::test]
  async fn finalize_preserves_only_switching_protocols_informational() {
    let audit = AdminAuditHandle::new(
      "127.0.0.1:12345".parse().expect("peer address"),
      "http",
      &Method::GET,
      "/admin/v1/config/status",
      None,
    );
    let response = error_response(StatusCode::CONTINUE, "continue");
    let response = finalize_response(response, &audit).await;
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["message"], "continue");
    assert_eq!(body["request_id"], audit.request_id());

    let switching = error_response(StatusCode::SWITCHING_PROTOCOLS, "switching protocols");
    let switching = finalize_response(switching, &audit).await;
    assert_eq!(switching.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(switching.headers()[REQUEST_ID_HEADER], audit.request_id());
    let body = switching.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert!(body.get("request_id").is_none());
  }
}
