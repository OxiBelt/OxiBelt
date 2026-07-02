use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use serde_json::{Value, json};

pub(super) struct AdminAuditDescriptor {
  pub service: Option<String>,
  pub operation: String,
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
}

pub(super) fn describe_request(method: &Method, path: &str) -> AdminAuditDescriptor {
  let service = service_for_path(path).map(str::to_string);
  let operation = operation_for_path(method, path);
  let (target_kind, target_id) = target_for_path(path);
  AdminAuditDescriptor {
    service,
    operation,
    target_kind,
    target_id,
  }
}

fn service_for_path(path: &str) -> Option<&'static str> {
  if path.starts_with("/cache/purge") || path.starts_with("/admin/v1/cache/") {
    Some("cache")
  } else if path.starts_with("/admin/v1/config/")
    || path.starts_with("/admin/v1/tls/")
    || path.starts_with("/admin/v1/files/")
  {
    Some("config")
  } else if path.starts_with("/admin/v1/ipm/") {
    Some("ipm")
  } else if path.starts_with("/admin/v1/dynamic-policies") {
    Some("dynamic-policy")
  } else if path.starts_with("/admin/v1/waf/") {
    Some("waf")
  } else if path.starts_with("/admin/v1/lifecycle") {
    Some("lifecycle")
  } else if path.starts_with("/admin/v1/upstream-pools") {
    Some("upstream-pool")
  } else if path.starts_with("/admin/v1/stream-pools") {
    Some("stream-pool")
  } else if path.starts_with("/admin/v1/diagnostics/") {
    Some("diagnostics")
  } else if path.starts_with("/admin/v1/runtime/") {
    Some("runtime")
  } else if matches!(
    path,
    "/admin/v1/openapi.json" | "/admin/v1/capabilities" | "/admin/v1/version" | "/admin/v1/audit"
  ) {
    Some("admin")
  } else {
    None
  }
}

fn operation_for_path(method: &Method, path: &str) -> String {
  let prefix = if path.starts_with("/admin/v1/") {
    "/admin/v1/"
  } else {
    "/"
  };
  let mut normalized = path
    .trim_start_matches(prefix)
    .trim_matches('/')
    .replace('/', ".")
    .replace('-', "_");
  if normalized.is_empty() {
    normalized = "root".to_string();
  }
  format!("{}.{}", method.as_str().to_ascii_lowercase(), normalized)
}

fn target_for_path(path: &str) -> (Option<String>, Option<String>) {
  let rest = path.strip_prefix("/admin/v1/").unwrap_or(path);
  let mut segments = rest.split('/');
  match (
    segments.next(),
    segments.next(),
    segments.next(),
    segments.next(),
    segments.next(),
  ) {
    (Some("ipm"), Some("principals"), Some(id), None, None) => {
      (Some("ipm-principal".to_string()), Some(id.to_string()))
    }
    (Some("ipm"), Some("credentials"), Some(id), None, None)
    | (Some("ipm"), Some("credentials"), Some(id), Some(_), None) => {
      (Some("ipm-credential".to_string()), Some(id.to_string()))
    }
    (Some("ipm"), Some("policies"), Some(id), None, None) => {
      (Some("ipm-policy".to_string()), Some(id.to_string()))
    }
    (Some("ipm"), Some("bindings"), Some(id), None, None) => {
      (Some("ipm-binding".to_string()), Some(id.to_string()))
    }
    (Some("dynamic-policies"), Some(id), None, None, None) if id.parse::<i64>().is_ok() => {
      (Some("dynamic-policy".to_string()), Some(id.to_string()))
    }
    (Some("upstream-pools"), Some(pool), Some("servers"), Some(server), None) => (
      Some("upstream-pool-server".to_string()),
      Some(format!("{pool}/{server}")),
    ),
    (Some("upstream-pools"), Some(pool), None, None, None) => {
      (Some("upstream-pool".to_string()), Some(pool.to_string()))
    }
    (Some("stream-pools"), Some(pool), Some("servers"), Some(server), None) => (
      Some("stream-pool-server".to_string()),
      Some(format!("{pool}/{server}")),
    ),
    (Some("stream-pools"), Some(pool), None, None, None) => {
      (Some("stream-pool".to_string()), Some(pool.to_string()))
    }
    _ => (None, None),
  }
}

pub(super) fn request_summary_from_query(query: Option<&str>) -> Value {
  let mut summary = json!({});
  let Some(query) = query else {
    return summary;
  };
  let mut keys = Vec::new();
  let mut safe_values = serde_json::Map::new();
  for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
    keys.push(sanitize_audit_text(&key));
    if is_safe_query_key(&key) {
      safe_values.insert(
        key.to_string(),
        json!(truncate_and_sanitize_value(&value, 256)),
      );
    }
  }
  keys.sort();
  keys.dedup();
  if let Some(map) = summary.as_object_mut() {
    map.insert("query_keys".to_string(), json!(keys));
    if !safe_values.is_empty() {
      map.insert("query".to_string(), Value::Object(safe_values));
    }
  }
  summary
}

fn is_safe_query_key(key: &str) -> bool {
  matches!(
    key,
    "limit"
      | "outcome"
      | "actor"
      | "principal"
      | "service"
      | "operation"
      | "request_id"
      | "path_prefix"
      | "before_id"
      | "policy_id"
      | "target_kind"
      | "target_id"
  )
}

pub(super) fn push_authorization_check(
  summary: &mut Value,
  action: &str,
  resource: &str,
  allowed: bool,
) {
  let Some(map) = summary.as_object_mut() else {
    return;
  };
  let checks = map
    .entry("authorization_checks")
    .or_insert_with(|| Value::Array(Vec::new()));
  let Value::Array(items) = checks else {
    return;
  };
  if items.len() < 16 {
    items.push(json!({
      "action": action,
      "resource": resource,
      "allowed": allowed,
    }));
  }
}

pub(super) fn merge_json_body_summary(summary: &mut Value, body: Value) {
  if let Some(map) = summary.as_object_mut() {
    map.insert("body".to_string(), body);
  }
}

pub(super) fn json_body_summary(bytes: &[u8]) -> Value {
  let mut body = serde_json::Map::new();
  body.insert("bytes".to_string(), json!(bytes.len()));
  match serde_json::from_slice::<Value>(bytes) {
    Ok(Value::Object(map)) => {
      let mut keys = map.keys().cloned().collect::<Vec<_>>();
      for key in &mut keys {
        *key = sanitize_audit_text(key);
      }
      keys.sort();
      body.insert("json_top_level_keys".to_string(), json!(keys));
      let mut safe_fields = serde_json::Map::new();
      for (key, value) in map {
        if is_safe_body_key(&key)
          && let Some(value) = safe_json_value(&value)
        {
          safe_fields.insert(key, value);
        }
      }
      if !safe_fields.is_empty() {
        body.insert("safe_fields".to_string(), Value::Object(safe_fields));
      }
    }
    Ok(_) => {
      body.insert("json_top_level".to_string(), json!("non_object"));
    }
    Err(_) => {
      body.insert("json_valid".to_string(), json!(false));
    }
  }
  Value::Object(body)
}

fn is_safe_body_key(key: &str) -> bool {
  matches!(
    key,
    "id"
      | "name"
      | "source"
      | "type"
      | "policy"
      | "principal"
      | "group"
      | "apply"
      | "state"
      | "method"
      | "scheme"
      | "host"
      | "tag"
      | "partition"
      | "path_prefix"
  )
}

fn safe_json_value(value: &Value) -> Option<Value> {
  match value {
    Value::String(value) => Some(json!(truncate_and_sanitize_value(value, 256))),
    Value::Bool(value) => Some(json!(value)),
    Value::Number(value) => Some(Value::Number(value.clone())),
    Value::Array(values) => Some(json!({ "array_items": values.len() })),
    Value::Object(values) => Some(json!({ "object_keys": values.len() })),
    Value::Null => Some(Value::Null),
  }
}

pub(super) fn sanitize_summary_for_storage(value: &Value) -> Value {
  match value {
    Value::String(value) => Value::String(sanitize_audit_text(value)),
    Value::Array(values) => Value::Array(values.iter().map(sanitize_summary_for_storage).collect()),
    Value::Object(values) => {
      let mut sanitized = serde_json::Map::new();
      for (key, value) in values {
        sanitized.insert(
          sanitize_audit_text(key),
          sanitize_summary_for_storage(value),
        );
      }
      Value::Object(sanitized)
    }
    _ => value.clone(),
  }
}

fn truncate_and_sanitize_value(value: &str, max: usize) -> String {
  sanitize_audit_text(&truncate_value(value, max))
}

fn truncate_value(value: &str, max: usize) -> String {
  if value.len() <= max {
    return value.to_string();
  }
  let truncated = value.chars().take(max).collect::<String>();
  format!("{truncated}...")
}

fn sanitize_audit_text(value: &str) -> String {
  if !value.chars().any(char::is_control) {
    return value.to_string();
  }
  let mut sanitized = String::with_capacity(value.len());
  for ch in value.chars() {
    if ch.is_control() {
      sanitized.push_str(&format!("\\u{:04x}", ch as u32));
    } else {
      sanitized.push(ch);
    }
  }
  sanitized
}

pub(super) fn random_request_id() -> String {
  let mut bytes = [0_u8; 16];
  if crate::crypto::random_fill(&mut bytes).is_ok() {
    return hex(&bytes);
  }
  let fallback = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_nanos())
    .unwrap_or_default();
  format!("{fallback:032x}")
}

fn hex(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(super) fn status_reason(status: StatusCode) -> &'static str {
  match status {
    StatusCode::UNAUTHORIZED => "unauthorized",
    StatusCode::FORBIDDEN => "permission denied",
    StatusCode::NOT_FOUND => "not found",
    StatusCode::METHOD_NOT_ALLOWED => "method not allowed",
    StatusCode::PAYLOAD_TOO_LARGE => "request body is too large",
    StatusCode::PRECONDITION_REQUIRED => "precondition required",
    StatusCode::PRECONDITION_FAILED => "precondition failed",
    StatusCode::CONFLICT => "conflict",
    StatusCode::BAD_REQUEST => "bad request",
    _ if status.is_server_error() => "server error",
    _ => "request failed",
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn json_body_summary_redacts_raw_sensitive_payloads() {
    let summary = json_body_summary(
      br#"{
        "config": "secret-config",
        "content": "rule content",
        "body": "response body",
        "token": "secret-token",
        "name": "safe-name",
        "source": "automation",
        "enabled": true
      }"#,
    );

    assert_eq!(summary["safe_fields"]["name"], "safe-name");
    assert_eq!(summary["safe_fields"]["source"], "automation");
    assert!(summary["safe_fields"].get("config").is_none());
    assert!(summary["safe_fields"].get("content").is_none());
    assert!(summary["safe_fields"].get("body").is_none());
    assert!(summary["safe_fields"].get("token").is_none());
    assert!(summary.get("sha256").is_none());
  }

  #[test]
  fn request_summary_sanitizes_query_control_text() {
    let summary = request_summary_from_query(Some("limit=%00&%00=x&path_prefix=%1Fadmin"));

    assert_no_control_text(&summary);
    assert_eq!(summary["query"]["limit"], "\\u0000");
    assert_eq!(summary["query"]["path_prefix"], "\\u001fadmin");
    assert_eq!(
      summary["query_keys"]
        .as_array()
        .expect("query keys should be an array")
        .iter()
        .map(|value| value.as_str().expect("query key should be a string"))
        .collect::<Vec<_>>(),
      ["\\u0000", "limit", "path_prefix"]
    );
  }

  #[test]
  fn json_body_summary_sanitizes_safe_fields_and_top_level_keys() {
    let summary = json_body_summary(
      br#"{
        "na\u0000me": "not-allowlisted",
        "name": "safe\u0000field",
        "source": "line\u001fend"
      }"#,
    );

    assert_no_control_text(&summary);
    assert_eq!(summary["safe_fields"]["name"], "safe\\u0000field");
    assert_eq!(summary["safe_fields"]["source"], "line\\u001fend");
    let keys = summary["json_top_level_keys"]
      .as_array()
      .expect("top-level keys should be an array")
      .iter()
      .map(|value| value.as_str().expect("top-level key should be a string"))
      .collect::<Vec<_>>();
    assert!(keys.contains(&"na\\u0000me"));
  }

  #[test]
  fn descriptor_extracts_service_operation_and_targets() {
    let descriptor = describe_request(&Method::PATCH, "/admin/v1/upstream-pools/app/servers/blue");

    assert_eq!(descriptor.service.as_deref(), Some("upstream-pool"));
    assert_eq!(
      descriptor.operation,
      "patch.upstream_pools.app.servers.blue"
    );
    assert_eq!(
      descriptor.target_kind.as_deref(),
      Some("upstream-pool-server")
    );
    assert_eq!(descriptor.target_id.as_deref(), Some("app/blue"));

    let descriptor = describe_request(&Method::PATCH, "/admin/v1/stream-pools/edge/servers/quic-a");

    assert_eq!(descriptor.service.as_deref(), Some("stream-pool"));
    assert_eq!(
      descriptor.operation,
      "patch.stream_pools.edge.servers.quic_a"
    );
    assert_eq!(
      descriptor.target_kind.as_deref(),
      Some("stream-pool-server")
    );
    assert_eq!(descriptor.target_id.as_deref(), Some("edge/quic-a"));
  }

  fn assert_no_control_text(value: &Value) {
    match value {
      Value::String(value) => {
        assert!(
          !value.chars().any(char::is_control),
          "string contains control character: {value:?}"
        );
      }
      Value::Array(values) => {
        for value in values {
          assert_no_control_text(value);
        }
      }
      Value::Object(values) => {
        for (key, value) in values {
          assert!(
            !key.chars().any(char::is_control),
            "key contains control character: {key:?}"
          );
          assert_no_control_text(value);
        }
      }
      _ => {}
    }
  }
}
