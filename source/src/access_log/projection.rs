use std::io::Write as _;

use serde_json::{Map, Number, Value, json};
use tracing::warn;

use crate::admin_audit::AdminAuditEvent;

use super::AccessLogSource;

pub(super) const ECS_VERSION: &str = "9.4.0";
const OCSF_VERSION: &str = "1.5.0";

pub(super) fn project_ecs(source: AccessLogSource, timestamp_unix_ms: u64, value: &Value) -> Value {
  let mut root = Map::new();
  root.insert(
    "@timestamp".to_string(),
    Value::Number(Number::from(timestamp_unix_ms)),
  );
  root.insert("ecs".to_string(), json!({ "version": ECS_VERSION }));
  root.insert(
    "event".to_string(),
    json!({
      "kind": "event",
      "category": event_categories(source),
      "type": ["access"],
      "dataset": event_dataset(source),
      "provider": "oxibelt",
      "action": event_action(source, value),
      "outcome": event_outcome(value),
    }),
  );
  root.insert(
    "observer".to_string(),
    json!({
      "vendor": "OxiBelt",
      "product": "OxiBelt",
      "type": "proxy",
    }),
  );
  insert_nested(
    &mut root,
    &["labels", "scope"],
    string_value(source_scope(source)),
  );

  if let Some(value) = value_string(value, &["method"]) {
    insert_nested(
      &mut root,
      &["http", "request", "method"],
      string_value(value),
    );
  }
  if let Some(value) = value_u64(value, &["status"]) {
    insert_nested(
      &mut root,
      &["http", "response", "status_code"],
      Value::Number(Number::from(value)),
    );
  }
  if let Some(value) = value_u64(value, &["response_body_bytes"]) {
    insert_nested(
      &mut root,
      &["http", "response", "body", "bytes"],
      Value::Number(Number::from(value)),
    );
  }
  if let Some(path) = value_string(value, &["path"]) {
    insert_nested(&mut root, &["url", "path"], string_value(path));
  }
  if let Some(query) = value_string(value, &["query"]) {
    insert_nested(&mut root, &["url", "query"], string_value(query));
  }
  if let Some(uri) = value_string(value, &["uri"]) {
    insert_nested(&mut root, &["url", "original"], string_value(uri));
  } else if let Some(path) = value_string(value, &["path"]) {
    insert_nested(&mut root, &["url", "original"], string_value(path));
  }
  if let Some(user_agent) = user_agent_value(value) {
    insert_nested(
      &mut root,
      &["user_agent", "original"],
      string_value(user_agent),
    );
  }
  if let Some(ip) =
    value_string(value, &["client_ip"]).or_else(|| value_string(value, &["source_ip"]))
  {
    insert_nested(&mut root, &["source", "ip"], string_value(ip.clone()));
    insert_nested(&mut root, &["client", "ip"], string_value(ip));
  }
  if let Some(port) = value_u64(value, &["client_port"]) {
    insert_nested(
      &mut root,
      &["source", "port"],
      Value::Number(Number::from(port)),
    );
  }
  if let Some(value) = value_string(value, &["host"]) {
    insert_nested(&mut root, &["url", "domain"], string_value(value));
  }
  if let Some(value) = value_string(value, &["protocol"]) {
    insert_nested(&mut root, &["network", "protocol"], string_value(value));
  }
  if let Some(value) = value_string(value, &["transport"]) {
    insert_nested(&mut root, &["network", "transport"], string_value(value));
  }
  if let Some(value) = value_bool(value, &["tls"]) {
    insert_nested(&mut root, &["tls", "established"], Value::Bool(value));
  }
  if let Some(value) = value_string(value, &["route"]) {
    insert_nested(&mut root, &["labels", "route"], string_value(value));
  }
  if let Some(value) = value_string(value, &["request_id"]) {
    insert_nested(&mut root, &["http", "request", "id"], string_value(value));
  }
  if let Some(value) = value_string(value, &["operation"]) {
    insert_nested(&mut root, &["labels", "operation"], string_value(value));
  }
  if let Some(value) = value_string(value, &["service"]) {
    insert_nested(&mut root, &["labels", "service"], string_value(value));
  }
  if let Some(value) = value_string(value, &["actor"]) {
    insert_nested(&mut root, &["user", "name"], string_value(value));
  }
  if let Some(value) = value_string(value, &["subject"]) {
    insert_nested(&mut root, &["user", "id"], string_value(value));
  }
  if let Some(value) = value.get("groups").and_then(Value::as_array) {
    insert_nested(&mut root, &["user", "roles"], Value::Array(value.clone()));
  }
  root.insert("oxibelt".to_string(), value.clone());
  Value::Object(root)
}

pub(super) fn project_ocsf(
  source: AccessLogSource,
  timestamp_unix_ms: u64,
  value: &Value,
) -> Value {
  let status = value_u64(value, &["status"]);
  let mut root = Map::new();
  root.insert(
    "time".to_string(),
    Value::Number(Number::from(timestamp_unix_ms)),
  );
  root.insert(
    "metadata".to_string(),
    json!({
      "version": OCSF_VERSION,
      "product": {
        "name": "OxiBelt",
        "vendor_name": "OxiBelt",
      },
    }),
  );
  root.insert(
    "category_uid".to_string(),
    Value::Number(Number::from(4_u64)),
  );
  root.insert(
    "category_name".to_string(),
    Value::String("Network Activity".to_string()),
  );
  root.insert(
    "class_uid".to_string(),
    Value::Number(Number::from(4002_u64)),
  );
  root.insert(
    "class_name".to_string(),
    Value::String("HTTP Activity".to_string()),
  );
  root.insert(
    "activity_id".to_string(),
    Value::Number(Number::from(1_u64)),
  );
  root.insert(
    "activity_name".to_string(),
    Value::String("Access".to_string()),
  );
  root.insert(
    "type_uid".to_string(),
    Value::Number(Number::from(400201_u64)),
  );
  root.insert(
    "type_name".to_string(),
    Value::String(format!("HTTP Activity: {}", source_scope(source))),
  );
  root.insert(
    "severity_id".to_string(),
    Value::Number(Number::from(
      if status.is_some_and(|status| status >= 500) {
        3_u64
      } else {
        1_u64
      },
    )),
  );
  root.insert(
    "status".to_string(),
    Value::String(event_outcome(value).to_string()),
  );
  root.insert(
    "http_request".to_string(),
    json!({
      "http_method": value_string(value, &["method"]),
      "url": {
        "path": value_string(value, &["path"]),
        "query_string": value_string(value, &["query"]),
        "url_string": value_string(value, &["uri"]).or_else(|| value_string(value, &["path"])),
      },
      "user_agent": user_agent_value(value),
    }),
  );
  root.insert(
    "http_response".to_string(),
    json!({
      "code": status,
    }),
  );
  root.insert(
    "src_endpoint".to_string(),
    json!({
      "ip": value_string(value, &["client_ip"]).or_else(|| value_string(value, &["source_ip"])),
      "port": value_u64(value, &["client_port"]),
    }),
  );
  root.insert(
    "tls".to_string(),
    json!({
      "enabled": value_bool(value, &["tls"]),
    }),
  );
  if source == AccessLogSource::Admin {
    root.insert(
      "actor".to_string(),
      json!({
        "user": {
          "name": value_string(value, &["actor"]),
          "uid": value_string(value, &["subject"]),
          "groups": value.get("groups").cloned(),
        },
        "process": {
          "name": "oxibelt-admin-api",
        },
      }),
    );
  }
  if source == AccessLogSource::Waf {
    root.insert(
      "security_result".to_string(),
      json!([{
        "category_name": "WAF",
        "action": "Logged",
      }]),
    );
  }
  root.insert("unmapped".to_string(), json!({ "oxibelt": value }));
  Value::Object(root)
}

pub(super) fn admin_event_value(event: &AdminAuditEvent) -> Value {
  json!({
    "event": "oxibelt.admin.access",
    "scope": "admin",
    "request_id": event.request_id,
    "actor": event.actor,
    "principal": event.principal,
    "subject": event.subject,
    "groups": event.groups,
    "peer": event.peer,
    "source_ip": event.source_ip,
    "scheme": event.scheme,
    "tls": event.scheme == "https",
    "method": event.method,
    "path": event.path,
    "token": {
      "actor": event.actor,
      "principal": event.principal,
      "subject": event.subject,
      "groups": event.groups,
    },
    "service": event.service,
    "operation": event.operation,
    "action": event.action,
    "resource": event.resource,
    "target_kind": event.target_kind,
    "target_id": event.target_id,
    "status": event.status,
    "outcome": event.outcome,
    "error": event.error,
    "request_summary": event.request_summary,
  })
}

pub(super) fn emit_stdout(source: AccessLogSource, value: &Value) {
  let line = match serde_json::to_string(value) {
    Ok(line) => line,
    Err(error) => {
      warn!(error = %error, "failed to serialize access log record");
      return;
    }
  };
  let mut stdout = std::io::stdout().lock();
  if let Err(error) = writeln!(stdout, "{line}") {
    warn!(error = %error, source = source_scope(source), "failed to write access log to stdout");
  }
}

pub(super) fn event_name(source: AccessLogSource) -> &'static str {
  match source {
    AccessLogSource::System => "oxibelt.access",
    AccessLogSource::Waf => "oxibelt.waf.access",
    AccessLogSource::Admin => "oxibelt.admin.access",
  }
}

pub(super) fn event_dataset(source: AccessLogSource) -> &'static str {
  match source {
    AccessLogSource::System => "oxibelt.access",
    AccessLogSource::Waf => "oxibelt.waf.access",
    AccessLogSource::Admin => "oxibelt.admin.access",
  }
}

pub(super) fn source_scope(source: AccessLogSource) -> &'static str {
  match source {
    AccessLogSource::System => "system",
    AccessLogSource::Waf => "waf",
    AccessLogSource::Admin => "admin",
  }
}

fn event_categories(source: AccessLogSource) -> Vec<&'static str> {
  match source {
    AccessLogSource::System => vec!["web"],
    AccessLogSource::Waf => vec!["web", "intrusion_detection"],
    AccessLogSource::Admin => vec!["web", "configuration"],
  }
}

fn event_action(source: AccessLogSource, value: &Value) -> String {
  match source {
    AccessLogSource::Admin => value_string(value, &["operation"]).unwrap_or_else(|| "admin".into()),
    _ => value_string(value, &["method"]).unwrap_or_else(|| "access".into()),
  }
}

fn event_outcome(value: &Value) -> &'static str {
  if let Some(outcome) = value_string(value, &["outcome"]) {
    if outcome.eq_ignore_ascii_case("success") || outcome.eq_ignore_ascii_case("allowed") {
      return "success";
    }
    if outcome.eq_ignore_ascii_case("failure") || outcome.eq_ignore_ascii_case("denied") {
      return "failure";
    }
  }
  match value_u64(value, &["status"]) {
    Some(status) if status >= 400 => "failure",
    Some(_) => "success",
    None => "unknown",
  }
}

fn user_agent_value(value: &Value) -> Option<String> {
  match value.get("user_agent") {
    Some(Value::String(value)) => Some(value.clone()),
    Some(Value::Object(object)) => object.get("values").and_then(first_string),
    Some(Value::Array(values)) => values
      .iter()
      .find_map(|value| value.as_str().map(str::to_string)),
    _ => None,
  }
}

fn first_string(value: &Value) -> Option<String> {
  match value {
    Value::String(value) => Some(value.clone()),
    Value::Array(values) => values
      .iter()
      .find_map(|value| value.as_str().map(str::to_string)),
    _ => None,
  }
}

fn value_string(value: &Value, path: &[&str]) -> Option<String> {
  value_at(value, path)?.as_str().map(str::to_string)
}

fn value_bool(value: &Value, path: &[&str]) -> Option<bool> {
  value_at(value, path)?.as_bool()
}

pub(super) fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
  let value = value_at(value, path)?;
  value
    .as_u64()
    .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
}

fn value_at<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
  for segment in path {
    value = value.get(*segment)?;
  }
  Some(value)
}

fn string_value(value: impl Into<String>) -> Value {
  Value::String(value.into())
}

fn insert_nested(object: &mut Map<String, Value>, path: &[&str], value: Value) {
  let Some((head, tail)) = path.split_first() else {
    return;
  };
  if tail.is_empty() {
    object.insert((*head).to_string(), value);
    return;
  }
  let child = object
    .entry((*head).to_string())
    .or_insert_with(|| Value::Object(Map::new()));
  if !child.is_object() {
    *child = Value::Object(Map::new());
  }
  if let Value::Object(child) = child {
    insert_nested(child, tail, value);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ecs_projection_maps_http_and_source_fields() {
    let record = json!({
      "event": "oxibelt.access",
      "scope": "system",
      "method": "GET",
      "uri": "/health?ready=1",
      "path": "/health",
      "query": "ready=1",
      "client_ip": "203.0.113.10",
      "client_port": 32123,
      "status": 200,
      "tls": true,
      "user_agent": { "values": ["curl/8.0"] }
    });

    let projected = project_ecs(AccessLogSource::System, 42, &record);

    assert_eq!(projected["@timestamp"], json!(42));
    assert_eq!(projected["ecs"]["version"], json!(ECS_VERSION));
    assert_eq!(projected["http"]["request"]["method"], json!("GET"));
    assert_eq!(projected["http"]["response"]["status_code"], json!(200));
    assert_eq!(projected["source"]["ip"], json!("203.0.113.10"));
    assert_eq!(projected["tls"]["established"], json!(true));
    assert_eq!(projected["user_agent"]["original"], json!("curl/8.0"));
  }

  #[test]
  fn ocsf_projection_preserves_unmapped_record() {
    let record = json!({
      "event": "oxibelt.admin.access",
      "scope": "admin",
      "method": "POST",
      "path": "/admin/tokens",
      "status": 403,
      "actor": "alice"
    });

    let projected = project_ocsf(AccessLogSource::Admin, 42, &record);

    assert_eq!(projected["class_uid"], json!(4002));
    assert_eq!(projected["http_response"]["code"], json!(403));
    assert_eq!(projected["actor"]["user"]["name"], json!("alice"));
    assert_eq!(projected["unmapped"]["oxibelt"]["scope"], json!("admin"));
  }

  #[test]
  fn admin_event_value_includes_tls_and_token_identity() {
    let event = AdminAuditEvent {
      request_id: "req-1".to_string(),
      actor: Some("alice".to_string()),
      principal: Some("admin".to_string()),
      subject: Some("sub-1".to_string()),
      groups: vec!["ops".to_string()],
      peer: "127.0.0.1:12345".to_string(),
      source_ip: Some("127.0.0.1".to_string()),
      scheme: "https",
      method: "POST".to_string(),
      path: "/admin/v1/tokens".to_string(),
      service: Some("tokens".to_string()),
      operation: "post.tokens.create".to_string(),
      action: Some("admin:CreateToken".to_string()),
      resource: Some("token/*".to_string()),
      target_kind: Some("token".to_string()),
      target_id: Some("tok-1".to_string()),
      status: 201,
      outcome: "applied".to_string(),
      error: None,
      request_summary: json!({ "body": "redacted" }),
    };

    let value = admin_event_value(&event);

    assert_eq!(value["tls"], json!(true));
    assert_eq!(value["token"]["actor"], json!("alice"));
    assert_eq!(value["token"]["principal"], json!("admin"));
    assert_eq!(value["token"]["subject"], json!("sub-1"));
    assert_eq!(value["token"]["groups"], json!(["ops"]));
  }
}
