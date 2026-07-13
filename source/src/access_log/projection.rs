use std::io::Write as _;

use serde_json::{Map, Number, Value, json};
use tracing::warn;

use crate::admin_audit::AdminAuditEvent;

use super::AccessLogSource;

mod ecs;

pub(super) use ecs::project_ecs;

pub(super) const OCSF_VERSION: &str = "1.8.0";
const HTTP_ACTIVITY_CLASS_UID: u64 = 4002;
const API_ACTIVITY_CLASS_UID: u64 = 6003;

struct OcsfClass {
  category_uid: u64,
  category_name: &'static str,
  class_uid: u64,
  class_name: &'static str,
  activity_id: u64,
  activity_name: &'static str,
}

pub(super) fn project_ocsf(
  source: AccessLogSource,
  timestamp_unix_ms: u64,
  value: &Value,
) -> Value {
  match source {
    AccessLogSource::Admin => project_admin_api_activity(timestamp_unix_ms, value),
    AccessLogSource::System | AccessLogSource::Waf => {
      project_http_activity(source, timestamp_unix_ms, value)
    }
  }
}

fn project_http_activity(source: AccessLogSource, timestamp_unix_ms: u64, value: &Value) -> Value {
  let method = value_string(value, &["method"]);
  let (activity_id, activity_name) = http_activity(method.as_deref());
  let status_code = value_u64(value, &["status"]);
  let status_id = event_status_id(value, status_code);
  let severity_id = severity_id(status_code, status_id);
  let mut root = base_event(
    timestamp_unix_ms,
    OcsfClass {
      category_uid: 4,
      category_name: "Network Activity",
      class_uid: HTTP_ACTIVITY_CLASS_UID,
      class_name: "HTTP Activity",
      activity_id,
      activity_name,
    },
    status_id,
    severity_id,
  );
  insert_string(
    &mut root,
    "message",
    Some(format!("OxiBelt {} access", source_scope(source))),
  );

  if let Some(http_request) = http_request_value(value, method) {
    root.insert("http_request".to_string(), http_request);
  }
  if let Some(http_response) = http_response_value(status_code) {
    root.insert("http_response".to_string(), http_response);
  }
  if let Some(src_endpoint) = src_endpoint_value(value) {
    root.insert("src_endpoint".to_string(), src_endpoint);
  }
  if let Some(dst_endpoint) = dst_endpoint_value(value) {
    root.insert("dst_endpoint".to_string(), dst_endpoint);
  }
  if let Some(tls) = tls_value(value) {
    root.insert("tls".to_string(), tls);
  }
  insert_string(
    &mut root,
    "app_protocol_name",
    value_string(value, &["protocol"]),
  );
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

fn project_admin_api_activity(timestamp_unix_ms: u64, value: &Value) -> Value {
  let method = value_string(value, &["method"]);
  let (activity_id, activity_name) = api_activity(method.as_deref());
  let status_code = value_u64(value, &["status"]);
  let status_id = event_status_id(value, status_code);
  let severity_id = severity_id(status_code, status_id);
  let mut root = base_event(
    timestamp_unix_ms,
    OcsfClass {
      category_uid: 6,
      category_name: "Application Activity",
      class_uid: API_ACTIVITY_CLASS_UID,
      class_name: "API Activity",
      activity_id,
      activity_name,
    },
    status_id,
    severity_id,
  );
  insert_string(
    &mut root,
    "message",
    value_string(value, &["operation"]).map(|operation| format!("OxiBelt Admin API {operation}")),
  );
  root.insert("actor".to_string(), admin_actor_value(value));
  root.insert("api".to_string(), admin_api_value(value));

  if let Some(http_request) = http_request_value(value, method) {
    root.insert("http_request".to_string(), http_request);
  }
  if let Some(http_response) = http_response_value(status_code) {
    root.insert("http_response".to_string(), http_response);
  }
  if let Some(src_endpoint) = src_endpoint_value(value) {
    root.insert("src_endpoint".to_string(), src_endpoint);
  }
  if let Some(tls) = tls_value(value) {
    root.insert("tls".to_string(), tls);
  }
  if let Some(resources) = admin_resources_value(value) {
    root.insert("resources".to_string(), resources);
  }
  insert_string(&mut root, "status_detail", value_string(value, &["error"]));
  root.insert("unmapped".to_string(), json!({ "oxibelt": value }));
  Value::Object(root)
}

fn base_event(
  timestamp_unix_ms: u64,
  class: OcsfClass,
  status_id: u64,
  severity_id: u64,
) -> Map<String, Value> {
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
    Value::Number(Number::from(class.category_uid)),
  );
  root.insert(
    "category_name".to_string(),
    Value::String(class.category_name.to_string()),
  );
  root.insert(
    "class_uid".to_string(),
    Value::Number(Number::from(class.class_uid)),
  );
  root.insert(
    "class_name".to_string(),
    Value::String(class.class_name.to_string()),
  );
  root.insert(
    "activity_id".to_string(),
    Value::Number(Number::from(class.activity_id)),
  );
  root.insert(
    "activity_name".to_string(),
    Value::String(class.activity_name.to_string()),
  );
  root.insert(
    "type_uid".to_string(),
    Value::Number(Number::from(type_uid(class.class_uid, class.activity_id))),
  );
  root.insert(
    "type_name".to_string(),
    Value::String(format!("{}: {}", class.class_name, class.activity_name)),
  );
  root.insert(
    "severity_id".to_string(),
    Value::Number(Number::from(severity_id)),
  );
  root.insert(
    "severity".to_string(),
    Value::String(severity_name(severity_id).to_string()),
  );
  root.insert(
    "status_id".to_string(),
    Value::Number(Number::from(status_id)),
  );
  root.insert(
    "status".to_string(),
    Value::String(status_name(status_id).to_string()),
  );
  root
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
    "authentication": {
      "reason": event.authentication_reason,
      "workload_identity": {
        "kind": event.workload_identity_kind,
        "value": event.workload_identity,
        "principal": event.workload_principal,
        "certificate_fingerprint_sha256": event.certificate_fingerprint_sha256,
      },
      "credential": {
        "kind": event.credential_kind,
        "identity": event.credential_identity,
        "principal": event.credential_principal,
      },
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

pub(super) fn source_scope(source: AccessLogSource) -> &'static str {
  match source {
    AccessLogSource::System => "system",
    AccessLogSource::Waf => "waf",
    AccessLogSource::Admin => "admin",
  }
}

fn http_activity(method: Option<&str>) -> (u64, &'static str) {
  match method.map(str::to_ascii_uppercase).as_deref() {
    Some("CONNECT") => (1, "Connect"),
    Some("DELETE") => (2, "Delete"),
    Some("GET") => (3, "Get"),
    Some("HEAD") => (4, "Head"),
    Some("OPTIONS") => (5, "Options"),
    Some("POST") => (6, "Post"),
    Some("PUT") => (7, "Put"),
    Some("TRACE") => (8, "Trace"),
    Some("PATCH") => (9, "Patch"),
    Some(_) => (99, "Other"),
    None => (0, "Unknown"),
  }
}

fn api_activity(method: Option<&str>) -> (u64, &'static str) {
  match method.map(str::to_ascii_uppercase).as_deref() {
    Some("POST") => (1, "Create"),
    Some("GET") | Some("HEAD") | Some("OPTIONS") => (2, "Read"),
    Some("PUT") | Some("PATCH") => (3, "Update"),
    Some("DELETE") => (4, "Delete"),
    Some(_) => (99, "Other"),
    None => (0, "Unknown"),
  }
}

fn type_uid(class_uid: u64, activity_id: u64) -> u64 {
  class_uid.saturating_mul(100).saturating_add(activity_id)
}

fn http_request_value(value: &Value, method: Option<String>) -> Option<Value> {
  let mut request = Map::new();
  insert_string(&mut request, "http_method", method);
  insert_string(&mut request, "user_agent", user_agent_value(value));
  let mut url = Map::new();
  insert_string(&mut url, "path", value_string(value, &["path"]));
  insert_string(&mut url, "query_string", value_string(value, &["query"]));
  insert_string(
    &mut url,
    "url_string",
    value_string(value, &["uri"]).or_else(|| value_string(value, &["path"])),
  );
  if !url.is_empty() {
    request.insert("url".to_string(), Value::Object(url));
  }
  object_value(request)
}

fn http_response_value(status_code: Option<u64>) -> Option<Value> {
  let mut response = Map::new();
  insert_u64(&mut response, "code", status_code);
  object_value(response)
}

fn src_endpoint_value(value: &Value) -> Option<Value> {
  let mut endpoint = Map::new();
  insert_string(
    &mut endpoint,
    "ip",
    value_string(value, &["client_ip"]).or_else(|| value_string(value, &["source_ip"])),
  );
  insert_u64(&mut endpoint, "port", value_u64(value, &["client_port"]));
  object_value(endpoint)
}

fn dst_endpoint_value(value: &Value) -> Option<Value> {
  let mut endpoint = Map::new();
  insert_string(&mut endpoint, "hostname", value_string(value, &["host"]));
  object_value(endpoint)
}

fn tls_value(value: &Value) -> Option<Value> {
  value_bool(value, &["tls"]).map(|enabled| json!({ "enabled": enabled }))
}

fn admin_actor_value(value: &Value) -> Value {
  let mut actor = Map::new();
  let mut user = Map::new();
  insert_string(&mut user, "name", value_string(value, &["actor"]));
  insert_string(&mut user, "uid", value_string(value, &["subject"]));
  if let Some(groups) = value.get("groups").and_then(Value::as_array)
    && !groups.is_empty()
  {
    user.insert("groups".to_string(), Value::Array(groups.clone()));
  }
  if let Some(principal) = value_string(value, &["principal"]) {
    user.insert("account".to_string(), json!({ "name": principal }));
  }
  if !user.is_empty() {
    actor.insert("user".to_string(), Value::Object(user));
  }
  actor.insert(
    "process".to_string(),
    json!({
      "name": "oxibelt-admin-api",
    }),
  );
  Value::Object(actor)
}

fn admin_api_value(value: &Value) -> Value {
  let mut api = Map::new();
  api.insert(
    "name".to_string(),
    Value::String("OxiBelt Admin API".to_string()),
  );
  insert_string(&mut api, "operation", value_string(value, &["operation"]));
  if let Some(service) = value_string(value, &["service"]) {
    api.insert("service".to_string(), json!({ "name": service }));
  }
  if let Some(request_id) = value_string(value, &["request_id"]) {
    api.insert("request".to_string(), json!({ "uid": request_id }));
  }
  Value::Object(api)
}

fn admin_resources_value(value: &Value) -> Option<Value> {
  let action = value_string(value, &["action"]);
  let resource = value_string(value, &["resource"]);
  let target_kind = value_string(value, &["target_kind"]);
  let target_id = value_string(value, &["target_id"]);
  if action.is_none() && resource.is_none() && target_kind.is_none() && target_id.is_none() {
    return None;
  }
  let mut item = Map::new();
  insert_string(&mut item, "name", resource);
  insert_string(&mut item, "type", target_kind);
  insert_string(&mut item, "uid", target_id);
  insert_string(&mut item, "action", action);
  Some(Value::Array(vec![Value::Object(item)]))
}

fn event_status_id(value: &Value, status_code: Option<u64>) -> u64 {
  if let Some(outcome) = value_string(value, &["outcome"]) {
    let normalized = outcome.to_ascii_lowercase();
    if matches!(normalized.as_str(), "success" | "allowed" | "applied") {
      return 1;
    }
    if matches!(normalized.as_str(), "failure" | "denied" | "rejected") {
      return 2;
    }
  }
  match status_code {
    Some(status) if status >= 400 => 2,
    Some(_) => 1,
    None => 0,
  }
}

fn status_name(status_id: u64) -> &'static str {
  match status_id {
    1 => "Success",
    2 => "Failure",
    99 => "Other",
    _ => "Unknown",
  }
}

fn severity_id(status_code: Option<u64>, status_id: u64) -> u64 {
  match status_code {
    Some(status) if status >= 500 => 3,
    Some(status) if status >= 400 => 2,
    Some(_) => 1,
    None if status_id == 2 => 2,
    None => 1,
  }
}

fn severity_name(severity_id: u64) -> &'static str {
  match severity_id {
    1 => "Informational",
    2 => "Low",
    3 => "Medium",
    4 => "High",
    5 => "Critical",
    6 => "Fatal",
    99 => "Other",
    _ => "Unknown",
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

fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
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

fn insert_string(object: &mut Map<String, Value>, key: &str, value: Option<String>) {
  if let Some(value) = value {
    object.insert(key.to_string(), Value::String(value));
  }
}

fn insert_u64(object: &mut Map<String, Value>, key: &str, value: Option<u64>) {
  if let Some(value) = value {
    object.insert(key.to_string(), Value::Number(Number::from(value)));
  }
}

fn object_value(object: Map<String, Value>) -> Option<Value> {
  if object.is_empty() {
    None
  } else {
    Some(Value::Object(object))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ocsf_http_projection_maps_system_access_fields() {
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
      "user_agent": { "values": ["curl/8.0", "duplicate"] }
    });

    let projected = project_ocsf(AccessLogSource::System, 42, &record);

    assert_eq!(projected["metadata"]["version"], json!(OCSF_VERSION));
    assert_eq!(projected["category_uid"], json!(4));
    assert_eq!(projected["class_uid"], json!(4002));
    assert_eq!(projected["activity_id"], json!(3));
    assert_eq!(projected["type_uid"], json!(400203));
    assert_eq!(projected["http_request"]["http_method"], json!("GET"));
    assert_eq!(projected["http_response"]["code"], json!(200));
    assert_eq!(projected["src_endpoint"]["ip"], json!("203.0.113.10"));
    assert_eq!(projected["tls"]["enabled"], json!(true));
    assert_eq!(projected["http_request"]["user_agent"], json!("curl/8.0"));
    assert_eq!(
      projected["unmapped"]["oxibelt"]["user_agent"]["values"],
      json!(["curl/8.0", "duplicate"])
    );
  }

  #[test]
  fn ocsf_waf_projection_adds_security_result() {
    let record = json!({
      "event": "oxibelt.access",
      "scope": "waf",
      "method": "POST",
      "path": "/login",
      "status": 403
    });

    let projected = project_ocsf(AccessLogSource::Waf, 99, &record);

    assert_eq!(projected["class_uid"], json!(4002));
    assert_eq!(projected["activity_id"], json!(6));
    assert_eq!(projected["status_id"], json!(2));
    assert_eq!(
      projected["security_result"][0]["category_name"],
      json!("WAF")
    );
    assert_eq!(projected["unmapped"]["oxibelt"]["scope"], json!("waf"));
  }

  #[test]
  fn ocsf_admin_projection_maps_tls_token_and_ipm_fields() {
    let record = json!({
      "event": "oxibelt.admin.access",
      "scope": "admin",
      "request_id": "req-1",
      "actor": "alice",
      "principal": "admin",
      "subject": "sub-1",
      "groups": ["ops"],
      "source_ip": "127.0.0.1",
      "tls": true,
      "method": "POST",
      "path": "/admin/v1/tokens",
      "service": "ipm",
      "operation": "post.ipm.credentials",
      "action": "ipm:CreateCredential",
      "resource": "oxibelt:oxibelt:ipm:credential/*",
      "target_kind": "credential",
      "target_id": "cred-1",
      "status": 201,
      "outcome": "applied"
    });

    let projected = project_ocsf(AccessLogSource::Admin, 42, &record);

    assert_eq!(projected["category_uid"], json!(6));
    assert_eq!(projected["class_uid"], json!(6003));
    assert_eq!(projected["activity_id"], json!(1));
    assert_eq!(projected["type_uid"], json!(600301));
    assert_eq!(projected["actor"]["user"]["name"], json!("alice"));
    assert_eq!(projected["actor"]["user"]["uid"], json!("sub-1"));
    assert_eq!(
      projected["actor"]["user"]["account"]["name"],
      json!("admin")
    );
    assert_eq!(projected["actor"]["user"]["groups"], json!(["ops"]));
    assert_eq!(projected["api"]["operation"], json!("post.ipm.credentials"));
    assert_eq!(projected["api"]["request"]["uid"], json!("req-1"));
    assert_eq!(
      projected["resources"][0]["name"],
      json!("oxibelt:oxibelt:ipm:credential/*")
    );
    assert_eq!(
      projected["resources"][0]["action"],
      json!("ipm:CreateCredential")
    );
    assert_eq!(projected["tls"]["enabled"], json!(true));
    assert_eq!(
      projected["unmapped"]["oxibelt"]["target_id"],
      json!("cred-1")
    );
  }

  #[test]
  fn admin_event_value_includes_tls_and_token_identity() {
    let event = AdminAuditEvent {
      request_id: "req-1".to_string(),
      actor: Some("alice".to_string()),
      principal: Some("admin".to_string()),
      subject: Some("sub-1".to_string()),
      groups: vec!["ops".to_string()],
      workload_identity_kind: Some("spiffe_id".to_string()),
      workload_identity: Some("spiffe://example.test/ns/edge/sa/controller".to_string()),
      workload_principal: Some("admin".to_string()),
      certificate_fingerprint_sha256: Some("a".repeat(64)),
      credential_kind: Some("bearer".to_string()),
      credential_identity: Some("admin-token".to_string()),
      credential_principal: Some("admin".to_string()),
      authentication_reason: Some("bound_bearer".to_string()),
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
    assert_eq!(value["authentication"]["reason"], json!("bound_bearer"));
    assert_eq!(
      value["authentication"]["workload_identity"]["kind"],
      json!("spiffe_id")
    );
  }
}
