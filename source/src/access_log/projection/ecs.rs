use serde_json::{Map, Number, Value, json};

use crate::access_log::AccessLogSource;

use super::{source_scope, value_bool, value_string, value_u64};

pub(super) const ECS_VERSION: &str = "9.4.0";

pub(in crate::access_log) fn project_ecs(
  source: AccessLogSource,
  timestamp_unix_ms: u64,
  value: &Value,
) -> Value {
  let mut root = base_event(source, timestamp_unix_ms, value);
  match source {
    AccessLogSource::Admin => project_admin_fields(&mut root, value),
    AccessLogSource::System | AccessLogSource::Waf => project_http_fields(&mut root, source, value),
  }
  insert_original(&mut root, value);
  Value::Object(root)
}

fn base_event(
  source: AccessLogSource,
  timestamp_unix_ms: u64,
  value: &Value,
) -> Map<String, Value> {
  let mut root = Map::new();
  root.insert(
    "@timestamp".to_string(),
    Value::Number(Number::from(timestamp_unix_ms)),
  );
  root.insert("ecs".to_string(), json!({ "version": ECS_VERSION }));
  root.insert(
    "service".to_string(),
    json!({
      "name": "oxibelt",
      "type": "proxy",
    }),
  );
  root.insert(
    "event".to_string(),
    event_value(source, value_string(value, &["method"]).as_deref(), value),
  );
  root
}

fn event_value(source: AccessLogSource, method: Option<&str>, value: &Value) -> Value {
  let mut event = Map::new();
  event.insert("kind".to_string(), Value::String("event".to_string()));
  event.insert("module".to_string(), Value::String("oxibelt".to_string()));
  event.insert("provider".to_string(), Value::String("oxibelt".to_string()));
  event.insert(
    "dataset".to_string(),
    Value::String(format!("oxibelt.access.{}", source_scope(source))),
  );
  event.insert(
    "category".to_string(),
    string_array(event_categories(source, value)),
  );
  event.insert(
    "type".to_string(),
    string_array(event_types(source, method, value)),
  );
  event.insert(
    "outcome".to_string(),
    Value::String(event_outcome(value).to_string()),
  );
  insert_string(&mut event, "id", value_string(value, &["request_id"]));
  insert_string(&mut event, "action", event_action(source, method, value));
  insert_string(&mut event, "reason", value_string(value, &["error"]));
  Value::Object(event)
}

fn event_categories(source: AccessLogSource, value: &Value) -> Vec<&'static str> {
  match source {
    AccessLogSource::System => vec!["web"],
    AccessLogSource::Waf => vec!["web", "intrusion_detection"],
    AccessLogSource::Admin => {
      let mut categories = vec!["api"];
      if value_string(value, &["service"]).as_deref() == Some("ipm")
        || value_string(value, &["action"])
          .as_deref()
          .is_some_and(|action| action.starts_with("ipm:"))
      {
        categories.push("iam");
      }
      if value_string(value, &["service"]).as_deref() == Some("config") {
        categories.push("configuration");
      }
      categories
    }
  }
}

fn event_types(source: AccessLogSource, method: Option<&str>, value: &Value) -> Vec<&'static str> {
  match source {
    AccessLogSource::System => vec!["access"],
    AccessLogSource::Waf => {
      let mut values = vec!["access"];
      values.push(match event_outcome(value) {
        "failure" => "denied",
        _ => "allowed",
      });
      values
    }
    AccessLogSource::Admin => {
      let mut values = vec!["admin"];
      values.push(admin_change_type(method, value));
      values
    }
  }
}

fn admin_change_type(method: Option<&str>, value: &Value) -> &'static str {
  let action = value_string(value, &["action"])
    .or_else(|| value_string(value, &["operation"]))
    .unwrap_or_default()
    .to_ascii_lowercase();
  if action.contains("create") {
    return "creation";
  }
  if action.contains("delete") || action.contains("revoke") {
    return "deletion";
  }
  if action.contains("update")
    || action.contains("rotate")
    || action.contains("load")
    || action.contains("sync")
    || action.contains("apply")
    || action.contains("purge")
    || action.contains("rollback")
    || action.contains("drain")
  {
    return "change";
  }
  match method.map(str::to_ascii_uppercase).as_deref() {
    Some("POST") => "creation",
    Some("PUT") | Some("PATCH") => "change",
    Some("DELETE") => "deletion",
    _ => "access",
  }
}

fn event_action(source: AccessLogSource, method: Option<&str>, value: &Value) -> Option<String> {
  match source {
    AccessLogSource::Admin => value_string(value, &["operation"])
      .or_else(|| value_string(value, &["action"]))
      .or_else(|| method.map(|method| format!("admin.{}", method.to_ascii_lowercase()))),
    AccessLogSource::Waf => {
      method.map(|method| format!("waf.http.{}", method.to_ascii_lowercase()))
    }
    AccessLogSource::System => method.map(|method| format!("http.{}", method.to_ascii_lowercase())),
  }
}

fn event_outcome(value: &Value) -> &'static str {
  if let Some(outcome) = value_string(value, &["outcome"]) {
    let outcome = outcome.to_ascii_lowercase();
    if matches!(outcome.as_str(), "success" | "allowed" | "applied") {
      return "success";
    }
    if matches!(outcome.as_str(), "failure" | "denied" | "rejected") {
      return "failure";
    }
    if outcome == "unknown" {
      return "unknown";
    }
  }
  match value_u64(value, &["status"]) {
    Some(status) if status >= 400 => "failure",
    Some(_) => "success",
    None => "unknown",
  }
}

fn project_http_fields(root: &mut Map<String, Value>, source: AccessLogSource, value: &Value) {
  insert_string_path(
    root,
    &["http", "request", "id"],
    value_string(value, &["request_id"]),
  );
  insert_string_path(
    root,
    &["http", "request", "method"],
    value_string(value, &["method"]),
  );
  insert_u64_path(
    root,
    &["http", "response", "status_code"],
    value_u64(value, &["status"]),
  );
  insert_u64_path(
    root,
    &["http", "response", "body", "bytes"],
    value_u64(value, &["response_body_bytes"]),
  );
  insert_string_path(
    root,
    &["http", "version"],
    value_string(value, &["request_version"]),
  );
  insert_url_fields(root, value);
  insert_string_path(root, &["client", "ip"], value_string(value, &["client_ip"]));
  insert_u64_path(
    root,
    &["client", "port"],
    value_u64(value, &["client_port"]),
  );
  insert_string_path(root, &["user_agent", "original"], user_agent_value(value));
  insert_string_path(
    root,
    &["network", "transport"],
    value_string(value, &["transport"]),
  );
  insert_string_path(
    root,
    &["network", "protocol"],
    value_string(value, &["protocol"]),
  );
  insert_tls_fields(root, value);
  if source == AccessLogSource::Waf {
    insert_string_path(root, &["rule", "name"], value_string(value, &["waf_rule"]));
    insert_string_path(root, &["rule", "id"], value_string(value, &["waf_rule_id"]));
  }
  insert_string_path(root, &["oxibelt", "route"], value_string(value, &["route"]));
  insert_string_path(
    root,
    &["oxibelt", "upstream", "name"],
    value_string(value, &["upstream"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "upstream", "pool"],
    value_string(value, &["upstream_pool"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "upstream", "scheme"],
    value_string(value, &["upstream_scheme"]),
  );
  insert_u64_path(
    root,
    &["oxibelt", "upstream", "connect_time_ms"],
    value_u64(value, &["upstream_connect_time_ms"]),
  );
  insert_u64_path(
    root,
    &["oxibelt", "upstream", "first_byte_time_ms"],
    value_u64(value, &["upstream_first_byte_time_ms"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "response", "id"],
    value_string(value, &["response_id"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "transaction", "id"],
    value_string(value, &["transaction_id"]),
  );
}

fn project_admin_fields(root: &mut Map<String, Value>, value: &Value) {
  insert_string_path(
    root,
    &["http", "request", "id"],
    value_string(value, &["request_id"]),
  );
  insert_string_path(
    root,
    &["http", "request", "method"],
    value_string(value, &["method"]),
  );
  insert_u64_path(
    root,
    &["http", "response", "status_code"],
    value_u64(value, &["status"]),
  );
  insert_string_path(root, &["url", "path"], value_string(value, &["path"]));
  insert_string_path(root, &["url", "original"], value_string(value, &["path"]));
  insert_string_path(root, &["url", "scheme"], value_string(value, &["scheme"]));
  insert_string_path(root, &["source", "ip"], value_string(value, &["source_ip"]));
  insert_tls_fields(root, value);
  insert_string_path(root, &["user", "name"], value_string(value, &["actor"]));
  insert_string_path(root, &["user", "id"], value_string(value, &["subject"]));
  if let Some(groups) = value.get("groups").and_then(Value::as_array)
    && !groups.is_empty()
  {
    insert_value(root, &["user", "roles"], Value::Array(groups.clone()));
  }
  insert_string_path(
    root,
    &["oxibelt", "admin", "principal"],
    value_string(value, &["principal"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "admin", "service"],
    value_string(value, &["service"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "admin", "authorization", "action"],
    value_string(value, &["action"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "admin", "authorization", "resource"],
    value_string(value, &["resource"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "admin", "target", "kind"],
    value_string(value, &["target_kind"]),
  );
  insert_string_path(
    root,
    &["oxibelt", "admin", "target", "id"],
    value_string(value, &["target_id"]),
  );
  if let Some(summary) = value.get("request_summary") {
    insert_value(
      root,
      &["oxibelt", "admin", "request_summary"],
      summary.clone(),
    );
  }
}

fn insert_url_fields(root: &mut Map<String, Value>, value: &Value) {
  insert_string_path(root, &["url", "original"], value_string(value, &["uri"]));
  insert_string_path(root, &["url", "path"], value_string(value, &["path"]));
  insert_string_path(root, &["url", "query"], value_string(value, &["query"]));
  insert_string_path(root, &["url", "domain"], value_string(value, &["host"]));
  insert_string_path(root, &["url", "scheme"], value_string(value, &["scheme"]));
}

fn insert_tls_fields(root: &mut Map<String, Value>, value: &Value) {
  if let Some(enabled) = tls_bool(value, "enabled").or_else(|| value_bool(value, &["tls"])) {
    insert_value(root, &["tls", "established"], Value::Bool(enabled));
  }
  if let Some(version) = tls_string(value, "version") {
    insert_string_path(root, &["tls", "version"], normalize_tls_version(&version));
    insert_string_path(root, &["tls", "version_protocol"], Some("tls".to_string()));
  }
  insert_string_path(root, &["tls", "cipher"], tls_cipher_suite(value));
  insert_string_path(
    root,
    &["tls", "client", "server_name"],
    tls_string(value, "sni"),
  );
  insert_string_path(root, &["tls", "next_protocol"], tls_string(value, "alpn"));
  if let Some(fingerprint) = tls_string(value, "fingerprint") {
    if tls_string(value, "fingerprint_scheme")
      .or_else(|| tls_string(value, "fingerprintscheme"))
      .is_some_and(|scheme| scheme.eq_ignore_ascii_case("ja3"))
    {
      insert_string_path(root, &["tls", "client", "ja3"], Some(fingerprint));
    } else {
      insert_string_path(root, &["oxibelt", "tls", "fingerprint"], Some(fingerprint));
    }
  }
  insert_string_path(
    root,
    &["oxibelt", "tls", "fingerprint_scheme"],
    tls_string(value, "fingerprint_scheme").or_else(|| tls_string(value, "fingerprintscheme")),
  );
  if let Some(present) = tls_bool(value, "client_certificate_present")
    .or_else(|| tls_bool(value, "clientcertificatepresent"))
  {
    insert_value(
      root,
      &["oxibelt", "tls", "client_certificate_present"],
      Value::Bool(present),
    );
  }
}

fn tls_cipher_suite(value: &Value) -> Option<String> {
  tls_string(value, "cipher_suite")
    .or_else(|| tls_string(value, "ciphersuite"))
    .or_else(|| tls_string(value, "cipher"))
}

fn tls_string(value: &Value, key: &str) -> Option<String> {
  let top_level = format!("tls_{key}");
  value_string(value, &[&top_level])
    .or_else(|| value_string(value, &["tls", key]))
    .or_else(|| value_string(value, &["request_tls", key]))
}

fn tls_bool(value: &Value, key: &str) -> Option<bool> {
  let top_level = format!("tls_{key}");
  value_bool(value, &[&top_level])
    .or_else(|| value_bool(value, &["tls", key]))
    .or_else(|| value_bool(value, &["request_tls", key]))
}

fn normalize_tls_version(value: &str) -> Option<String> {
  let value = value.trim();
  let value = value
    .strip_prefix("TLSv")
    .or_else(|| value.strip_prefix("tlsv"))
    .or_else(|| value.strip_prefix("TLS"))
    .or_else(|| value.strip_prefix("tls"))
    .unwrap_or(value)
    .replace('_', ".");
  (!value.is_empty()).then_some(value)
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

fn insert_original(root: &mut Map<String, Value>, value: &Value) {
  insert_value(root, &["oxibelt", "access", "original"], value.clone());
}

fn insert_string(object: &mut Map<String, Value>, key: &str, value: Option<String>) {
  if let Some(value) = value {
    object.insert(key.to_string(), Value::String(value));
  }
}

fn insert_string_path(object: &mut Map<String, Value>, path: &[&str], value: Option<String>) {
  if let Some(value) = value {
    insert_value(object, path, Value::String(value));
  }
}

fn insert_u64_path(object: &mut Map<String, Value>, path: &[&str], value: Option<u64>) {
  if let Some(value) = value {
    insert_value(object, path, Value::Number(Number::from(value)));
  }
}

fn insert_value(object: &mut Map<String, Value>, path: &[&str], value: Value) {
  if path.is_empty() {
    return;
  }
  if path.len() == 1 {
    object.insert(path[0].to_string(), value);
    return;
  }
  let child = object
    .entry(path[0].to_string())
    .or_insert_with(|| Value::Object(Map::new()));
  if !child.is_object() {
    *child = Value::Object(Map::new());
  }
  if let Value::Object(child) = child {
    insert_value(child, &path[1..], value);
  }
}

fn string_array(values: Vec<&str>) -> Value {
  Value::Array(
    values
      .into_iter()
      .map(|value| Value::String(value.to_string()))
      .collect(),
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ecs_http_projection_maps_system_access_fields() {
    let record = json!({
      "event": "oxibelt.access",
      "scope": "system",
      "request_id": "req-1",
      "response_id": "resp-1",
      "transaction_id": "tx-1",
      "method": "GET",
      "uri": "/health?ready=1",
      "path": "/health",
      "query": "ready=1",
      "request_version": "2",
      "client_ip": "203.0.113.10",
      "client_port": 32123,
      "status": 200,
      "tls": true,
      "tls_version": "TLSv1_3",
      "tls_cipher_suite": "TLS13_AES_128_GCM_SHA256",
      "tls_alpn": "h2",
      "user_agent": { "values": ["curl/8.0", "duplicate"] },
      "route": "health",
      "upstream": "app"
    });

    let projected = project_ecs(AccessLogSource::System, 42, &record);

    assert_eq!(projected["@timestamp"], json!(42));
    assert_eq!(projected["ecs"]["version"], json!(ECS_VERSION));
    assert_eq!(
      projected["event"]["dataset"],
      json!("oxibelt.access.system")
    );
    assert_eq!(projected["event"]["category"], json!(["web"]));
    assert_eq!(projected["event"]["type"], json!(["access"]));
    assert_eq!(projected["event"]["outcome"], json!("success"));
    assert_eq!(projected["http"]["request"]["method"], json!("GET"));
    assert_eq!(projected["http"]["response"]["status_code"], json!(200));
    assert_eq!(projected["http"]["version"], json!("2"));
    assert_eq!(projected["url"]["path"], json!("/health"));
    assert_eq!(projected["url"]["query"], json!("ready=1"));
    assert_eq!(projected["client"]["ip"], json!("203.0.113.10"));
    assert_eq!(projected["client"]["port"], json!(32123));
    assert_eq!(projected["user_agent"]["original"], json!("curl/8.0"));
    assert_eq!(projected["tls"]["established"], json!(true));
    assert_eq!(projected["tls"]["version"], json!("1.3"));
    assert_eq!(projected["tls"]["version_protocol"], json!("tls"));
    assert_eq!(
      projected["tls"]["cipher"],
      json!("TLS13_AES_128_GCM_SHA256")
    );
    assert_eq!(projected["tls"]["next_protocol"], json!("h2"));
    assert_eq!(projected["oxibelt"]["route"], json!("health"));
    assert_eq!(projected["oxibelt"]["upstream"]["name"], json!("app"));
    assert_eq!(
      projected["oxibelt"]["access"]["original"]["user_agent"]["values"],
      json!(["curl/8.0", "duplicate"])
    );
  }

  #[test]
  fn ecs_waf_projection_adds_security_classification_and_rule() {
    let record = json!({
      "event": "oxibelt.access",
      "scope": "waf",
      "method": "POST",
      "path": "/login",
      "status": 403,
      "waf_rule": "block-login",
      "waf_rule_id": "9001"
    });

    let projected = project_ecs(AccessLogSource::Waf, 99, &record);

    assert_eq!(
      projected["event"]["category"],
      json!(["web", "intrusion_detection"])
    );
    assert_eq!(projected["event"]["type"], json!(["access", "denied"]));
    assert_eq!(projected["event"]["outcome"], json!("failure"));
    assert_eq!(projected["rule"]["name"], json!("block-login"));
    assert_eq!(projected["rule"]["id"], json!("9001"));
    assert_eq!(
      projected["oxibelt"]["access"]["original"]["scope"],
      json!("waf")
    );
  }

  #[test]
  fn ecs_admin_projection_maps_tls_token_and_ipm_fields() {
    let record = json!({
      "event": "oxibelt.admin.access",
      "scope": "admin",
      "request_id": "req-1",
      "actor": "alice",
      "principal": "admin",
      "subject": "sub-1",
      "groups": ["ops"],
      "source_ip": "127.0.0.1",
      "scheme": "https",
      "tls": true,
      "method": "POST",
      "path": "/admin/v1/ipm/credentials",
      "service": "ipm",
      "operation": "post.ipm.credentials",
      "action": "ipm:CreateCredential",
      "resource": "oxibelt:oxibelt:ipm:credential/*",
      "target_kind": "credential",
      "target_id": "cred-1",
      "status": 201,
      "outcome": "applied",
      "request_summary": {
        "body": {
          "json_top_level_keys": ["name"],
          "safe_fields": { "name": "admin-env-token" }
        }
      }
    });

    let projected = project_ecs(AccessLogSource::Admin, 42, &record);

    assert_eq!(projected["event"]["dataset"], json!("oxibelt.access.admin"));
    assert_eq!(projected["event"]["category"], json!(["api", "iam"]));
    assert_eq!(projected["event"]["type"], json!(["admin", "creation"]));
    assert_eq!(projected["event"]["action"], json!("post.ipm.credentials"));
    assert_eq!(projected["event"]["outcome"], json!("success"));
    assert_eq!(projected["source"]["ip"], json!("127.0.0.1"));
    assert_eq!(projected["url"]["scheme"], json!("https"));
    assert_eq!(projected["tls"]["established"], json!(true));
    assert_eq!(projected["user"]["name"], json!("alice"));
    assert_eq!(projected["user"]["id"], json!("sub-1"));
    assert_eq!(projected["user"]["roles"], json!(["ops"]));
    assert_eq!(projected["oxibelt"]["admin"]["principal"], json!("admin"));
    assert_eq!(
      projected["oxibelt"]["admin"]["authorization"]["action"],
      json!("ipm:CreateCredential")
    );
    assert_eq!(
      projected["oxibelt"]["admin"]["authorization"]["resource"],
      json!("oxibelt:oxibelt:ipm:credential/*")
    );
    assert_eq!(
      projected["oxibelt"]["admin"]["request_summary"]["body"]["safe_fields"]["name"],
      json!("admin-env-token")
    );
    assert!(projected.to_string().find("Bearer").is_none());
  }
}
