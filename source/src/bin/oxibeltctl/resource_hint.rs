use serde_json::Value;

pub(crate) fn cache_policy(policy: &str) -> String {
  format!("policy/{}", component(policy))
}

pub(crate) fn cache_host(host: &str) -> String {
  format!("host/{}", component(&oxibelt::routes::normalize_host(host)))
}

pub(crate) fn cache_target(policy: &str, host: Option<&str>) -> Vec<String> {
  vec![
    cache_policy(policy),
    host.map(cache_host).unwrap_or_else(|| "host/*".to_string()),
  ]
}

pub(crate) fn cache_key_explain_target(body: &Value) -> Vec<String> {
  let policy = string_field(body, "policy").unwrap_or("default");
  cache_target(policy, string_field(body, "host"))
}

pub(crate) fn cache_warm_target(body: &Value) -> Vec<String> {
  let mut resources = Vec::new();
  if let Some(items) = body.get("items").and_then(Value::as_array) {
    for item in items {
      let policy = string_field(item, "policy")
        .map(cache_policy)
        .unwrap_or_else(|| "policy/*".to_string());
      push_unique(&mut resources, policy);
      let host = string_field(item, "host")
        .map(cache_host)
        .unwrap_or_else(|| "host/*".to_string());
      push_unique(&mut resources, host);
    }
  }
  if resources.is_empty() {
    resources.push("policy/*".to_string());
    resources.push("host/*".to_string());
  }
  resources
}

pub(crate) fn dynamic_policy_source_name(source: &str, name: &str) -> String {
  format!("source/{}/name/{}", component(source), component(name))
}

pub(crate) fn dynamic_policy_route(route: &str) -> String {
  format!("route/{}", component(route))
}

pub(crate) fn dynamic_policy_status() -> &'static str {
  "status/current"
}

pub(crate) fn dynamic_policy_target(body: &Value) -> Vec<String> {
  let mut resources = Vec::new();
  if let (Some(source), Some(name)) = (string_field(body, "source"), string_field(body, "name")) {
    resources.push(dynamic_policy_source_name(source, name));
  }
  if let Some(route) = string_field(body, "route_name") {
    resources.push(dynamic_policy_route(route));
  }
  if resources.is_empty() {
    resources.push("*".to_string());
  }
  resources
}

pub(crate) fn dynamic_policy_import_target(body: &Value) -> Vec<String> {
  let mut resources = Vec::new();
  if let Some(policies) = body.get("policies").and_then(Value::as_array) {
    for policy in policies {
      for resource in dynamic_policy_target(policy) {
        push_unique(&mut resources, resource);
      }
    }
  }
  if resources.is_empty() {
    resources.push("*".to_string());
  }
  resources
}

pub(crate) fn upstream_pool_server(pool: &str, server_id: &str) -> String {
  format!("{}/server/{}", component(pool), component(server_id))
}

pub(crate) fn upstream_pool_status() -> &'static str {
  "status/current"
}

pub(crate) fn ipm_status() -> &'static str {
  "status/current"
}

pub(crate) fn ipm_principal(id: &str) -> String {
  format!("principal/{}", component(id))
}

pub(crate) fn ipm_credential(id: &str) -> String {
  format!("credential/{}", component(id))
}

pub(crate) fn ipm_policy(name: &str) -> String {
  format!("policy/{}", component(name))
}

pub(crate) fn ipm_binding(id: &str) -> String {
  format!("binding/{}", component(id))
}

pub(crate) fn ipm_group(group: &str) -> String {
  format!("group/{}", component(group))
}

pub(crate) fn ipm_audit() -> &'static str {
  "audit/current"
}

pub(crate) fn ipm_simulation() -> &'static str {
  "simulation/current"
}

pub(crate) fn ipm_policy_create_target(body: &Value) -> String {
  string_field(body, "name")
    .map(ipm_policy)
    .unwrap_or_else(|| "policy/*".to_string())
}

pub(crate) fn ipm_binding_create_target(
  id: Option<&str>,
  principal: Option<&str>,
  group: Option<&str>,
  policy: &str,
) -> Vec<String> {
  let binding_id = id
    .map(str::to_string)
    .unwrap_or_else(|| generated_binding_id(principal, group, policy));
  let mut resources = vec![ipm_binding(&binding_id)];
  if let Some(principal) = principal {
    resources.push(ipm_principal(principal));
  }
  if let Some(group) = group {
    resources.push(ipm_group(group));
  }
  resources.push(ipm_policy(policy));
  unique(resources)
}

pub(crate) fn unique(resources: Vec<String>) -> Vec<String> {
  let mut unique = Vec::new();
  for resource in resources {
    push_unique(&mut unique, resource);
  }
  unique
}

fn generated_binding_id(principal: Option<&str>, group: Option<&str>, policy: &str) -> String {
  match (principal, group) {
    (Some(principal), None) => format!("principal.{principal}.{policy}"),
    (None, Some(group)) => format!("group.{group}.{policy}"),
    _ => format!("binding.{policy}"),
  }
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
  value.get(field).and_then(Value::as_str)
}

fn push_unique(resources: &mut Vec<String>, resource: String) {
  if !resources.iter().any(|existing| existing == &resource) {
    resources.push(resource);
  }
}

fn component(value: &str) -> String {
  let mut encoded = String::with_capacity(value.len());
  for byte in value.bytes() {
    if is_component_byte(byte) {
      encoded.push(char::from(byte));
    } else {
      encoded.push('%');
      encoded.push(hex(byte >> 4));
      encoded.push(hex(byte & 0x0f));
    }
  }
  encoded
}

fn is_component_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

fn hex(value: u8) -> char {
  match value {
    0..=9 => char::from(b'0' + value),
    10..=15 => char::from(b'A' + value - 10),
    _ => unreachable!("hex nibble should be within 0..=15"),
  }
}
