#[cfg(feature = "config-tooling")]
use std::collections::BTreeMap;

use anyhow::{anyhow, bail};
use serde::Serialize;
use serde_json::Value;
#[cfg(feature = "config-tooling")]
use serde_json::{Map, json};

#[cfg(feature = "config-tooling")]
use super::{allowed_config_keys, shape::join_key_path};

pub const NATIVE_CONFIG_SCHEMA_EPOCH: u32 = 1;
pub const NATIVE_CONFIG_REPORT_SCHEMA_VERSION: u32 = 3;

const NATIVE_CONFIG_SCHEMA_JSON: &str =
  include_str!(concat!(env!("OUT_DIR"), "/oxibelt-config-v1.schema.json"));

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeConfigSecretClass {
  None,
  Literal,
  EnvironmentReference,
  FileReference,
  CredentialBearingUrl,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeConfigActivation {
  FullReload,
  OxiRuleReload,
  DownstreamTlsReload,
  RestartRequired,
  Conditional,
  None,
}

#[derive(Debug, Clone, Copy)]
pub struct NativeConfigFieldMetadata {
  pub path: &'static str,
  pub introduced_epoch: u32,
  pub deprecated_epoch: Option<u32>,
  pub replacement: Option<&'static str>,
  pub secret_class: NativeConfigSecretClass,
  pub config_activation: NativeConfigActivation,
  pub reference_activation: NativeConfigActivation,
}

const FIELD_METADATA: &[NativeConfigFieldMetadata] = &[
  deprecated_restart(
    "runtime.hardening.seccomp.mode",
    "runtime.hardening.seccomp.expectation",
  ),
  deprecated("tls.key_exchange_groups", "tls.1_3.key_exchange_groups"),
  deprecated("tls.session_tickets", "tls.resumption.mode"),
  deprecated(
    "tls.session_ticket_rotation_seconds",
    "tls.resumption.rotation_seconds",
  ),
  deprecated(
    "upstream_pools[].health_check.rise",
    "upstream_pools[].health_check.healthy_threshold",
  ),
  deprecated(
    "upstream_pools[].health_check.fall",
    "upstream_pools[].health_check.unhealthy_threshold",
  ),
  secret(
    "admin.bearer_token_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "admin.audit.integrity.hmac_key_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "admin.audit.anchor.signer.token_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "admin.audit.anchor.signer.token_file",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "admin.cache_purge_signing.key_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret_reload(
    "admin.mutations.artifact_key_env",
    NativeConfigSecretClass::EnvironmentReference,
    NativeConfigActivation::RestartRequired,
  ),
  secret(
    "admin.operations.artifact_key_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "admin.rbac.tokens[].bearer_token_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "cache.external_handlers[].token_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "dynamic_policy.automation_api.signature_key_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "external_auth[].client_secret_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "database.mitigation.connection_url",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "database.mitigation.connection_url_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "database.mitigation.tls.client_key",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "shared_state.backends[].connection_url",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "shared_state.backends[].connection_url_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "shared_state.backends[].redis_auth.password_file",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "shared_state.backends[].redis_auth.username_file",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "shared_state.backends[].redis_tls.client_key",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "shared_state.backends[].tls.client_key",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "shared_state.udp_flow_identity_key_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "ipm.credentials[].bearer_token_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "ipm.credentials[].break_glass_access_token_hash",
    NativeConfigSecretClass::Literal,
  ),
  secret("quic.host_key_file", NativeConfigSecretClass::FileReference),
  secret(
    "webrtc_turn_listeners[].auth.rest_shared_secret",
    NativeConfigSecretClass::Literal,
  ),
  secret(
    "webrtc_turn_listeners[].auth.rest_shared_secret_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "webrtc_turn_listeners[].auth.static_credentials[].password",
    NativeConfigSecretClass::Literal,
  ),
  secret(
    "webrtc_turn_listeners[].auth.static_credentials[].password_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "webrtc_turn_listeners[].tls.private_key",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "tls.ocsp.responder_url",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "tls.certificates[].ocsp.responder_url",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "upstreams[].origin",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "upstream_pools[].servers[].origin",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "stream_upstream_pools[].servers[].origin",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "turn_upstream_pools[].servers[].origin",
    NativeConfigSecretClass::CredentialBearingUrl,
  ),
  secret(
    "upstream_pools[].discovery[].token_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret(
    "upstream_pools[].discovery[].token_file",
    NativeConfigSecretClass::FileReference,
  ),
  secret(
    "upstream_pools[].sticky_cookie.secret_env",
    NativeConfigSecretClass::EnvironmentReference,
  ),
  secret_reload(
    "tls.private_key",
    NativeConfigSecretClass::FileReference,
    NativeConfigActivation::DownstreamTlsReload,
  ),
  secret_reload(
    "tls.certificates[].private_key",
    NativeConfigSecretClass::FileReference,
    NativeConfigActivation::DownstreamTlsReload,
  ),
  secret(
    "admin.tls.certificates[].private_key",
    NativeConfigSecretClass::FileReference,
  ),
  secret_reload(
    "tls.remote_signer.token_env",
    NativeConfigSecretClass::EnvironmentReference,
    NativeConfigActivation::DownstreamTlsReload,
  ),
  secret_reload(
    "tls.remote_signer.token_file",
    NativeConfigSecretClass::FileReference,
    NativeConfigActivation::DownstreamTlsReload,
  ),
  full_reload("quic.upstream.resolution"),
  full_reload("quic.upstream.resolution.*"),
  conditional("runtime.main_runtime"),
  conditional("runtime.topology_policy"),
  restart("runtime.worker_threads"),
  conditional("runtime.workers"),
  restart("runtime.workers.tokio"),
  full_reload("runtime.workers.compio_direct_h1"),
  conditional("runtime.worker_multipliers"),
  restart("runtime.worker_multipliers.runtime"),
  restart("runtime.worker_multipliers.tokio"),
  full_reload("runtime.worker_multipliers.compio_direct_h1"),
  secret_restart(
    "runtime.hardening.filesystem_manifest.expected_digest",
    NativeConfigSecretClass::Literal,
  ),
  secret_restart(
    "runtime.hardening.filesystem_manifest.expected_writable_paths",
    NativeConfigSecretClass::Literal,
  ),
  restart("runtime.hardening"),
  restart("runtime.hardening.*"),
  restart("runtime.hot_reload"),
  restart("runtime.hot_reload.*"),
  restart("runtime.netport_switcher"),
  restart("runtime.netport_switcher.*"),
  restart("runtime.unprivileged_mode"),
  restart("crypto"),
  restart("crypto.*"),
  restart("logging.level"),
  restart("metrics.enabled"),
  restart("metrics.bind"),
  restart("health.enabled"),
  restart("health.bind"),
  restart("admin.mutations"),
  restart("admin.mutations.*"),
  restart("admin.audit"),
  restart("admin.audit.*"),
  restart("admin.operations"),
  restart("admin.operations.*"),
  oxirule("waf"),
  oxirule("waf.*"),
  oxirule("routes[].waf"),
  oxirule("routes[].waf.*"),
];

const fn deprecated(path: &'static str, replacement: &'static str) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 0,
    deprecated_epoch: Some(1),
    replacement: Some(replacement),
    secret_class: NativeConfigSecretClass::None,
    config_activation: NativeConfigActivation::FullReload,
    reference_activation: NativeConfigActivation::None,
  }
}

const fn deprecated_restart(
  path: &'static str,
  replacement: &'static str,
) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: Some(1),
    replacement: Some(replacement),
    secret_class: NativeConfigSecretClass::None,
    config_activation: NativeConfigActivation::RestartRequired,
    reference_activation: NativeConfigActivation::None,
  }
}

const fn secret(
  path: &'static str,
  secret_class: NativeConfigSecretClass,
) -> NativeConfigFieldMetadata {
  secret_reload(path, secret_class, NativeConfigActivation::FullReload)
}

const fn secret_reload(
  path: &'static str,
  secret_class: NativeConfigSecretClass,
  reference_activation: NativeConfigActivation,
) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: None,
    replacement: None,
    secret_class,
    config_activation: NativeConfigActivation::FullReload,
    reference_activation,
  }
}

const fn secret_restart(
  path: &'static str,
  secret_class: NativeConfigSecretClass,
) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: None,
    replacement: None,
    secret_class,
    config_activation: NativeConfigActivation::RestartRequired,
    reference_activation: NativeConfigActivation::None,
  }
}

const fn restart(path: &'static str) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: None,
    replacement: None,
    secret_class: NativeConfigSecretClass::None,
    config_activation: NativeConfigActivation::RestartRequired,
    reference_activation: NativeConfigActivation::None,
  }
}

const fn full_reload(path: &'static str) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: None,
    replacement: None,
    secret_class: NativeConfigSecretClass::None,
    config_activation: NativeConfigActivation::FullReload,
    reference_activation: NativeConfigActivation::None,
  }
}

const fn conditional(path: &'static str) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: None,
    replacement: None,
    secret_class: NativeConfigSecretClass::None,
    config_activation: NativeConfigActivation::Conditional,
    reference_activation: NativeConfigActivation::None,
  }
}

const fn oxirule(path: &'static str) -> NativeConfigFieldMetadata {
  NativeConfigFieldMetadata {
    path,
    introduced_epoch: 1,
    deprecated_epoch: None,
    replacement: None,
    secret_class: NativeConfigSecretClass::None,
    config_activation: NativeConfigActivation::OxiRuleReload,
    reference_activation: NativeConfigActivation::OxiRuleReload,
  }
}

pub fn native_config_schema(epoch: u32) -> anyhow::Result<&'static str> {
  if epoch != NATIVE_CONFIG_SCHEMA_EPOCH {
    bail!("unsupported native configuration schema epoch {epoch}");
  }
  Ok(NATIVE_CONFIG_SCHEMA_JSON)
}

pub fn native_config_schema_value(epoch: u32) -> anyhow::Result<Value> {
  serde_json::from_str(native_config_schema(epoch)?)
    .map_err(|error| anyhow!("embedded native configuration schema is invalid: {error}"))
}

pub fn native_config_field_metadata(path: &str) -> NativeConfigFieldMetadata {
  let normalized = normalize_field_path(path);
  FIELD_METADATA
    .iter()
    .find(|metadata| field_pattern_matches(metadata.path, &normalized))
    .copied()
    .unwrap_or(NativeConfigFieldMetadata {
      path: "*",
      introduced_epoch: 1,
      deprecated_epoch: None,
      replacement: None,
      secret_class: NativeConfigSecretClass::None,
      config_activation: NativeConfigActivation::FullReload,
      reference_activation: NativeConfigActivation::None,
    })
}

pub fn normalize_field_path(path: &str) -> String {
  let mut normalized = String::with_capacity(path.len());
  let mut chars = path.chars().peekable();
  while let Some(ch) = chars.next() {
    if ch != '[' {
      normalized.push(ch);
      continue;
    }
    let mut index = String::new();
    while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
      index.push(chars.next().unwrap_or_default());
    }
    if !index.is_empty() && chars.next() == Some(']') {
      normalized.push_str("[]");
    } else {
      normalized.push('[');
      normalized.push_str(&index);
    }
  }
  normalized
}

fn field_pattern_matches(pattern: &str, path: &str) -> bool {
  if pattern == path {
    return true;
  }
  if let Some(prefix) = pattern.strip_suffix(".*") {
    return path.starts_with(prefix);
  }
  false
}

#[cfg(feature = "config-tooling")]
pub fn generate_native_config_schema() -> anyhow::Result<String> {
  let schema = generated_schema_value();
  jsonschema::draft7::meta::validate(&schema)
    .map_err(|error| anyhow!("generated native schema failed Draft 7 meta-validation: {error}"))?;
  let mut rendered = serde_json::to_string_pretty(&schema)?;
  rendered.push('\n');
  Ok(rendered)
}

#[cfg(feature = "config-tooling")]
pub fn validate_native_schema_instance(
  value: &toml::Value,
) -> anyhow::Result<Vec<(String, String, String)>> {
  let schema = native_config_schema_value(NATIVE_CONFIG_SCHEMA_EPOCH)?;
  let instance = serde_json::to_value(value)?;
  let validator = jsonschema::draft7::options()
    .with_pattern_options(jsonschema::PatternOptions::regex())
    .build(&schema)
    .map_err(|error| anyhow!("failed to compile native configuration schema: {error}"))?;
  Ok(
    validator
      .iter_errors(&instance)
      .map(|error| {
        (
          error.instance_path().to_string(),
          error.schema_path().to_string(),
          error.to_string(),
        )
      })
      .collect(),
  )
}

#[cfg(feature = "config-tooling")]
fn generated_schema_value() -> Value {
  let mut root = object_schema("", "");
  if let Some(properties) = root.get_mut("properties").and_then(Value::as_object_mut) {
    properties.insert(
      "include".to_string(),
      json!({
        "description": "Relative native configuration include or include list.",
        "oneOf": [
          {"type": "string"},
          {"type": "array", "items": {"type": "string"}}
        ],
        "x-oxibelt-introduced-epoch": 1,
        "x-oxibelt-path-kind": "config_relative"
      }),
    );
  }
  if let Some(root_object) = root.as_object_mut() {
    root_object.insert(
      "$schema".to_string(),
      json!("http://json-schema.org/draft-07/schema#"),
    );
    root_object.insert(
      "$id".to_string(),
      json!("urn:oxibelt:native-config-schema:v1"),
    );
    root_object.insert(
      "title".to_string(),
      json!("OxiBelt native configuration v1"),
    );
    root_object.insert("x-oxibelt-schema-version".to_string(), json!(1));
    root_object.insert(
      "x-oxibelt-semantic-validator".to_string(),
      json!("Config::load + Config::validate"),
    );
    root_object.insert("required".to_string(), json!(["listeners", "tls"]));
  }
  root
}

#[cfg(feature = "config-tooling")]
fn object_schema(shape_path: &str, metadata_path: &str) -> Value {
  let keys = allowed_config_keys(shape_path).unwrap_or_default();
  let properties = keys
    .into_iter()
    .map(|key| {
      let child_shape_path = join_key_path(shape_path, key);
      let child_metadata_path = join_key_path(metadata_path, key);
      (
        key.to_string(),
        schema_for_path(&child_shape_path, &child_metadata_path),
      )
    })
    .collect::<Map<_, _>>();
  let mut schema = json!({
    "type": "object",
    "additionalProperties": false,
    "properties": properties,
  });
  if is_subject_alt_names_path(shape_path)
    && let Some(object) = schema.as_object_mut()
  {
    object.insert("required".to_string(), json!(["type", "value"]));
  }
  schema
}

#[cfg(feature = "config-tooling")]
fn schema_for_path(shape_path: &str, metadata_path: &str) -> Value {
  let metadata = native_config_field_metadata(metadata_path);
  let mut schema = if is_array_path(shape_path) {
    let item_metadata_path = format!("{metadata_path}[]");
    let items = if allowed_config_keys(shape_path).is_some() {
      object_schema(shape_path, &item_metadata_path)
    } else {
      scalar_schema(shape_path)
    };
    json!({"type": "array", "items": items})
  } else if allowed_config_keys(shape_path).is_some() {
    object_schema(shape_path, metadata_path)
  } else {
    scalar_schema(shape_path)
  };
  let Some(object) = schema.as_object_mut() else {
    return schema;
  };
  object.insert(
    "description".to_string(),
    json!(format!(
      "OxiBelt native field `{metadata_path}`. Production Rust validation is authoritative."
    )),
  );
  object.insert(
    "x-oxibelt-introduced-epoch".to_string(),
    json!(metadata.introduced_epoch),
  );
  object.insert(
    "x-oxibelt-secret-class".to_string(),
    json!(metadata.secret_class),
  );
  object.insert(
    "x-oxibelt-config-activation".to_string(),
    json!(metadata.config_activation),
  );
  object.insert(
    "x-oxibelt-reference-activation".to_string(),
    json!(metadata.reference_activation),
  );
  if let Some(epoch) = metadata.deprecated_epoch {
    object.insert("deprecated".to_string(), Value::Bool(true));
    object.insert("x-oxibelt-deprecated-epoch".to_string(), json!(epoch));
  }
  if let Some(replacement) = metadata.replacement {
    object.insert("x-oxibelt-replacement".to_string(), json!(replacement));
  }
  if let Some(default) = default_value(shape_path) {
    object.insert("default".to_string(), default);
  }
  if let Some(path_kind) = path_kind(shape_path) {
    object.insert("x-oxibelt-path-kind".to_string(), json!(path_kind));
  }
  if is_subject_alt_names_path(shape_path) {
    object.insert("maxItems".to_string(), json!(5));
  }
  if shape_path == "upstream_pools.discovery" {
    object.insert("maxItems".to_string(), json!(64));
  }
  if is_subject_alt_name_value_path(shape_path) {
    object.insert("minLength".to_string(), json!(1));
    object.insert("maxLength".to_string(), json!(253));
  }
  schema
}

#[cfg(feature = "config-tooling")]
fn scalar_schema(path: &str) -> Value {
  if let Some(values) = enum_values(path) {
    return json!({"type": "string", "enum": values});
  }
  if let Some((minimum, maximum)) = bounded_integer_range(path) {
    return json!({"type": "integer", "minimum": minimum, "maximum": maximum});
  }
  if auto_integer_path(path) {
    return json!({
      "oneOf": [
        {"type": "integer", "minimum": 1},
        {"type": "string", "const": "auto"}
      ]
    });
  }
  if boolean_path(path) {
    return json!({"type": "boolean"});
  }
  if number_array_path(path) {
    return json!({"type": "array", "items": {"type": "number"}});
  }
  if integer_path(path) {
    return json!({"type": "integer", "minimum": 0});
  }
  if string_array_path(path) {
    return json!({"type": "array", "items": {"type": "string"}});
  }
  if string_path(path) {
    return json!({"type": "string"});
  }
  json!({
    "anyOf": [
      {"type": "string"},
      {"type": "integer"},
      {"type": "number"},
      {"type": "boolean"},
      {"type": "array"},
      {"type": "object"}
    ]
  })
}

#[cfg(feature = "config-tooling")]
fn bounded_integer_range(path: &str) -> Option<(u64, u64)> {
  let range = match path {
    "quic.upstream.resolution.max_endpoint_count" => (1, 64),
    "quic.upstream.resolution.min_ttl_ms" | "quic.upstream.resolution.max_ttl_ms" => (1, 3_600_000),
    "quic.upstream.resolution.negative_ttl_ms" => (1, 30_000),
    "quic.upstream.resolution.address_family_stagger_ms" => (10, 5_000),
    "quic.upstream.resolution.max_connect_attempts" => (1, 16),
    "quic.upstream.resolution.cooldown_base_ms" | "quic.upstream.resolution.cooldown_max_ms" => {
      (1, 300_000)
    }
    "upstream_pools.discovery.weight_multiplier" => (1, u64::from(u32::MAX)),
    "routes.actions.request_mirrors.max_body_bytes" => {
      (0, super::MAX_REQUEST_MIRROR_BODY_BYTES as u64)
    }
    "sni_forward.quic_initial_reassembly.max_pending_sessions"
    | "sni_forward.quic_initial_reassembly.max_fragments_per_session"
    | "sni_forward.quic_initial_reassembly.max_datagrams_per_session"
    | "sni_forward.quic_initial_reassembly.max_buffered_datagram_bytes_per_session"
    | "sni_forward.quic_initial_reassembly.max_total_buffered_bytes"
    | "sni_forward.quic_initial_reassembly.timeout_ms" => (1, u64::MAX),
    _ => return None,
  };
  Some(range)
}

#[cfg(feature = "config-tooling")]
fn is_array_path(path: &str) -> bool {
  const ARRAYS: &[&str] = &[
    "admin.mutations.signers",
    "admin.tls.certificates",
    "cache.external_handlers",
    "cache.policies",
    "cache.policies.rules",
    "compression.policies",
    "connection_limits",
    "external_auth",
    "ipm.bindings",
    "ipm.credentials",
    "ipm.policies",
    "ipm.policies.statements",
    "ipm.principals",
    "logging.access_log.fields",
    "rate_limits",
    "routes",
    "routes.actions.request_mirrors",
    "security.header_policies",
    "sni_forward.rules",
    "stream_listeners",
    "stream_listeners.sni_rules",
    "stream_upstream_pools",
    "stream_upstream_pools.servers",
    "tls.certificates",
    "turn_upstream_pools",
    "turn_upstream_pools.servers",
    "upstream_pools",
    "upstream_pools.discovery",
    "upstream_pools.discovery.tls.subject_alt_names",
    "upstream_pools.servers",
    "upstream_pools.servers.tls.subject_alt_names",
    "upstreams",
    "upstreams.tls.subject_alt_names",
    "webrtc_turn_listeners",
    "webrtc_turn_listeners.auth.static_credentials",
    "webrtc_turn_listeners.relay_families",
  ];
  ARRAYS.contains(&path)
}

#[cfg(feature = "config-tooling")]
fn boolean_path(path: &str) -> bool {
  path.rsplit('.').next().is_some_and(|name| {
    name == "enabled"
      || name == "reuse_port"
      || name.starts_with("allow_")
      || name.starts_with("reject_")
      || name.starts_with("require_")
      || name.starts_with("strict_")
      || (name.starts_with("verify_") && name != "verify_depth")
  })
}

#[cfg(feature = "config-tooling")]
fn auto_integer_path(path: &str) -> bool {
  matches!(
    path,
    "runtime.worker_threads"
      | "runtime.workers.tokio"
      | "runtime.workers.compio_direct_h1"
      | "runtime.accept.workers"
      | "quic.socket.workers"
  )
}

#[cfg(feature = "config-tooling")]
fn number_array_path(path: &str) -> bool {
  matches!(path, "metrics.histogram_buckets_ms")
}

#[cfg(feature = "config-tooling")]
fn integer_path(path: &str) -> bool {
  path.rsplit('.').next().is_some_and(|name| {
    [
      "_bytes",
      "_capacity",
      "_count",
      "_depth",
      "_interval_ms",
      "_ms",
      "_port",
      "_seconds",
      "_size",
      "_threads",
      "_timeout_ms",
      "_tries",
      "_workers",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
  })
}

#[cfg(feature = "config-tooling")]
fn string_array_path(path: &str) -> bool {
  if matches!(
    path,
    "external_auth.allowed_content_types"
      | "runtime.hardening.filesystem_manifest.expected_writable_paths"
  ) {
    return true;
  }
  path.rsplit('.').next().is_some_and(|name| {
    name.ends_with("_binds")
      || name.ends_with("_certs")
      || name.ends_with("_cidrs")
      || name.ends_with("_groups")
      || name.ends_with("_names")
  })
}

#[cfg(feature = "config-tooling")]
fn string_path(path: &str) -> bool {
  matches!(
    path,
    "runtime.hardening.filesystem_manifest.expected_digest"
      | "upstream_pools.discovery.id"
      | "upstream_pools.discovery.tls.subject_alt_names.value"
      | "upstream_pools.servers.tls.subject_alt_names.value"
      | "upstreams.tls.subject_alt_names.value"
  )
}

#[cfg(feature = "config-tooling")]
fn is_subject_alt_names_path(path: &str) -> bool {
  matches!(
    path,
    "upstream_pools.discovery.tls.subject_alt_names"
      | "upstream_pools.servers.tls.subject_alt_names"
      | "upstreams.tls.subject_alt_names"
  )
}

#[cfg(feature = "config-tooling")]
fn is_subject_alt_name_value_path(path: &str) -> bool {
  matches!(
    path,
    "upstream_pools.discovery.tls.subject_alt_names.value"
      | "upstream_pools.servers.tls.subject_alt_names.value"
      | "upstreams.tls.subject_alt_names.value"
  )
}

#[cfg(feature = "config-tooling")]
fn enum_values(path: &str) -> Option<Vec<&'static str>> {
  let values = BTreeMap::from([
    ("access_log.otlp.schema", vec!["ocsf", "ecs"]),
    ("access_log.stdout.schema", vec!["ocsf", "ecs"]),
    (
      "config.lb_policy_compat_profile",
      vec!["strict", "nginx", "caddy"],
    ),
    ("crypto.primitive_provider", vec!["rustcrypto", "aws_lc_rs"]),
    ("crypto.tls_provider", vec!["aws_lc_rs", "ring"]),
    (
      "listeners.http_mode",
      vec!["off", "redirect_to_https", "proxy"],
    ),
    ("listeners.proxy_protocol.version", vec!["any", "v1", "v2"]),
    (
      "runtime.direct_h1_io",
      vec!["auto", "tokio_hyper", "compio"],
    ),
    (
      "runtime.hardening.close_range",
      vec!["auto", "off", "required"],
    ),
    (
      "runtime.hardening.landlock.mode",
      vec!["off", "enforce", "manifest"],
    ),
    (
      "runtime.hardening.seccomp.expectation",
      vec!["off", "optional", "required"],
    ),
    (
      "runtime.hardening.seccomp.mode",
      vec!["off", "log", "enforce"],
    ),
    (
      "runtime.hot_reload.mode",
      vec!["off", "oxirule", "downstream_tls", "full"],
    ),
    (
      "runtime.main_runtime",
      vec!["hybrid_compio", "tokio_hyper", "auto", "compio"],
    ),
    (
      "runtime.topology_policy",
      vec!["allow_fallback", "require_exact"],
    ),
    (
      "shared_state.failure_policies.udp_flows",
      vec!["reject_new_only"],
    ),
    (
      "stream_listeners.udp_flow_state",
      vec!["local", "shared_required"],
    ),
    ("tls.min_version", vec!["tls1.2", "tls1.3"]),
    ("tls.max_version", vec!["tls1.2", "tls1.3"]),
    ("tls.resumption.mode", vec!["off", "stateful", "stateless"]),
    ("tls.ssl_early_data", vec!["off", "safe_methods", "on"]),
    (
      "upstream_pools.discovery.tls.subject_alt_names.type",
      vec!["dns", "uri"],
    ),
    (
      "upstream_pools.servers.tls.subject_alt_names.type",
      vec!["dns", "uri"],
    ),
    ("upstreams.tls.subject_alt_names.type", vec!["dns", "uri"]),
    (
      "upstream_pools.algorithm",
      vec![
        "power_of_two_choices",
        "weighted_least_conn",
        "rendezvous_hash",
        "rendezvous_ip_hash",
        "ewma",
        "least_time",
        "sticky_cookie",
      ],
    ),
  ]);
  values.get(path).cloned()
}

#[cfg(feature = "config-tooling")]
fn default_value(path: &str) -> Option<Value> {
  let value = match path {
    "access_log.otlp.schema" | "access_log.stdout.schema" => json!("ocsf"),
    "config.lb_policy_compat_profile" => json!("strict"),
    "config.strict_unknown_fields" | "config.warn_on_deprecated_fields" => json!(true),
    "logging.level" => json!("info"),
    "runtime.direct_h1_io" => json!("auto"),
    "runtime.hot_reload.mode" => json!("off"),
    "runtime.main_runtime" => json!("hybrid_compio"),
    "runtime.topology_policy" => json!("allow_fallback"),
    "runtime.worker_threads" => json!("auto"),
    "runtime.workers.tokio" | "runtime.workers.compio_direct_h1" => json!("auto"),
    "runtime.worker_multipliers.runtime"
    | "runtime.worker_multipliers.tokio"
    | "runtime.worker_multipliers.compio_direct_h1" => json!(1.0),
    "shared_state.failure_policies.udp_flows" => json!("reject_new_only"),
    "shared_state.udp_flow_identity_key_env" => json!("OXIBELT_UDP_FLOW_IDENTITY_KEY"),
    "sni_forward.quic_initial_reassembly.max_pending_sessions" => json!(64),
    "sni_forward.quic_initial_reassembly.max_fragments_per_session" => json!(64),
    "sni_forward.quic_initial_reassembly.max_datagrams_per_session" => json!(64),
    "sni_forward.quic_initial_reassembly.max_buffered_datagram_bytes_per_session" => {
      json!(131_072)
    }
    "sni_forward.quic_initial_reassembly.max_total_buffered_bytes" => json!(4_194_304),
    "sni_forward.quic_initial_reassembly.timeout_ms" => json!(10_000),
    "stream_listeners.udp_flow_state" => json!("local"),
    "upstream_pools.discovery.weight_multiplier" => json!(1),
    "quic.upstream.resolution.address_family_stagger_ms" => json!(250),
    "quic.upstream.resolution.cooldown_base_ms" => json!(1_000),
    "quic.upstream.resolution.cooldown_max_ms" => json!(30_000),
    "quic.upstream.resolution.max_connect_attempts" => json!(4),
    "quic.upstream.resolution.max_endpoint_count" => json!(16),
    "quic.upstream.resolution.max_ttl_ms" => json!(30_000),
    "quic.upstream.resolution.min_ttl_ms" => json!(1_000),
    "quic.upstream.resolution.negative_ttl_ms" => json!(1_000),
    "tls.max_version" | "tls.min_version" => json!("tls1.3"),
    "tls.ssl_early_data" => json!("off"),
    _ => return None,
  };
  Some(value)
}

#[cfg(feature = "config-tooling")]
fn path_kind(path: &str) -> Option<&'static str> {
  if path == "tls.cert_chain"
    || path == "tls.private_key"
    || path.starts_with("tls.certificates.")
    || path == "tls.client_auth.ca_certs"
    || path.ends_with(".trusted_ca_certs")
  {
    return Some("cert_relative");
  }
  if path.ends_with(".rule_files")
    || path.ends_with(".rule_group_files")
    || path.ends_with(".rulepack_files")
  {
    return Some("oxirule_relative");
  }
  None
}

#[cfg(test)]
mod tests;
