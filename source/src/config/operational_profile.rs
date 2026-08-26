//! Built-in operational profiles.
//!
//! Profiles are compiled into the binary so selecting a security baseline does
//! not introduce a second configuration supply chain.  They fill only missing
//! configuration values; site-specific values remain explicit in operator TOML.

use std::collections::BTreeSet;

use anyhow::{Context, anyhow, bail};

use crate::waf::{
  RouteWafHttpBodyCompressionMode, WafDuplicateMetadataPolicy, WafFailPolicy,
  WafHttpBodyCompressionMode, WafMode,
};

use super::{
  AdminAuditMode, AdminAuditRequiredSink, AdminTransportMode, Config, ForwardedClientIpSource,
  ForwardedHeaderMode, HardeningAutoMode, LbPolicyCompatProfile, MetricsDetail, QuicZeroRttMode,
  RedisPlaintextPolicy, RuntimeLandlockMode, RuntimeSeccompExpectation, TlsClientAuthMode,
  TlsEarlyDataMode, TlsVersion, TrailerMode,
};

const EDGE_SECURE_MEDIUM_NAME: &str = "edge-secure-medium";
const EDGE_SECURE_MEDIUM_VERSION: u32 = 1;
const EDGE_SECURE_MEDIUM_V2_VERSION: u32 = 2;
const EDGE_SECURE_MEDIUM_MAX_REQUEST_BODY_BYTES: u64 = 10 * 1024 * 1024;
const EDGE_SECURE_MEDIUM_MAX_CONNECTIONS: usize = 65_536;
const EDGE_SECURE_MEDIUM_MAX_CONNECTIONS_PER_IP: usize = 128;
const EDGE_SECURE_MEDIUM_MAX_WEBTRANSPORT_SESSIONS_PER_CONNECTION: usize = 256;
const EDGE_SECURE_MEDIUM_MAX_REQUESTS_PER_CONNECTION: usize = 1_000;
const EDGE_SECURE_MEDIUM_MAX_HEADERS: usize = 128;
const EDGE_SECURE_MEDIUM_MAX_HEADER_NAME_BYTES: usize = 128;
const EDGE_SECURE_MEDIUM_MAX_HEADER_VALUE_BYTES: usize = 8_192;
const EDGE_SECURE_MEDIUM_MAX_TOTAL_HEADER_BYTES: usize = 65_536;
const EDGE_SECURE_MEDIUM_MAX_URI_BYTES: usize = 8_192;
const EDGE_SECURE_MEDIUM_MAX_H2_STREAMS: u32 = 1_024;
const EDGE_SECURE_MEDIUM_MAX_QUIC_STREAMS: u64 = 512;
const EDGE_SECURE_MEDIUM_MAX_WAF_RULE_RUNTIME_MS: u64 = 5;
const EDGE_SECURE_MEDIUM_MAX_TOTAL_WAF_RUNTIME_MS: u64 = 20;
const EDGE_SECURE_MEDIUM_MAX_WAF_EXPRESSION_STEPS: usize = 2_000;
const EDGE_SECURE_MEDIUM_MAX_WAF_MEMORY_BYTES: usize = 262_144;
const EDGE_SECURE_MEDIUM_MAX_WAF_STRING_BYTES: usize = 8_192;
const EDGE_SECURE_MEDIUM_MAX_WAF_BODY_INSPECTION_BYTES: usize = 1_048_576;
const EDGE_SECURE_MEDIUM_MAX_WAF_HEADER_COUNT: usize = 128;
const EDGE_SECURE_MEDIUM_MAX_WAF_HEADER_VALUE_BYTES: usize = 8_192;
const EDGE_SECURE_MEDIUM_MAX_WAF_MUTATIONS: usize = 32;
const EDGE_SECURE_MEDIUM_MAX_WAF_REGEX_RUNTIME_MS: u64 = 2;
const EDGE_SECURE_MEDIUM_MAX_ADVANCED_REGEX_SUBJECT_BYTES: usize = 65_536;
const EDGE_SECURE_MEDIUM_MAX_ADVANCED_REGEX_BACKTRACKS: usize = 100_000;
const EDGE_SECURE_MEDIUM_MAX_WAF_HELPER_ITEMS: usize = 128;
const EDGE_SECURE_MEDIUM_MAX_WAF_HELPER_PATTERN_COUNT: usize = 32;
const EDGE_SECURE_MEDIUM_MAX_WAF_HELPER_RESULT_BYTES: usize = 8_192;
const EDGE_SECURE_MEDIUM_MAX_WAF_PERSON_PROOF_REUSE_TOKENS: usize = 4_096;
const EDGE_SECURE_MEDIUM_MAX_WAF_BODY_EXPANSION_RATIO: usize = 20;
const EDGE_SECURE_MEDIUM_MAX_WAF_BODY_DECODE_TIMEOUT_MS: u64 = 1_000;
const EDGE_SECURE_MEDIUM_MIN_SHUTDOWN_DELAY_MS: u64 = 10_000;
const EDGE_SECURE_MEDIUM_MIN_GRACEFUL_DRAIN_MS: u64 = 30_000;
const EDGE_SECURE_MEDIUM_MIN_LONG_CONNECTION_DRAIN_MS: u64 = 300_000;

const EDGE_SECURE_MEDIUM_V1_DEFAULTS: &str = r#"
[config]
strict_unknown_fields = true
warn_on_deprecated_fields = true
lb_policy_compat_profile = "strict"

[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true

[runtime.drain]
shutdown_delay_ms = 10000
graceful_timeout_ms = 30000
long_connection_close_delay_ms = 300000

[tls]
min_version = "tls1.3"
max_version = "tls1.3"
require_sni = true
reject_unknown_sni = true
ssl_early_data = "off"

[quic]
retry = true
zero_rtt = "off"

[quic.transport]
max_concurrent_bidi_streams = 512
max_concurrent_uni_streams = 512

[proxy.forwarded_headers]
mode = "overwrite"
client_ip_source = "resolved"

[proxy.real_ip]
enabled = false
fail_on_untrusted_forwarded_headers = true

[proxy.http]
trailers = "drop"

[proxy.http2]
max_concurrent_streams = 1024

[limits]
max_connections = 65536
max_connections_per_ip = 128
max_webtransport_sessions = 65536
max_webtransport_sessions_per_ip = 128
max_webtransport_sessions_per_connection = 256
max_requests_per_connection = 1000
max_headers = 128
max_header_name_bytes = 128
max_header_value_bytes = 8192
max_total_header_bytes = 65536
max_uri_bytes = 8192
max_request_body_bytes = 10485760

[waf]
mode = "enforcing"
fail_policy = "closed"
duplicate_metadata_policy = "fail_closed"

[waf.http_body_compression]
mode = "transform"
max_decoded_body_bytes = 10485760
max_expansion_ratio = 20
decode_timeout_ms = 1000

[waf.limits]
max_rule_runtime_ms = 5
max_total_waf_runtime_ms = 20
max_expression_steps = 2000
max_memory_bytes = 262144
max_string_bytes = 8192
max_body_inspection_bytes = 1048576
max_header_count = 128
max_header_value_bytes = 8192
max_mutations = 32
max_regex_runtime_ms = 2
max_advanced_regex_subject_bytes = 65536
max_advanced_regex_backtracks = 100000
max_helper_items = 128
max_helper_pattern_count = 32
max_helper_result_bytes = 8192
max_person_proof_reuse_tokens = 4096

[access_log.system]
enabled = true

[access_log.admin]
enabled = true

[access_log.waf]
enabled = true

[admin]
enabled = false

[metrics]
enabled = true
detail = "detailed"

[health]
enabled = true

[overload]
enabled = true

[circuit_breakers]
enabled = true

[shared_state]
redis_plaintext_policy = "deny"
"#;

const EDGE_SECURE_MEDIUM_V2_DEFAULTS: &str = r#"
[runtime.hardening]
close_range = "required"

[runtime.hardening.seccomp]
expectation = "required"

[runtime.hardening.landlock]
mode = "manifest"
"#;

const EDGE_SECURE_MEDIUM_V1_DEFAULT_LAYERS: &[&str] = &[EDGE_SECURE_MEDIUM_V1_DEFAULTS];
const EDGE_SECURE_MEDIUM_V2_DEFAULT_LAYERS: &[&str] = &[
  EDGE_SECURE_MEDIUM_V1_DEFAULTS,
  EDGE_SECURE_MEDIUM_V2_DEFAULTS,
];

struct BuiltInProfileDefinition {
  name: &'static str,
  version: u32,
  default_layers: &'static [&'static str],
  validate: fn(&Config, &OperationalProfile) -> anyhow::Result<()>,
}

const BUILTIN_PROFILE_CATALOG: &[BuiltInProfileDefinition] = &[
  BuiltInProfileDefinition {
    name: EDGE_SECURE_MEDIUM_NAME,
    version: EDGE_SECURE_MEDIUM_VERSION,
    default_layers: EDGE_SECURE_MEDIUM_V1_DEFAULT_LAYERS,
    validate: validate_edge_secure_medium_v1,
  },
  BuiltInProfileDefinition {
    name: EDGE_SECURE_MEDIUM_NAME,
    version: EDGE_SECURE_MEDIUM_V2_VERSION,
    default_layers: EDGE_SECURE_MEDIUM_V2_DEFAULT_LAYERS,
    validate: validate_edge_secure_medium_v2,
  },
];

/// The selected built-in operational profile and the operator-provided paths
/// that were present before profile expansion.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OperationalProfile {
  name: &'static str,
  version: u32,
  explicit_paths: BTreeSet<String>,
}

impl OperationalProfile {
  pub fn name(&self) -> &'static str {
    self.name
  }

  pub fn version(&self) -> u32 {
    self.version
  }

  pub fn explicitly_sets(&self, path: &str) -> bool {
    self.explicit_paths.contains(path)
  }
}

/// Resolves a profile selector and fills missing values with its immutable
/// built-in defaults.  Existing values are never overwritten.
pub(super) fn apply_to_toml(value: &mut toml::Value) -> anyhow::Result<Option<OperationalProfile>> {
  let table = value
    .as_table()
    .ok_or_else(|| anyhow!("configuration root must be a TOML table"))?;
  let profile_name = match table.get("profile") {
    None => {
      if table.contains_key("profile_version") {
        bail!("profile_version requires profile");
      }
      return Ok(None);
    }
    Some(toml::Value::String(name)) => name.as_str(),
    Some(_) => bail!("profile must be a string"),
  };
  let version = match table.get("profile_version") {
    None => EDGE_SECURE_MEDIUM_VERSION,
    Some(toml::Value::Integer(value)) if *value > 0 => u32::try_from(*value)
      .map_err(|_| anyhow!("profile_version must be a positive 32-bit integer"))?,
    Some(_) => bail!("profile_version must be a positive integer"),
  };
  let definition = find_builtin_profile(profile_name, version).ok_or_else(|| {
    let supported = BUILTIN_PROFILE_CATALOG
      .iter()
      .map(|entry| format!("{:?} version {}", entry.name, entry.version))
      .collect::<Vec<_>>()
      .join(", ");
    anyhow!(
      "unsupported operational profile {profile_name:?} version {version}; supported profiles: {supported}"
    )
  })?;

  if profile_name != definition.name || version != definition.version {
    bail!(
      "operational profile lookup returned an inconsistent definition for {profile_name:?} version {version}"
    );
  }

  let mut explicit_paths = BTreeSet::new();
  collect_explicit_paths(value, "", &mut explicit_paths);
  for (layer_index, raw_defaults) in definition.default_layers.iter().enumerate() {
    let defaults: toml::Value = toml::from_str(raw_defaults).with_context(|| {
      format!(
        "built-in operational profile {} v{} defaults layer {} must be valid TOML",
        definition.name,
        definition.version,
        layer_index + 1
      )
    })?;
    fill_missing_values(value, &defaults)?;
  }
  let Some(root) = value.as_table_mut() else {
    bail!("configuration root must be a table after profile expansion");
  };
  root.insert(
    "profile_version".to_string(),
    toml::Value::Integer(i64::from(definition.version)),
  );

  Ok(Some(OperationalProfile {
    name: definition.name,
    version: definition.version,
    explicit_paths,
  }))
}

fn find_builtin_profile(name: &str, version: u32) -> Option<&'static BuiltInProfileDefinition> {
  BUILTIN_PROFILE_CATALOG
    .iter()
    .find(|entry| entry.name == name && entry.version == version)
}

fn collect_explicit_paths(value: &toml::Value, path: &str, paths: &mut BTreeSet<String>) {
  match value {
    toml::Value::Table(values) => {
      for (key, value) in values {
        let child = if path.is_empty() {
          key.clone()
        } else {
          format!("{path}.{key}")
        };
        collect_explicit_paths(value, &child, paths);
      }
    }
    toml::Value::Array(_)
    | toml::Value::String(_)
    | toml::Value::Integer(_)
    | toml::Value::Float(_)
    | toml::Value::Boolean(_)
    | toml::Value::Datetime(_) => {
      paths.insert(path.to_string());
    }
  }
}

fn fill_missing_values(target: &mut toml::Value, defaults: &toml::Value) -> anyhow::Result<()> {
  let (toml::Value::Table(target), toml::Value::Table(defaults)) = (target, defaults) else {
    bail!("operational profile defaults must have a TOML table root");
  };
  for (key, default_value) in defaults {
    match target.get_mut(key) {
      Some(existing) if existing.is_table() && default_value.is_table() => {
        fill_missing_values(existing, default_value)?;
      }
      Some(_) => {}
      None => {
        target.insert(key.clone(), default_value.clone());
      }
    }
  }
  Ok(())
}

pub(super) fn validate(config: &Config) -> anyhow::Result<()> {
  let Some(profile) = config.operational_profile.as_ref() else {
    return Ok(());
  };
  let definition = find_builtin_profile(profile.name, profile.version).ok_or_else(|| {
    anyhow!(
      "active operational profile {:?} version {} is not built into this binary",
      profile.name,
      profile.version
    )
  })?;
  (definition.validate)(config, profile)
}

fn validate_edge_secure_medium_v1(
  config: &Config,
  profile: &OperationalProfile,
) -> anyhow::Result<()> {
  validate_configuration_and_runtime(config)?;
  validate_tls(config)?;
  validate_limits(config)?;
  validate_proxy_and_identity(config)?;
  validate_waf(config, profile)?;
  validate_operations(config)?;
  validate_admin(config)?;
  validate_rulepacks(config)?;
  Ok(())
}

fn validate_edge_secure_medium_v2(
  config: &Config,
  profile: &OperationalProfile,
) -> anyhow::Result<()> {
  // Keep the v1 validator and its diagnostics immutable. Version 2 is an
  // additive deployment-hardening contract over that established baseline.
  validate_edge_secure_medium_v1(config, profile)?;

  if config.runtime.hardening.close_range != HardeningAutoMode::Required
    || config.runtime.hardening.seccomp.expectation != RuntimeSeccompExpectation::Required
    || config.runtime.hardening.landlock.mode != RuntimeLandlockMode::Manifest
  {
    bail!(
      "edge-secure-medium v2 requires close_range, external seccomp verification, and manifest-derived Landlock enforcement"
    );
  }
  if !config
    .runtime
    .hardening
    .filesystem_manifest
    .expectation_configured()
  {
    bail!(
      "edge-secure-medium v2 requires runtime.hardening.filesystem_manifest.expected_digest and expected_writable_paths"
    );
  }
  if !config.runtime.hardening.landlock.read_paths.is_empty()
    || !config
      .runtime
      .hardening
      .landlock
      .read_write_paths
      .is_empty()
  {
    bail!(
      "edge-secure-medium v2 forbids manual Landlock path additions outside the generated filesystem manifest"
    );
  }
  Ok(())
}

fn validate_configuration_and_runtime(config: &Config) -> anyhow::Result<()> {
  if !config.config.strict_unknown_fields
    || !config.config.warn_on_deprecated_fields
    || config.config.lb_policy_compat_profile != LbPolicyCompatProfile::Strict
  {
    bail!(
      "edge-secure-medium v1 requires strict configuration parsing and canonical compatibility behavior"
    );
  }
  if !config.runtime.linux_only
    || !config.runtime.read_only_rootfs_compatible
    || !config.runtime.memory_only_state
    || !config.runtime.unprivileged_mode
  {
    bail!(
      "edge-secure-medium v1 requires the Linux, read-only, memory-only, and unprivileged runtime hardening baseline"
    );
  }
  Ok(())
}

fn validate_tls(config: &Config) -> anyhow::Result<()> {
  if config.tls.min_version != TlsVersion::Tls13 || config.tls.max_version != TlsVersion::Tls13 {
    bail!("edge-secure-medium v1 requires tls.min_version and tls.max_version to be tls1.3");
  }
  if !config.tls.require_sni || !config.tls.reject_unknown_sni {
    bail!("edge-secure-medium v1 requires tls.require_sni and tls.reject_unknown_sni");
  }
  if config.tls.ssl_early_data != Some(TlsEarlyDataMode::Off) {
    bail!("edge-secure-medium v1 requires tls.ssl_early_data = \"off\"");
  }
  let mut names = config.tls.server_names.iter().chain(
    config
      .tls
      .certificates
      .iter()
      .flat_map(|certificate| certificate.server_names.iter()),
  );
  if !names.clone().any(|name| !name.is_empty()) || names.any(|name| name == "*") {
    bail!("edge-secure-medium v1 requires explicit non-wildcard public TLS server names");
  }
  if !config.quic.retry || config.quic.zero_rtt != QuicZeroRttMode::Off {
    bail!("edge-secure-medium v1 requires QUIC Retry and disables QUIC 0-RTT");
  }
  if config.listeners.http3 && config.quic.host_key_file.is_none() {
    bail!("edge-secure-medium v1 requires quic.host_key_file when listeners.http3 is enabled");
  }
  for route in &config.routes {
    if route
      .tls
      .min_version
      .is_some_and(|version| version != TlsVersion::Tls13)
      || route
        .tls
        .max_version
        .is_some_and(|version| version != TlsVersion::Tls13)
      || route
        .tls
        .ssl_early_data
        .is_some_and(|mode| mode != TlsEarlyDataMode::Off)
    {
      bail!(
        "edge-secure-medium v1 forbids TLS or early-data downgrades on route {}",
        route.name
      );
    }
  }
  Ok(())
}

fn validate_limits(config: &Config) -> anyhow::Result<()> {
  let limits = &config.limits;
  if limits.max_connections > EDGE_SECURE_MEDIUM_MAX_CONNECTIONS
    || limits.max_connections_per_ip > EDGE_SECURE_MEDIUM_MAX_CONNECTIONS_PER_IP
    || limits
      .max_webtransport_sessions
      .is_some_and(|value| value > EDGE_SECURE_MEDIUM_MAX_CONNECTIONS)
    || limits
      .max_webtransport_sessions_per_ip
      .is_some_and(|value| value > EDGE_SECURE_MEDIUM_MAX_CONNECTIONS_PER_IP)
    || limits.max_webtransport_sessions_per_connection
      > EDGE_SECURE_MEDIUM_MAX_WEBTRANSPORT_SESSIONS_PER_CONNECTION
    || limits.max_requests_per_connection > EDGE_SECURE_MEDIUM_MAX_REQUESTS_PER_CONNECTION
    || limits.max_headers > EDGE_SECURE_MEDIUM_MAX_HEADERS
    || limits.max_header_name_bytes > EDGE_SECURE_MEDIUM_MAX_HEADER_NAME_BYTES
    || limits.max_header_value_bytes > EDGE_SECURE_MEDIUM_MAX_HEADER_VALUE_BYTES
    || limits.max_total_header_bytes > EDGE_SECURE_MEDIUM_MAX_TOTAL_HEADER_BYTES
    || limits.max_uri_bytes > EDGE_SECURE_MEDIUM_MAX_URI_BYTES
    || limits.max_request_body_bytes > EDGE_SECURE_MEDIUM_MAX_REQUEST_BODY_BYTES
    || config.proxy.http2.max_concurrent_streams > EDGE_SECURE_MEDIUM_MAX_H2_STREAMS
    || quic_transport_raises_stream_limits(&config.quic.transport)
    || quic_transport_raises_stream_limits(&config.quic.downstream.transport)
    || quic_transport_raises_stream_limits(&config.quic.upstream.transport)
  {
    bail!("edge-secure-medium v1 limits may be tightened but not raised above the v1 bounds");
  }
  for route in &config.routes {
    if route.effective_max_request_body_bytes(limits) > EDGE_SECURE_MEDIUM_MAX_REQUEST_BODY_BYTES {
      bail!(
        "edge-secure-medium v1 route {} raises the request body limit above 10 MiB",
        route.name
      );
    }
  }
  Ok(())
}

fn quic_transport_raises_stream_limits(transport: &crate::config::QuicTransportConfig) -> bool {
  transport.max_concurrent_bidi_streams > EDGE_SECURE_MEDIUM_MAX_QUIC_STREAMS
    || transport.max_concurrent_uni_streams > EDGE_SECURE_MEDIUM_MAX_QUIC_STREAMS
}

fn validate_proxy_and_identity(config: &Config) -> anyhow::Result<()> {
  if config.proxy.forwarded_headers.mode != ForwardedHeaderMode::Overwrite {
    bail!("edge-secure-medium v1 requires proxy.forwarded_headers.mode = \"overwrite\"");
  }
  if config.proxy.forwarded_headers.client_ip_source != ForwardedClientIpSource::Resolved {
    bail!("edge-secure-medium v1 requires proxy.forwarded_headers.client_ip_source = \"resolved\"");
  }
  if config.proxy.http.trailers != TrailerMode::Drop {
    bail!("edge-secure-medium v1 requires proxy.http.trailers = \"drop\"");
  }
  if config.proxy.real_ip.enabled {
    validate_trusted_cidrs(
      "proxy.real_ip.trusted_proxies",
      &config.proxy.real_ip.trusted_proxies,
    )?;
    if !config.proxy.real_ip.fail_on_untrusted_forwarded_headers {
      bail!(
        "edge-secure-medium v1 requires rejecting untrusted forwarded headers when Real-IP is enabled"
      );
    }
  }
  if config.listeners.proxy_protocol.enabled {
    validate_trusted_cidrs(
      "listeners.proxy_protocol.trusted_sources",
      &config.listeners.proxy_protocol.trusted_sources,
    )?;
  }
  Ok(())
}

fn validate_trusted_cidrs(field: &str, values: &[String]) -> anyhow::Result<()> {
  if values.is_empty() {
    bail!("edge-secure-medium v1 requires {field} to be explicit and nonempty");
  }
  let cidrs = values
    .iter()
    .map(|value| {
      crate::identity::Cidr::parse(value).with_context(|| format!("invalid {field} entry {value}"))
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  if crate::identity::cidrs_cover_entire_address_family(&cidrs) {
    bail!("edge-secure-medium v1 forbids all-address trust in {field}");
  }
  Ok(())
}

fn validate_waf(config: &Config, profile: &OperationalProfile) -> anyhow::Result<()> {
  if !profile.explicitly_sets("waf.enabled") || !config.waf.enabled {
    bail!("edge-secure-medium v1 requires an explicit waf.enabled = true");
  }
  if !matches!(config.waf.mode, WafMode::Enforcing | WafMode::Monitor) {
    bail!("edge-secure-medium v1 has an unsupported WAF rollout mode");
  }
  if config.waf.fail_policy != WafFailPolicy::Closed
    || config.waf.duplicate_metadata_policy != WafDuplicateMetadataPolicy::FailClosed
    || config.waf.http_body_compression.mode != WafHttpBodyCompressionMode::Transform
    || config.waf.http_body_compression.max_decoded_body_bytes
      > EDGE_SECURE_MEDIUM_MAX_REQUEST_BODY_BYTES as usize
    || config.waf.http_body_compression.max_expansion_ratio
      > EDGE_SECURE_MEDIUM_MAX_WAF_BODY_EXPANSION_RATIO
    || config.waf.http_body_compression.decode_timeout_ms
      > EDGE_SECURE_MEDIUM_MAX_WAF_BODY_DECODE_TIMEOUT_MS
  {
    bail!(
      "edge-secure-medium v1 requires fail-closed WAF evaluation and bounded body transformation"
    );
  }
  validate_waf_limits(&config.waf.limits)?;
  for route in &config.routes {
    if route.waf.http_body_compression.mode == RouteWafHttpBodyCompressionMode::Off {
      bail!(
        "edge-secure-medium v1 forbids disabling WAF body transformation on route {}",
        route.name
      );
    }
  }
  Ok(())
}

fn validate_waf_limits(limits: &crate::waf::WafLimits) -> anyhow::Result<()> {
  if limits.max_rule_runtime_ms > EDGE_SECURE_MEDIUM_MAX_WAF_RULE_RUNTIME_MS
    || limits.max_total_waf_runtime_ms > EDGE_SECURE_MEDIUM_MAX_TOTAL_WAF_RUNTIME_MS
    || limits.max_expression_steps > EDGE_SECURE_MEDIUM_MAX_WAF_EXPRESSION_STEPS
    || limits.max_memory_bytes > EDGE_SECURE_MEDIUM_MAX_WAF_MEMORY_BYTES
    || limits.max_string_bytes > EDGE_SECURE_MEDIUM_MAX_WAF_STRING_BYTES
    || limits.max_body_inspection_bytes > EDGE_SECURE_MEDIUM_MAX_WAF_BODY_INSPECTION_BYTES
    || limits.max_header_count > EDGE_SECURE_MEDIUM_MAX_WAF_HEADER_COUNT
    || limits.max_header_value_bytes > EDGE_SECURE_MEDIUM_MAX_WAF_HEADER_VALUE_BYTES
    || limits.max_mutations > EDGE_SECURE_MEDIUM_MAX_WAF_MUTATIONS
    || limits.max_regex_runtime_ms > EDGE_SECURE_MEDIUM_MAX_WAF_REGEX_RUNTIME_MS
    || limits.max_advanced_regex_subject_bytes > EDGE_SECURE_MEDIUM_MAX_ADVANCED_REGEX_SUBJECT_BYTES
    || limits.max_advanced_regex_backtracks > EDGE_SECURE_MEDIUM_MAX_ADVANCED_REGEX_BACKTRACKS
    || limits.max_helper_items > EDGE_SECURE_MEDIUM_MAX_WAF_HELPER_ITEMS
    || limits.max_helper_pattern_count > EDGE_SECURE_MEDIUM_MAX_WAF_HELPER_PATTERN_COUNT
    || limits.max_helper_result_bytes > EDGE_SECURE_MEDIUM_MAX_WAF_HELPER_RESULT_BYTES
    || limits.max_person_proof_reuse_tokens > EDGE_SECURE_MEDIUM_MAX_WAF_PERSON_PROOF_REUSE_TOKENS
  {
    bail!("edge-secure-medium v1 WAF limits may be tightened but not raised above the v1 bounds");
  }
  Ok(())
}

fn validate_operations(config: &Config) -> anyhow::Result<()> {
  if !config.access_log.system.enabled
    || !config.access_log.waf.enabled
    || !config.access_log.admin.enabled
  {
    bail!("edge-secure-medium v1 requires system, WAF, and Admin access-log sources");
  }
  if !config.metrics.enabled
    || config.metrics.detail != MetricsDetail::Detailed
    || !config.health.enabled
  {
    bail!("edge-secure-medium v1 requires detailed metrics and health endpoints");
  }
  if !config.overload.enabled || !config.circuit_breakers.enabled {
    bail!("edge-secure-medium v1 requires overload and circuit-breaker protection");
  }
  if config.shared_state.redis_plaintext_policy != RedisPlaintextPolicy::Deny {
    bail!("edge-secure-medium v1 requires shared_state.redis_plaintext_policy = \"deny\"");
  }
  if config.runtime.drain.shutdown_delay_ms < EDGE_SECURE_MEDIUM_MIN_SHUTDOWN_DELAY_MS
    || config.runtime.drain.graceful_timeout_ms < EDGE_SECURE_MEDIUM_MIN_GRACEFUL_DRAIN_MS
    || config.runtime.drain.long_connection_close_delay_ms
      < EDGE_SECURE_MEDIUM_MIN_LONG_CONNECTION_DRAIN_MS
  {
    bail!("edge-secure-medium v1 drain timings may be lengthened but not shortened");
  }
  Ok(())
}

fn validate_admin(config: &Config) -> anyhow::Result<()> {
  if !config.admin.enabled {
    return Ok(());
  }
  if config.admin.transport != AdminTransportMode::Tls
    || !config.admin.tls.enabled
    || config.admin.tls.min_version != TlsVersion::Tls13
    || config.admin.tls.max_version != TlsVersion::Tls13
    || config.admin.tls.client_auth.mode != TlsClientAuthMode::Require
    || !config.ipm.enabled
    || !config.admin.audit.enabled
    || config.admin.audit.mode != AdminAuditMode::Enforcing
    || !config.admin.audit.store.enabled
    || !config
      .admin
      .audit
      .export
      .required_sinks
      .contains(&AdminAuditRequiredSink::Store)
  {
    bail!(
      "edge-secure-medium v1 requires TLS 1.3 mTLS, IPM, and durable enforcing audit for Admin"
    );
  }
  if config
    .listeners
    .https_binds
    .iter()
    .chain(config.listeners.http_binds.iter())
    .any(|bind| bind.port() == config.admin.bind.port())
  {
    bail!("edge-secure-medium v1 requires Admin to use a dedicated listener port");
  }
  Ok(())
}

fn validate_rulepacks(config: &Config) -> anyhow::Result<()> {
  validate_rulepack_scope(
    "waf.rulepack_files",
    &config.waf.rulepack_files,
    config.waf.rulepack_summaries(),
  )?;
  for route in &config.routes {
    validate_rulepack_scope(
      &format!("routes {} waf.rulepack_files", route.name),
      &route.waf.rulepack_files,
      route.waf.rulepack_summaries(),
    )?;
  }
  Ok(())
}

fn validate_rulepack_scope(
  field: &str,
  paths: &[std::path::PathBuf],
  summaries: &[crate::waf::WafRulepackSummary],
) -> anyhow::Result<()> {
  if paths.iter().any(|path| {
    path
      .to_string_lossy()
      .chars()
      .any(|character| matches!(character, '*' | '?' | '['))
  }) {
    bail!("edge-secure-medium v1 requires exact {field} paths rather than globs");
  }
  if summaries
    .iter()
    .any(|summary| summary.source_url.is_some() && summary.source_sha256.is_none())
  {
    bail!(
      "edge-secure-medium v1 requires source_sha256 provenance for remotely sourced rulepacks in {field}"
    );
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn profile_v1_fills_missing_values_and_materializes_version() {
    let mut value: toml::Value = toml::from_str(
      r#"
profile = "edge-secure-medium"

[waf]
enabled = true
"#,
    )
    .expect("profile fixture should parse");

    let profile = apply_to_toml(&mut value)
      .expect("profile should expand")
      .expect("profile should be selected");

    assert_eq!(profile.name(), EDGE_SECURE_MEDIUM_NAME);
    assert_eq!(profile.version(), EDGE_SECURE_MEDIUM_VERSION);
    assert!(profile.explicitly_sets("waf.enabled"));
    assert_eq!(value["profile_version"].as_integer(), Some(1));
    assert_eq!(value["tls"]["min_version"].as_str(), Some("tls1.3"));
    assert_eq!(value["waf"]["enabled"].as_bool(), Some(true));
  }

  #[test]
  fn explicit_values_win_over_profile_defaults() {
    let mut value: toml::Value = toml::from_str(
      r#"
profile = "edge-secure-medium"

[waf]
enabled = true

[limits]
max_headers = 64
"#,
    )
    .expect("profile fixture should parse");

    apply_to_toml(&mut value).expect("profile should expand");

    assert_eq!(value["limits"]["max_headers"].as_integer(), Some(64));
  }

  #[test]
  fn profile_v2_inherits_v1_and_adds_immutable_runtime_hardening_defaults() {
    let mut value: toml::Value = toml::from_str(
      r#"
profile = "edge-secure-medium"
profile_version = 2

[waf]
enabled = true

[runtime.hardening.filesystem_manifest]
expected_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expected_writable_paths = []
"#,
    )
    .expect("profile fixture should parse");

    let profile = apply_to_toml(&mut value)
      .expect("profile should expand")
      .expect("profile should be selected");

    assert_eq!(profile.name(), EDGE_SECURE_MEDIUM_NAME);
    assert_eq!(profile.version(), EDGE_SECURE_MEDIUM_V2_VERSION);
    assert_eq!(value["profile_version"].as_integer(), Some(2));
    assert_eq!(value["tls"]["min_version"].as_str(), Some("tls1.3"));
    assert_eq!(
      value["runtime"]["hardening"]["close_range"].as_str(),
      Some("required")
    );
    assert_eq!(
      value["runtime"]["hardening"]["seccomp"]["expectation"].as_str(),
      Some("required")
    );
    assert_eq!(
      value["runtime"]["hardening"]["landlock"]["mode"].as_str(),
      Some("manifest")
    );
  }

  #[test]
  fn profile_version_without_profile_fails_closed() {
    let mut value: toml::Value =
      toml::from_str("profile_version = 1").expect("profile fixture should parse");
    let error = apply_to_toml(&mut value).expect_err("orphaned version must fail");
    assert!(error.to_string().contains("requires profile"));
  }

  #[test]
  fn unknown_profile_name_or_version_fails_closed() {
    for raw in [
      "profile = \"unknown\"",
      "profile = \"edge-secure-medium\"\nprofile_version = 3",
    ] {
      let mut value: toml::Value = toml::from_str(raw).expect("profile fixture should parse");
      let error = apply_to_toml(&mut value).expect_err("unsupported profile must fail");
      assert!(
        error
          .to_string()
          .contains("unsupported operational profile"),
        "unexpected error: {error}"
      );
    }
  }
}
