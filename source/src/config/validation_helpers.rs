//! Shared semantic-validation primitives.

use super::*;

pub(super) fn validate_ocsp_config(prefix: &str, ocsp: &OcspConfig) -> anyhow::Result<()> {
  match ocsp.mode {
    OcspMode::Disabled => {}
    OcspMode::StaticFile => {
      if ocsp.response_file.is_none() {
        bail!("{prefix}.response_file is required when {prefix}.mode = \"static_file\"");
      }
    }
    OcspMode::LiveFetch => {
      if ocsp.response_file.is_some() {
        bail!("{prefix}.response_file cannot be used when {prefix}.mode = \"live_fetch\"");
      }
    }
  }
  ocsp.validate_fetch_settings_with_prefix(prefix)
}

pub(super) fn validate_tls_server_resumption(
  prefix: &str,
  resumption: &TlsServerResumptionConfig,
) -> anyhow::Result<()> {
  if resumption.session_cache_size == 0 {
    bail!("{prefix}.session_cache_size must be greater than 0");
  }
  if resumption.tls13_ticket_count == 0 {
    bail!("{prefix}.tls13_ticket_count must be greater than 0");
  }
  if resumption.rotation_seconds == 0 {
    bail!("{prefix}.rotation_seconds must be greater than 0");
  }
  Ok(())
}

pub(super) fn validate_compression_statuses(
  field_name: &str,
  statuses: &[u16],
) -> anyhow::Result<()> {
  if statuses.is_empty() {
    bail!("{field_name} must include at least one status");
  }
  for status in statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name} contains invalid status {status}"))?;
  }
  Ok(())
}

pub(super) fn validate_compression_level(field_name: &str, level: u8) -> anyhow::Result<()> {
  if !(1..=9).contains(&level) {
    bail!("{field_name} must be between 1 and 9");
  }
  Ok(())
}

pub(super) fn validate_compression_proxied(
  field_name: &str,
  proxied: &[CompressionProxiedPredicate],
) -> anyhow::Result<()> {
  if proxied.is_empty() {
    bail!("{field_name} must include at least one predicate");
  }
  let mut seen = HashSet::new();
  for predicate in proxied {
    if !seen.insert(*predicate) {
      bail!("{field_name} contains duplicate predicate {predicate:?}");
    }
  }
  let has_off = seen.contains(&CompressionProxiedPredicate::Off);
  let has_any = seen.contains(&CompressionProxiedPredicate::Any);
  if has_off && proxied.len() > 1 {
    bail!("{field_name} predicate off cannot be combined with other predicates");
  }
  if has_any && proxied.len() > 1 {
    bail!("{field_name} predicate any cannot be combined with other predicates");
  }
  Ok(())
}

pub(super) fn validate_compression_mime_types(
  field_name: &str,
  mime_types: &[String],
) -> anyhow::Result<()> {
  if mime_types.is_empty() {
    bail!("{field_name} must include at least one MIME pattern");
  }
  for mime_type in mime_types {
    validate_compression_mime_type(field_name, mime_type)?;
  }
  Ok(())
}

pub(super) fn validate_compression_mime_type(
  field_name: &str,
  mime_type: &str,
) -> anyhow::Result<()> {
  if mime_type.trim() != mime_type || mime_type.is_empty() {
    bail!("{field_name} contains an empty or padded MIME pattern");
  }
  if mime_type.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field_name} contains a control character in {mime_type}");
  }
  let Some((type_part, subtype_part)) = mime_type.split_once('/') else {
    bail!("{field_name} MIME pattern {mime_type} must contain '/'");
  };
  if type_part.is_empty() || subtype_part.is_empty() {
    bail!("{field_name} MIME pattern {mime_type} must have type and subtype");
  }
  if type_part.contains('*') && type_part != "*" {
    bail!("{field_name} MIME pattern {mime_type} has invalid wildcard type");
  }
  if type_part == "*" && subtype_part != "*" {
    bail!("{field_name} MIME pattern {mime_type} must use */* for wildcard type");
  }
  if subtype_part.matches('*').count() > 1 {
    bail!("{field_name} MIME pattern {mime_type} has too many wildcards");
  }
  if subtype_part.contains('*') && subtype_part != "*" && !subtype_part.starts_with("*+") {
    bail!("{field_name} MIME pattern {mime_type} has invalid wildcard subtype");
  }
  Ok(())
}

pub(super) fn validate_cache_tag_headers(
  field_name: &str,
  headers: &[String],
) -> anyhow::Result<()> {
  if headers.is_empty() {
    bail!("{field_name} must include at least one header name");
  }
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    http::header::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
  }
  Ok(())
}

pub(super) fn validate_cache_bypass_headers(
  field_name: &str,
  headers: &[String],
) -> anyhow::Result<()> {
  if headers.is_empty() {
    bail!("{field_name} must include at least one header");
  }
  let mut names = HashSet::new();
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    let name = http::header::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
    let normalized = name.as_str().to_ascii_lowercase();
    if !names.insert(normalized.clone()) {
      bail!("{field_name} contains duplicate header {normalized}");
    }
  }
  Ok(())
}

pub(super) fn validate_cache_admission(
  field_name: &str,
  admission: &CacheAdmissionConfig,
  cache: &CacheConfig,
) -> anyhow::Result<()> {
  if admission.statuses.is_empty() && cache.negative_statuses.is_empty() {
    bail!("{field_name}.statuses must include at least one status");
  }
  for status in &admission.statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name}.statuses contains invalid status {status}"))?;
  }
  if !admission.content_types.is_empty() {
    validate_compression_mime_types(
      &format!("{field_name}.content_types"),
      &admission.content_types,
    )?;
  }
  if admission.min_hits == 0 {
    bail!("{field_name}.min_hits must be greater than 0");
  }
  if admission.max_tracked_keys == 0 {
    bail!("{field_name}.max_tracked_keys must be greater than 0");
  }
  Ok(())
}

pub(super) fn validate_cache_stale_if_error(
  field_name: &str,
  stale_if_error: &CacheStaleIfErrorConfig,
) -> anyhow::Result<()> {
  for status in &stale_if_error.statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name}.statuses contains invalid status {status}"))?;
  }
  Ok(())
}

pub(super) fn validate_base64_32_byte_env(field_name: &str, env_name: &str) -> anyhow::Result<()> {
  if env_name.trim().is_empty() {
    bail!("{field_name} must not be empty");
  }
  let raw = zeroize::Zeroizing::new(
    std::env::var(env_name).with_context(|| format!("failed to read {field_name} {env_name}"))?,
  );
  let bytes = zeroize::Zeroizing::new(
    base64::engine::general_purpose::STANDARD
      .decode(raw.trim())
      .with_context(|| format!("{field_name} must contain base64"))?,
  );
  if bytes.len() != 32 {
    bail!("{field_name} must contain exactly 32 bytes");
  }
  Ok(())
}

pub(super) fn validate_tls_server_name(field_name: &str, name: &str) -> anyhow::Result<()> {
  if name.trim() != name || name.is_empty() {
    bail!("{field_name} must not be empty or padded");
  }
  if name.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field_name} {name} contains a control character");
  }
  let name = name.strip_prefix("*.").unwrap_or(name);
  if name.is_empty() || name.contains('*') {
    bail!("{field_name} may only use a leftmost wildcard");
  }
  if name
    .split('.')
    .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
  {
    bail!("{field_name} {name} is not a valid DNS pattern");
  }
  if !name
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("{field_name} {name} contains invalid characters");
  }
  Ok(())
}

pub(super) fn validate_admin_server_name(name: &str) -> anyhow::Result<()> {
  validate_tls_server_name("admin.tls certificate server name", name)
}

pub(crate) fn upstream_pool_server_id(index: usize, server: &UpstreamPoolServerConfig) -> String {
  server.id.clone().unwrap_or_else(|| index.to_string())
}

pub(crate) fn turn_upstream_pool_server_id(
  index: usize,
  server: &TurnUpstreamPoolServerConfig,
) -> String {
  server.id.clone().unwrap_or_else(|| index.to_string())
}

pub(crate) fn validate_runtime_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  if value.trim() != value || value.is_empty() {
    bail!("{field_name} must not be empty or padded");
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("{field_name} must contain only ASCII letters, digits, '-', '_' or '.'");
  }
  Ok(())
}

pub(super) fn routes_without_waf_are_equivalent(
  left: &[RouteConfig],
  right: &[RouteConfig],
) -> bool {
  left.len() == right.len()
    && left.iter().zip(right).all(|(left, right)| {
      left.name == right.name
        && left.hosts == right.hosts
        && left.path_prefix == right.path_prefix
        && left.r#match == right.r#match
        && left.replace_prefix_with == right.replace_prefix_with
        && left.actions == right.actions
        && left.upstream == right.upstream
        && left.upstream_pool == right.upstream_pool
        && left.static_root == right.static_root
        && left.static_files == right.static_files
        && left.upstream_http_version == right.upstream_http_version
        && left.generic_http_upgrade == right.generic_http_upgrade
        && left.connect_tunneling == right.connect_tunneling
        && left.grpc_web == right.grpc_web
        && left.external_auth == right.external_auth
        && left.cache == right.cache
        && left.compression == right.compression
        && left.buffering == right.buffering
        && left.limits == right.limits
    })
}

pub(super) fn validate_effective_buffering(
  field_name: &str,
  mode: BufferingMode,
  max_temp_file_bytes: usize,
  requires_temp_dir: &mut bool,
) -> anyhow::Result<()> {
  if mode == BufferingMode::Spool {
    if max_temp_file_bytes == 0 {
      bail!("{field_name}.max_temp_file_bytes must be greater than 0 when buffering uses spool");
    }
    *requires_temp_dir = true;
  }
  Ok(())
}

pub(super) fn route_waf_configs_are_equivalent(
  left: &[RouteConfig],
  right: &[RouteConfig],
) -> bool {
  left.len() == right.len()
    && left
      .iter()
      .zip(right)
      .all(|(left, right)| left.name == right.name && left.waf == right.waf)
}
