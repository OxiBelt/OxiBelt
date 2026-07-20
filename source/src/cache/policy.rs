//! Cache store selection, admission, and compiled policy construction.

use super::*;

pub(super) fn select_store(policy: &CachePolicyRuntime, headers: &HeaderMap) -> CacheStore {
  let content_type = normalized_content_type(headers);
  for rule in &policy.rules {
    if rule
      .mime_types
      .iter()
      .any(|pattern| mime_matches(pattern, &content_type))
    {
      return rule.store;
    }
  }
  policy.store
}

pub(super) fn select_store_for_insert(
  inner: &CacheInner,
  policy: &CachePolicyRuntime,
  headers: &HeaderMap,
  size: usize,
) -> CacheStore {
  match select_store(policy, headers) {
    CacheStore::MemoryThenDisk if inner.memory_size + size <= policy.memory_max_size_bytes => {
      CacheStore::Memory
    }
    CacheStore::MemoryThenDisk => CacheStore::Disk,
    store => store,
  }
}

pub(super) fn mime_matches(pattern: &str, mime: &str) -> bool {
  if pattern == "*/*" {
    return true;
  }
  let pattern = pattern.to_ascii_lowercase();
  if let Some(prefix) = pattern.strip_suffix("/*") {
    return mime.starts_with(&format!("{prefix}/"));
  }
  if let Some(suffix) = pattern.strip_prefix("*/") {
    return mime.ends_with(&format!("/{suffix}"));
  }
  if let Some(suffix) = pattern.split_once("/*+").map(|(_, suffix)| suffix) {
    return mime.ends_with(&format!("+{suffix}"));
  }
  pattern == mime
}

pub(super) fn extract_tags(headers: &HeaderMap, policy: &CachePolicyRuntime) -> Vec<String> {
  let mut tags = Vec::new();
  for header in &policy.tag_headers {
    for value in headers.get_all(header) {
      let Ok(value) = value.to_str() else {
        continue;
      };
      for tag in value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
      {
        if tag.len() > policy.max_tag_bytes
          || tag.bytes().any(|byte| byte.is_ascii_control())
          || tags.iter().any(|existing| existing == tag)
        {
          continue;
        }
        tags.push(tag.to_string());
        if tags.len() >= policy.max_tags_per_entry {
          return tags;
        }
      }
    }
  }
  tags
}

pub(super) fn stored_response_headers(headers: &HeaderMap, config: &CacheConfig) -> HeaderMap {
  let mut headers = headers.clone();
  if config.surrogate.enabled && config.surrogate.strip_response_header {
    headers.remove(HeaderName::from_static(SURROGATE_CONTROL_HEADER));
  }
  headers
}

pub(super) fn variant_count_exceeded(
  inner: &CacheInner,
  policy: &CachePolicyRuntime,
  partition: &str,
  base_key: &str,
  variant_key: &str,
) -> bool {
  if inner.entries.contains_key(variant_key) {
    return false;
  }
  let group = index::VariantGroupKey::new(&policy.name, partition, base_key);
  inner.index.variant_count(&group) >= policy.max_vary_variants_per_key
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum PreparedBodyAdmission {
  Admitted,
  Warming,
  Rejected,
}

pub(super) fn admit_prepared_body(
  inner: &mut CacheInner,
  policy: &CachePolicyRuntime,
  variant_key: &str,
  body_len: usize,
) -> PreparedBodyAdmission {
  if policy.admission.max_body_bytes > 0 && body_len > policy.admission.max_body_bytes {
    return PreparedBodyAdmission::Rejected;
  }
  if policy.admission.min_hits <= 1 {
    return PreparedBodyAdmission::Admitted;
  }
  if admit_frequency(inner, policy, variant_key) {
    PreparedBodyAdmission::Admitted
  } else {
    PreparedBodyAdmission::Warming
  }
}

pub(super) fn admit_frequency(
  inner: &mut CacheInner,
  policy: &CachePolicyRuntime,
  variant_key: &str,
) -> bool {
  let key = format!("{}\n{variant_key}", policy.name);
  let count = {
    let count = inner
      .admission_counts
      .entry(key.clone())
      .and_modify(|count| *count = count.saturating_add(1))
      .or_insert(1);
    *count
  };
  if count == 1 {
    inner.admission_order.push_back(key.clone());
  }
  while inner.admission_counts.len() > policy.admission.max_tracked_keys {
    let Some(oldest) = inner.admission_order.pop_front() else {
      break;
    };
    inner.admission_counts.remove(&oldest);
  }
  count >= policy.admission.min_hits as u32
}

pub(super) fn admit_response_head(
  policy: &CachePolicyRuntime,
  status: StatusCode,
  headers: &HeaderMap,
  content_length: Option<usize>,
) -> bool {
  if !policy.admission.statuses.contains(&status) {
    return false;
  }
  if policy.admission.max_body_bytes > 0
    && content_length.is_some_and(|length| length > policy.admission.max_body_bytes)
  {
    return false;
  }
  if !policy.admission.content_types.is_empty() {
    let content_type = normalized_content_type(headers);
    if !policy
      .admission
      .content_types
      .iter()
      .any(|pattern| mime_matches(pattern, &content_type))
    {
      return false;
    }
  }
  true
}

pub(super) fn normalized_content_type(headers: &HeaderMap) -> String {
  headers
    .get(CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .map(|value| {
      value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
    })
    .unwrap_or_default()
}

pub(super) fn policy_runtime(
  config: &CacheConfig,
  policy: &CachePolicyConfig,
  default_memory_limit: usize,
) -> CachePolicyRuntime {
  CachePolicyRuntime {
    name: policy.name.clone(),
    store: policy.store.unwrap_or(config.store),
    cache_key: policy
      .cache_key
      .clone()
      .unwrap_or_else(|| config.cache_key.clone()),
    partition_key: policy
      .partition_key
      .clone()
      .unwrap_or_else(|| config.partition_key.clone()),
    default_ttl_seconds: policy
      .default_ttl_seconds
      .unwrap_or(config.default_ttl_seconds),
    negative_statuses: policy
      .negative_statuses
      .as_ref()
      .map(|statuses| cache_status_codes(statuses))
      .unwrap_or_else(|| cache_status_codes(&config.negative_statuses)),
    negative_ttl_seconds: policy
      .negative_ttl_seconds
      .unwrap_or(config.negative_ttl_seconds),
    memory_max_size_bytes: policy.memory_max_size_bytes.unwrap_or(default_memory_limit),
    disk_max_size_bytes: policy.disk_max_size_bytes.or(config.disk_max_size_bytes),
    tag_headers: cache_tag_headers(policy.tag_headers.as_ref().unwrap_or(&config.tag_headers)),
    max_tags_per_entry: policy
      .max_tags_per_entry
      .unwrap_or(config.max_tags_per_entry),
    max_tag_bytes: policy.max_tag_bytes.unwrap_or(config.max_tag_bytes),
    max_vary_fields: policy.max_vary_fields.unwrap_or(config.max_vary_fields),
    max_vary_variants_per_key: policy
      .max_vary_variants_per_key
      .unwrap_or(config.max_vary_variants_per_key),
    background_refresh: policy
      .background_refresh
      .unwrap_or(config.background_refresh),
    background_refresh_max_concurrent: policy
      .background_refresh_max_concurrent
      .unwrap_or(config.background_refresh_max_concurrent),
    lock_wait_timeout: Duration::from_millis(
      policy
        .lock_wait_timeout_ms
        .unwrap_or(config.lock_wait_timeout_ms),
    ),
    external_handler: external_handler_selection(
      config.external_handler.as_deref(),
      policy.external_handler.as_deref(),
    ),
    admission: admission_runtime(
      policy.admission.as_ref().unwrap_or(&config.admission),
      policy
        .negative_statuses
        .as_deref()
        .unwrap_or(&config.negative_statuses),
    ),
    stale_if_error: policy
      .stale_if_error
      .clone()
      .unwrap_or_else(|| config.stale_if_error.clone()),
    rules: policy
      .rules
      .iter()
      .map(|rule| CachePolicyRuleRuntime {
        mime_types: rule.mime_types.clone(),
        store: rule.store,
      })
      .collect(),
  }
}

pub(super) fn external_handler_selection(
  default: Option<&str>,
  override_value: Option<&str>,
) -> Option<String> {
  match override_value.or(default) {
    Some("off") | None => None,
    Some(name) => Some(name.to_string()),
  }
}

pub(super) fn cache_tag_headers(headers: &[String]) -> Vec<HeaderName> {
  headers
    .iter()
    .filter_map(|header| HeaderName::from_bytes(header.as_bytes()).ok())
    .collect()
}

pub(super) fn cache_status_codes(statuses: &[u16]) -> Vec<StatusCode> {
  statuses
    .iter()
    .filter_map(|status| StatusCode::from_u16(*status).ok())
    .collect()
}

pub(super) fn admission_runtime(
  admission: &CacheAdmissionConfig,
  negative_statuses: &[u16],
) -> CacheAdmissionRuntime {
  let mut statuses = admission
    .statuses
    .iter()
    .chain(negative_statuses)
    .filter_map(|status| StatusCode::from_u16(*status).ok())
    .collect::<Vec<_>>();
  statuses.sort();
  statuses.dedup();
  CacheAdmissionRuntime {
    statuses,
    content_types: admission.content_types.clone(),
    max_body_bytes: admission.max_body_bytes,
    min_hits: admission.min_hits,
    max_tracked_keys: admission.max_tracked_keys,
  }
}
