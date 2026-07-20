//! Response freshness, validator, Vary, and cache-control interpretation.

use super::*;

#[derive(Debug)]
pub(super) struct ResponseMetadata {
  pub(super) expires_at: SystemTime,
  pub(super) stale_if_error_until: Option<SystemTime>,
  pub(super) stale_while_revalidate_until: Option<SystemTime>,
  pub(super) must_revalidate: bool,
  pub(super) stored_at: SystemTime,
  pub(super) vary: Vec<VaryMatcher>,
}

pub(super) fn cache_metadata(
  config: &CacheConfig,
  policy: &CachePolicyRuntime,
  request_headers: &HeaderMap,
  status: StatusCode,
  response_headers: &HeaderMap,
) -> Result<ResponseMetadata, CacheFillSuppressionReason> {
  if status == StatusCode::PARTIAL_CONTENT {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  if !cacheable_status(policy, status) {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  if response_has_set_cookie(response_headers) {
    return Err(CacheFillSuppressionReason::SetCookie);
  }
  let request_directives = cache_control_directives(request_headers);
  if request_directives.has("no-store") {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  let directives = cache_control_directives(response_headers);
  let surrogate = config
    .surrogate
    .enabled
    .then(|| surrogate_control_directives(response_headers))
    .flatten();
  if surrogate
    .as_ref()
    .is_some_and(|directives| directives.no_store)
  {
    return Err(CacheFillSuppressionReason::ResponseNoStore);
  }
  if surrogate.is_none() && config.respect_cache_control && directives.has("no-store") {
    return Err(CacheFillSuppressionReason::ResponseNoStore);
  }
  if surrogate.is_none() && config.respect_cache_control && directives.has("private") {
    return Err(CacheFillSuppressionReason::ResponsePrivate);
  }
  let vary = vary_matchers_result(
    response_headers,
    request_headers,
    policy.max_vary_fields,
    MAX_VARY_VALUE_BYTES,
  )
  .map_err(|_| CacheFillSuppressionReason::VaryRejected)?;
  if has_non_identity_content_encoding(response_headers)
    && !response_varies_accept_encoding(response_headers)
  {
    return Err(CacheFillSuppressionReason::VaryRejected);
  }
  let now = SystemTime::now();
  let mut ttl = surrogate
    .as_ref()
    .and_then(|directives| directives.max_age)
    .unwrap_or_else(|| {
      if config.respect_cache_control {
        directives
          .seconds("s-maxage")
          .or_else(|| directives.seconds("max-age"))
          .or_else(|| expires_ttl(response_headers, now))
          .unwrap_or(policy.default_ttl_seconds)
      } else {
        policy.default_ttl_seconds
      }
    });
  if policy.negative_statuses.contains(&status) {
    ttl = policy.negative_ttl_seconds;
  }
  if ttl == 0 {
    return Err(CacheFillSuppressionReason::Unknown);
  }
  let must_revalidate = surrogate.is_none()
    && (directives.has("no-cache")
      || directives.has("must-revalidate")
      || directives.has("proxy-revalidate"));
  let expires_at = if must_revalidate {
    now
  } else {
    now + Duration::from_secs(ttl)
  };
  let stale_if_error_seconds = surrogate
    .as_ref()
    .and_then(|directives| directives.stale_if_error)
    .unwrap_or_else(|| {
      if config.respect_cache_control {
        directives
          .seconds("stale-if-error")
          .unwrap_or(config.stale_if_error_seconds)
      } else {
        config.stale_if_error_seconds
      }
    });
  let stale_if_error_seconds = if policy.stale_if_error.max_upstream_stale_seconds > 0 {
    stale_if_error_seconds.min(policy.stale_if_error.max_upstream_stale_seconds)
  } else {
    stale_if_error_seconds
  };
  let stale_while_revalidate_seconds = surrogate
    .as_ref()
    .and_then(|directives| directives.stale_while_revalidate)
    .unwrap_or_else(|| {
      if config.respect_cache_control {
        directives
          .seconds("stale-while-revalidate")
          .unwrap_or(config.stale_while_revalidate_seconds)
      } else {
        config.stale_while_revalidate_seconds
      }
    });
  Ok(ResponseMetadata {
    expires_at,
    stale_if_error_until: (stale_if_error_seconds > 0)
      .then_some(expires_at + Duration::from_secs(stale_if_error_seconds)),
    stale_while_revalidate_until: (stale_while_revalidate_seconds > 0)
      .then_some(expires_at + Duration::from_secs(stale_while_revalidate_seconds)),
    must_revalidate,
    stored_at: now,
    vary,
  })
}

pub(super) fn cacheable_status(policy: &CachePolicyRuntime, status: StatusCode) -> bool {
  matches!(
    status,
    StatusCode::OK
      | StatusCode::NON_AUTHORITATIVE_INFORMATION
      | StatusCode::NO_CONTENT
      | StatusCode::MOVED_PERMANENTLY
      | StatusCode::PERMANENT_REDIRECT
  ) || policy.negative_statuses.contains(&status)
}

pub(super) fn response_has_set_cookie(headers: &HeaderMap) -> bool {
  headers.contains_key(http::header::SET_COOKIE)
}

pub(super) fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
  headers.get_all(CONTENT_ENCODING).iter().any(|value| {
    value
      .to_str()
      .map(|value| !value.trim().eq_ignore_ascii_case("identity"))
      .unwrap_or(true)
  })
}

pub(super) fn response_varies_accept_encoding(headers: &HeaderMap) -> bool {
  headers
    .get_all(VARY)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|item| item == "*" || item.eq_ignore_ascii_case("accept-encoding"))
}

pub(super) fn request_no_store(headers: &HeaderMap, bypass_headers: &[HeaderName]) -> bool {
  bypass_headers.iter().any(|name| headers.contains_key(name))
    || cache_control_directives(headers).has("no-store")
}

pub(super) fn request_no_cache(headers: &HeaderMap) -> bool {
  headers
    .get(PRAGMA)
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value.eq_ignore_ascii_case("no-cache"))
    || cache_control_directives(headers).has("no-cache")
}

pub(super) fn validator_headers(headers: &HeaderMap) -> HeaderMap {
  let mut validators = HeaderMap::new();
  if let Some(etag) = headers.get(ETAG) {
    validators.insert(IF_NONE_MATCH, etag.clone());
  }
  if let Some(last_modified) = headers.get(LAST_MODIFIED) {
    validators.insert(IF_MODIFIED_SINCE, last_modified.clone());
  }
  validators
}

pub(super) fn vary_matchers_result(
  response_headers: &HeaderMap,
  request_headers: &HeaderMap,
  max_fields: usize,
  max_value_bytes: usize,
) -> Result<Vec<VaryMatcher>, &'static str> {
  let mut result = Vec::new();
  for value in response_headers.get_all(VARY) {
    let value = value.to_str().map_err(|_| "invalid Vary header")?;
    for name in value
      .split(',')
      .map(str::trim)
      .filter(|name| !name.is_empty())
    {
      if name == "*" {
        return Err("Vary: * is not cacheable");
      }
      if result.len() >= max_fields {
        return Err("too many Vary fields");
      }
      let lower = name.to_ascii_lowercase();
      let value = header_values(request_headers, &lower);
      if value.len() > max_value_bytes {
        return Err("Vary value material is too large");
      }
      result.push(VaryMatcher {
        name: lower.clone(),
        value,
      });
    }
  }
  result.sort_by(|left, right| left.name.cmp(&right.name));
  result.dedup_by(|left, right| left.name == right.name);
  Ok(result)
}

pub(super) fn vary_matches(vary: &[VaryMatcher], request_headers: &HeaderMap) -> bool {
  vary
    .iter()
    .all(|item| header_values(request_headers, &item.name) == item.value)
}

pub(super) fn header_values(headers: &HeaderMap, name: &str) -> String {
  HeaderName::from_bytes(name.as_bytes())
    .ok()
    .map(|name| {
      headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
    })
    .unwrap_or_default()
}

#[derive(Debug, Default)]
struct CacheControl {
  values: HashMap<String, Option<String>>,
}

impl CacheControl {
  fn has(&self, name: &str) -> bool {
    self.values.contains_key(&name.to_ascii_lowercase())
  }

  fn seconds(&self, name: &str) -> Option<u64> {
    self
      .values
      .get(&name.to_ascii_lowercase())
      .and_then(|value| value.as_ref())
      .and_then(|value| value.parse::<u64>().ok())
  }
}

#[derive(Debug, Default)]
struct SurrogateControl {
  no_store: bool,
  max_age: Option<u64>,
  stale_if_error: Option<u64>,
  stale_while_revalidate: Option<u64>,
}

fn cache_control_directives(headers: &HeaderMap) -> CacheControl {
  let mut directives = CacheControl::default();
  for value in headers.get_all(CACHE_CONTROL) {
    let Ok(value) = value.to_str() else {
      continue;
    };
    for item in value.split(',') {
      let item = item.trim();
      if item.is_empty() {
        continue;
      }
      let (name, value) = item
        .split_once('=')
        .map(|(name, value)| {
          (
            name.trim(),
            Some(value.trim().trim_matches('"').to_string()),
          )
        })
        .unwrap_or((item, None));
      directives.values.insert(name.to_ascii_lowercase(), value);
    }
  }
  directives
}

fn surrogate_control_directives(headers: &HeaderMap) -> Option<SurrogateControl> {
  let name = HeaderName::from_static(SURROGATE_CONTROL_HEADER);
  let mut result = SurrogateControl::default();
  let mut seen = false;
  for value in headers.get_all(name) {
    let Ok(value) = value.to_str() else {
      continue;
    };
    for item in value.split(',').flat_map(|part| part.split(';')) {
      let item = item.trim();
      if item.is_empty() {
        continue;
      }
      seen = true;
      let (name, value) = item
        .split_once('=')
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), Some(value.trim())))
        .unwrap_or_else(|| (item.to_ascii_lowercase(), None));
      match name.as_str() {
        "no-store" => result.no_store = true,
        "max-age" => result.max_age = value.and_then(|value| value.parse::<u64>().ok()),
        "stale-if-error" => {
          result.stale_if_error = value.and_then(|value| value.parse::<u64>().ok());
        }
        "stale-while-revalidate" => {
          result.stale_while_revalidate = value.and_then(|value| value.parse::<u64>().ok());
        }
        _ => {}
      }
    }
  }
  seen.then_some(result)
}

pub(super) fn expires_ttl(headers: &HeaderMap, now: SystemTime) -> Option<u64> {
  let expires = headers.get(EXPIRES)?.to_str().ok()?;
  let expires = httpdate::parse_http_date(expires).ok()?;
  Some(
    expires
      .duration_since(now)
      .map(|duration| duration.as_secs())
      .unwrap_or_default(),
  )
}
