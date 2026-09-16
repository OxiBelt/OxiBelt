//! Response-owned No-Vary-Search identities. Exact cache keys stay unchanged.

use super::*;
use serde::{Deserialize, Serialize};

mod runtime;
pub use runtime::CacheNvsCandidate;
mod explain;
pub use explain::CacheNvsExplain;
pub(crate) use explain::explain;

pub(super) fn metadata_size(metadata: Option<&CacheNvsMetadata>) -> usize {
  metadata
    .and_then(|value| serde_json::to_vec(value).ok())
    .map_or(0, |bytes| bytes.len().saturating_add(256))
}

/// Bounded evidence supplied by the proxy after request inspection and rewriting.
#[derive(Clone, Debug)]
pub struct CacheNvsRequest {
  pub(crate) effective_uri: Uri,
  context_digest: [u8; 32],
  pub(super) epoch: Arc<Mutex<Option<(u64, u64)>>>,
  origin_fields: Arc<Mutex<Option<Vec<Vec<u8>>>>>,
}

impl CacheNvsRequest {
  pub fn new(effective_uri: Uri, context_material: &[u8]) -> Option<Self> {
    if context_material.len() > 65_536 || effective_uri.to_string().len() > 16_384 {
      return None;
    }
    Some(Self {
      effective_uri,
      context_digest: crate::crypto::sha256(context_material),
      epoch: Arc::new(Mutex::new(None)),
      origin_fields: Arc::new(Mutex::new(None)),
    })
  }

  /// Called with the sanitized origin response, before configurable mutations.
  pub fn capture_origin(&self, headers: &HeaderMap) {
    let fields = fields(headers);
    if let Ok(mut origin) = self.origin_fields.lock() {
      *origin = fields;
    }
  }

  pub(crate) fn origin_unchanged(&self, headers: &HeaderMap) -> bool {
    self.origin_fields.lock().ok().is_some_and(|origin| {
      origin
        .as_ref()
        .is_some_and(|original| fields(headers).as_ref() == Some(original))
    })
  }

  pub(crate) fn for_owner(&self, metadata: &CacheNvsMetadata) -> Option<Self> {
    if !metadata.valid() {
      return None;
    }
    Some(Self {
      effective_uri: metadata.effective_uri.parse().ok()?,
      context_digest: self.context_digest,
      epoch: self.epoch.clone(),
      origin_fields: Arc::new(Mutex::new(None)),
    })
  }

  pub(crate) fn reset_epoch_for_replay(&self) {
    if let Ok(mut epoch) = self.epoch.lock() {
      *epoch = None;
    }
  }
}

impl ResponseCache {
  pub(crate) async fn nvs_owner_current(
    &self,
    ctx: CacheLookupContext<'_>,
    entry: &CacheEntry,
  ) -> bool {
    let Some(metadata) = entry.no_vary_search.as_ref().filter(|value| value.valid()) else {
      return false;
    };
    let Some(policy) = self.policy(ctx.policy_name) else {
      return false;
    };
    self
      .nvs_epoch(&target(&policy.name, ctx.scheme, ctx.host, ctx.uri), false)
      .await
      == Some(metadata.epoch)
      && self.nvs_epoch(&policy_target(&policy.name), false).await == Some(metadata.policy_epoch)
  }

  pub(crate) fn nvs_policy_changed(
    &self,
    entry: &CacheEntry,
    headers: &HeaderMap,
    not_modified: bool,
  ) -> bool {
    entry.no_vary_search.is_some()
      && (!not_modified || headers.contains_key("no-vary-search"))
      && fields(&entry.headers) != fields(headers)
  }

  /// Advance exactly once from the response owner's observed generation.
  /// A concurrent invalidation wins: it cannot be hidden by rebinding a fill.
  pub(crate) async fn replace_nvs_policy(
    &self,
    ctx: CacheLookupContext<'_>,
    entry: &CacheEntry,
  ) -> bool {
    let Some(metadata) = entry.no_vary_search.as_ref() else {
      return true;
    };
    let Some(policy) = self.policy(ctx.policy_name) else {
      return false;
    };
    let Some(expected) = metadata.epoch.checked_add(1) else {
      return false;
    };
    let advanced = self
      .nvs_epoch(&target(&policy.name, ctx.scheme, ctx.host, ctx.uri), true)
      .await;
    let policy_epoch = self.nvs_epoch(&policy_target(&policy.name), false).await;
    if advanced != Some(expected) || policy_epoch != Some(metadata.policy_epoch) {
      return false;
    }
    if let Some(request) = ctx.no_vary_search {
      let Ok(mut bound) = request.epoch.lock() else {
        return false;
      };
      if *bound != Some((metadata.epoch, metadata.policy_epoch)) {
        return false;
      }
      *bound = Some((expected, metadata.policy_epoch));
    }
    true
  }

  pub(crate) fn nvs_revalidation_allows_alias(
    &self,
    entry: &CacheEntry,
    raw_uri: &Uri,
    request: &CacheNvsRequest,
    headers: &HeaderMap,
  ) -> bool {
    self.nvs_response_allows_alias(entry, raw_uri, request, headers, true)
  }

  pub(crate) fn nvs_response_allows_alias(
    &self,
    entry: &CacheEntry,
    raw_uri: &Uri,
    request: &CacheNvsRequest,
    headers: &HeaderMap,
    not_modified: bool,
  ) -> bool {
    if !entry.nvs_alias {
      return true;
    }
    let Some(owner) = entry.no_vary_search.as_ref().filter(|m| m.valid()) else {
      return false;
    };
    if !request.origin_unchanged(headers) {
      return false;
    }
    let source = if !not_modified || headers.contains_key("no-vary-search") {
      headers
    } else {
      &entry.headers
    };
    let no_vary_search::NoVarySearchParse::Valid(rule) =
      no_vary_search::parse_no_vary_search(source)
    else {
      return false;
    };
    let (Ok(owner_uri), Ok(effective_uri)) = (
      owner.owner_uri.parse::<Uri>(),
      owner.effective_uri.parse::<Uri>(),
    ) else {
      return false;
    };
    rule.equivalent(raw_uri, &owner_uri) && rule.equivalent(&request.effective_uri, &effective_uri)
  }
}

fn fields(headers: &HeaderMap) -> Option<Vec<Vec<u8>>> {
  let mut size = 0usize;
  let mut result = Vec::new();
  for value in headers.get_all("no-vary-search") {
    size = size.checked_add(value.as_bytes().len().checked_add(2)?)?;
    if size > 4096 {
      return None;
    }
    result.push(value.as_bytes().to_vec());
  }
  Some(result)
}

/// Persisted only for entries admitted with complete origin/proxy evidence.
/// Digests contain no recoverable header values, credentials, or request bodies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CacheNvsMetadata {
  pub version: u8,
  pub scope: String,
  pub owner_uri: String,
  pub effective_uri: String,
  pub epoch: u64,
  pub policy_epoch: u64,
  pub candidate_limit: usize,
}

impl CacheNvsMetadata {
  pub(crate) fn valid(&self) -> bool {
    self.version == 1
      && (1..=1024).contains(&self.candidate_limit)
      && self.scope.len() == 64
      && self.scope.bytes().all(|b| b.is_ascii_hexdigit())
      && self.owner_uri.len() <= 16_384
      && self.effective_uri.len() <= 16_384
      && self.owner_uri.parse::<Uri>().is_ok()
      && self.effective_uri.parse::<Uri>().is_ok()
  }
}

fn digest_hex(bytes: &[u8]) -> String {
  let mut result = String::with_capacity(64);
  for byte in crate::crypto::sha256(bytes) {
    use std::fmt::Write as _;
    let _ = write!(result, "{byte:02x}");
  }
  result
}

/// Preserve explicit query tokens and every non-query custom-key dimension.
fn key_projection(template: &str, ctx: &CacheLookupContext<'_>) -> String {
  let projected = template.replace("{uri}", "{path}").replace("{query}", "");
  expanded_cache_key(
    &projected,
    ctx.scheme,
    ctx.host,
    ctx.uri,
    lookup::cache_view_headers(ctx),
  )
}

fn scope(ctx: &CacheLookupContext<'_>, policy: &CachePolicyRuntime) -> Option<String> {
  let request = ctx.no_vary_search?;
  if !matches!(ctx.method.as_str(), "GET" | "HEAD" | "QUERY") {
    return None;
  }
  let mut material = Vec::new();
  if policy.groups_enabled {
    let origin = ctx.group_request?.origin.as_origin();
    append_query_field(&mut material, origin.as_bytes());
  }
  for value in [
    "oxibelt-nvs-scope-v1",
    &policy.name,
    &expanded_cache_key(
      &policy.partition_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      lookup::cache_view_headers(ctx),
    ),
    ctx.scheme,
    ctx.host,
    ctx.uri.path(),
    ctx.uri.scheme_str().unwrap_or(""),
    ctx
      .uri
      .authority()
      .map(|authority| authority.as_str())
      .unwrap_or(""),
    if ctx.method.as_str() == "QUERY" {
      "QUERY"
    } else {
      "GET"
    },
    request.effective_uri.scheme_str().unwrap_or(""),
    request
      .effective_uri
      .authority()
      .map(|a| a.as_str())
      .unwrap_or(""),
    request.effective_uri.path(),
  ] {
    append_query_field(&mut material, value.as_bytes());
  }
  append_query_field(&mut material, &request.context_digest);
  let projected = certificate_partitioned_base_key(
    key_projection(&policy.cache_key, ctx),
    ctx.certificate_identity,
  );
  let projected = match ctx.proxy_protocol_identity {
    Some(identity) => identity.partition(projected),
    None => projected,
  };
  append_query_field(&mut material, projected.as_bytes());
  if let Some(identity) = ctx.query_identity {
    for representation in [&identity.original, &identity.effective] {
      let mut representation = representation.clone();
      let uri: Uri = representation.target_uri.parse().ok()?;
      let path = uri.path().parse::<http::uri::PathAndQuery>().ok()?;
      let mut parts = uri.into_parts();
      parts.path_and_query = Some(path);
      representation.target_uri = Uri::from_parts(parts).ok()?.to_string();
      append_query_representation(&mut material, &representation);
    }
  } else if ctx.method.as_str() == "QUERY" {
    return None;
  }
  (material.len() <= 65_536).then(|| digest_hex(&material))
}

pub(super) fn target(
  policy: &str,
  scheme: &str,
  host: &str,
  uri: &Uri,
) -> CacheQueryInvalidationTarget {
  CacheQueryInvalidationTarget::new(policy, &format!("nvs-v1:{scheme}"), host, uri.path(), None)
}

pub(super) fn policy_target(policy: &str) -> CacheQueryInvalidationTarget {
  CacheQueryInvalidationTarget::new(policy, "nvs-policy-v1", "", "/", None)
}

impl CacheQueryIdentity {
  pub(crate) fn for_nvs_owner(&self, metadata: &CacheNvsMetadata) -> Self {
    let mut identity = self.clone();
    identity.original.target_uri =
      retarget_query_uri(&identity.original.target_uri, &metadata.owner_uri)
        .unwrap_or_else(|| identity.original.target_uri.clone());
    identity.effective.target_uri =
      retarget_query_uri(&identity.effective.target_uri, &metadata.effective_uri)
        .unwrap_or_else(|| identity.effective.target_uri.clone());
    identity.generation = Arc::new(Mutex::new(None));
    identity.epoch_authority_failed = Arc::new(AtomicBool::new(false));
    identity
  }
}

fn retarget_query_uri(original: &str, owner: &str) -> Option<String> {
  let mut parts = original.parse::<Uri>().ok()?.into_parts();
  parts.path_and_query = owner.parse::<Uri>().ok()?.path_and_query().cloned();
  Some(Uri::from_parts(parts).ok()?.to_string())
}
