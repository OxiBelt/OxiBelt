//! Bounded secondary No-Vary-Search discovery records.
//!
//! A record contains only response evidence, never an owner body or a storage
//! key. The runtime reloads the exact owner through the ordinary cache path
//! and verifies this evidence before an alias can become a hit.

use http::{HeaderMap, HeaderName, HeaderValue};
use tracing::warn;

use crate::cache::CacheNvsCandidate;

use super::{SharedCacheEntry, SharedState, SharedStateFeature};

const MAX_NVS_CANDIDATES: usize = 1024;

impl SharedState {
  pub(crate) async fn cache_nvs_candidates(
    &self,
    scope: &str,
    limit: usize,
  ) -> anyhow::Result<Vec<CacheNvsCandidate>> {
    if !valid_scope(scope) || limit == 0 {
      return Ok(Vec::new());
    }
    let result = match tokio::time::timeout(
      self.operation_timeout,
      self.cache_nvs_candidates_inner(scope, limit.min(MAX_NVS_CANDIDATES)),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow::anyhow!("shared No-Vary-Search discovery timed out")),
    };
    self.observe_backend_result(SharedStateFeature::Cache, &result);
    result
  }

  async fn cache_nvs_candidates_inner(
    &self,
    scope: &str,
    limit: usize,
  ) -> anyhow::Result<Vec<CacheNvsCandidate>> {
    let Some(backend) = &self.cache else {
      return Ok(Vec::new());
    };
    let prefix = self.shared_nvs_index_prefix(scope);
    let mut cursor = None;
    let mut inspected = 0usize;
    let mut candidates = Vec::new();
    let mut cleanup = Vec::new();
    for _ in 0..self.enumeration.max_rounds() {
      let remaining = limit
        .saturating_sub(inspected)
        .min(self.enumeration.max_items.saturating_sub(inspected));
      if remaining == 0 {
        break;
      }
      let page = backend
        .enumeration_keys(
          &prefix,
          cursor.as_ref(),
          self.enumeration.page_size.min(remaining).max(1),
          "cache_nvs_index",
        )
        .await?;
      inspected = inspected.saturating_add(page.keys.len());
      for (index_key, value) in page.keys.iter().zip(
        backend
          .enumeration_values(&page.keys, "cache_nvs_index")
          .await?,
      ) {
        let Some(value) = value else {
          cleanup.push(index_key.clone());
          continue;
        };
        let Ok(candidate) = serde_json::from_slice::<CacheNvsCandidate>(&value) else {
          cleanup.push(index_key.clone());
          continue;
        };
        if !candidate.metadata.valid()
          || candidate.metadata.scope != scope
          || candidate.metadata.candidate_limit > limit
          || !candidate_fields_bounded(&candidate)
        {
          cleanup.push(index_key.clone());
          continue;
        }
        candidates.push(candidate);
        if candidates.len() == limit {
          break;
        }
      }
      if !cleanup.is_empty() {
        backend
          .enumeration_delete(&cleanup, "cache_nvs_index")
          .await?;
        cleanup.clear();
      }
      if candidates.len() == limit {
        break;
      }
      cursor = page.next_cursor;
      if cursor.is_none() {
        break;
      }
    }
    Ok(candidates)
  }

  pub(super) async fn cache_put_nvs_index(&self, entry: &SharedCacheEntry) {
    let Some(backend) = &self.cache else {
      return;
    };
    let Some(metadata) = entry.no_vary_search.as_ref().filter(|value| value.valid()) else {
      return;
    };
    let Some(headers) = entry_headers(entry) else {
      return;
    };
    let Some(candidate) =
      CacheNvsCandidate::from_parts(metadata.clone(), &headers, entry.stored_at_ms)
    else {
      return;
    };
    let Ok(value) = serde_json::to_vec(&candidate) else {
      return;
    };
    let ttl =
      super::ttl_from_expires_ms(super::cache_store::shared_cache_retention_until_ms(entry));
    let key = self.shared_nvs_index_key(entry);
    if let Err(error) = backend.put(&key, &value, ttl).await {
      // Missing secondary discovery is a safe miss; the committed exact owner
      // remains available through every established cache path.
      warn!(error = %error, "failed to write shared No-Vary-Search index");
    }
  }

  pub(super) fn shared_nvs_index_key(&self, entry: &SharedCacheEntry) -> String {
    let Some(metadata) = entry.no_vary_search.as_ref().filter(|value| value.valid()) else {
      return self.shared_nvs_index_prefix("");
    };
    // Fixed slots bound a scope even when an origin produces unbounded owner
    // keys. Slot collisions merely evict an alias candidate and are safe.
    let digest = crate::crypto::sha256(entry.variant_key.as_bytes());
    let slot = u64::from_be_bytes([
      digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]) % metadata.candidate_limit as u64;
    format!("{}:{slot}", self.shared_nvs_index_prefix(&metadata.scope))
  }

  fn shared_nvs_index_prefix(&self, scope: &str) -> String {
    self.key(&format!("cache:nvs:{scope}"))
  }
}

fn valid_scope(scope: &str) -> bool {
  scope.len() == 64 && scope.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn candidate_fields_bounded(candidate: &CacheNvsCandidate) -> bool {
  candidate.fields.len() <= 2048
    && candidate
      .fields
      .iter()
      .try_fold(0usize, |size, field| {
        size.checked_add(field.len().checked_add(2)?)
      })
      .is_some_and(|size| size <= 4096)
}

fn entry_headers(entry: &SharedCacheEntry) -> Option<HeaderMap> {
  let mut headers = HeaderMap::new();
  for (name, value) in &entry.headers {
    headers.append(
      HeaderName::from_bytes(name.as_bytes()).ok()?,
      HeaderValue::from_bytes(value).ok()?,
    );
  }
  Some(headers)
}
