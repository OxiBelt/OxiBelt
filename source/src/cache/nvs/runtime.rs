//! Bounded secondary discovery and owner-object lookup.

use super::super::no_vary_search::{NoVarySearchParse, parse_no_vary_search};
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheNvsCandidate {
  pub metadata: CacheNvsMetadata,
  pub fields: Vec<Vec<u8>>,
  pub date_ms: i64,
}

impl CacheNvsCandidate {
  pub(crate) fn from_parts(
    metadata: CacheNvsMetadata,
    headers: &HeaderMap,
    stored_at_ms: i64,
  ) -> Option<Self> {
    let fields = fields(headers)?;
    let date_ms = headers
      .get(http::header::DATE)
      .and_then(|v| v.to_str().ok())
      .and_then(|v| httpdate::parse_http_date(v).ok())
      .map(system_time_ms)
      .unwrap_or(stored_at_ms);
    Some(Self {
      metadata,
      fields,
      date_ms,
    })
  }

  fn rule(&self) -> Option<super::super::no_vary_search::NoVarySearch> {
    if !self.metadata.valid() || self.fields.len() > 2048 {
      return None;
    }
    let mut headers = HeaderMap::new();
    let mut bytes = 0usize;
    for field in &self.fields {
      bytes = bytes.checked_add(field.len().checked_add(2)?)?;
      if bytes > 4096 {
        return None;
      }
      headers.append("no-vary-search", HeaderValue::from_bytes(field).ok()?);
    }
    match parse_no_vary_search(&headers) {
      NoVarySearchParse::Valid(rule) if !rule.is_default() => Some(rule),
      _ => None,
    }
  }
}

impl ResponseCache {
  pub fn no_vary_search_enabled(&self) -> bool {
    self.config.enabled && self.config.no_vary_search
  }

  /// Bind before origin I/O. A failed authority disables this request's aliases.
  pub(crate) async fn bind_nvs_epoch(&self, ctx: CacheLookupContext<'_>) {
    let Some(request) = ctx.no_vary_search else {
      return;
    };
    if !self.no_vary_search_enabled() {
      return;
    }
    let Some(policy) = self.policy(ctx.policy_name) else {
      return;
    };
    let target = target(&policy.name, ctx.scheme, ctx.host, ctx.uri);
    let epoch = self.nvs_epoch(&target, false).await;
    let policy_epoch = self.nvs_epoch(&policy_target(&policy.name), false).await;
    if let Ok(mut bound) = request.epoch.lock()
      && bound.is_none()
    {
      *bound = epoch.zip(policy_epoch);
    }
  }

  pub(in crate::cache) async fn nvs_epoch(
    &self,
    target: &CacheQueryInvalidationTarget,
    advance: bool,
  ) -> Option<u64> {
    let durable = if let Some(shared) = self.shared_state.as_ref().filter(|s| s.has_cache()) {
      let result = if advance {
        shared
          .cache_advance_query_epoch(&target.policy, &target.scheme, &target.host, &target.uri)
          .await
      } else {
        shared
          .cache_query_epoch(&target.policy, &target.scheme, &target.host, &target.uri)
          .await
      };
      match result {
        Ok(epoch) => Some(epoch),
        Err(_) => {
          self.mark_query_invalidation_failed(target.clone());
          return None;
        }
      }
    } else if self
      .policy(Some(&target.policy))
      .is_some_and(|p| p.external_handler.is_some())
    {
      match self.external_nvs_epoch(target, advance).await {
        Some(epoch) => Some(epoch),
        None => {
          if advance {
            self.mark_query_invalidation_failed(target.clone());
          }
          return None;
        }
      }
    } else {
      None
    };
    if advance {
      self.advance_query_generation_to(target, durable);
    } else if let Some(epoch) = durable {
      let mut inner = self.inner_guard();
      let current = inner
        .query_invalidation_generations
        .entry(super::super::lookup::query_epoch_bucket(target))
        .or_default();
      if epoch < *current {
        return None;
      }
      *current = epoch;
    }
    let inner = self.inner_guard();
    let bucket = super::super::lookup::query_epoch_bucket(target);
    if inner.failed_query_invalidations.contains(&bucket) {
      return None;
    }
    Some(
      inner
        .query_invalidation_generations
        .get(&bucket)
        .copied()
        .unwrap_or(0),
    )
  }

  pub(in crate::cache) fn prepare_nvs(
    &self,
    ctx: &CacheInsertContext<'_>,
    headers: &HeaderMap,
  ) -> Option<CacheNvsMetadata> {
    if !self.no_vary_search_enabled() || ctx.uri.to_string().len() > 16_384 {
      return None;
    }
    let request = ctx.no_vary_search?;
    if !request.origin_unchanged(headers) {
      return None;
    }
    let NoVarySearchParse::Valid(rule) = parse_no_vary_search(headers) else {
      return None;
    };
    if rule.is_default()
      || rule.canonical_query(ctx.uri).is_none()
      || rule.canonical_query(&request.effective_uri).is_none()
    {
      return None;
    }
    let (epoch, policy_epoch) = (*request.epoch.lock().ok()?)?;
    let policy = self.policy(ctx.policy_name)?;
    let lookup = CacheLookupContext {
      no_vary_search: ctx.no_vary_search,
      policy_name: ctx.policy_name,
      scheme: ctx.scheme,
      host: ctx.host,
      method: ctx.method,
      uri: ctx.uri,
      request_headers: ctx.request_headers,
      query_identity: ctx.query_identity,
      certificate_identity: ctx.certificate_identity,
      proxy_protocol_identity: ctx.proxy_protocol_identity,
    };
    Some(CacheNvsMetadata {
      version: 1,
      scope: scope(&lookup, policy)?,
      owner_uri: ctx.uri.to_string(),
      effective_uri: request.effective_uri.to_string(),
      epoch,
      policy_epoch,
      candidate_limit: policy.max_vary_variants_per_key.min(1024),
    })
  }

  pub(in crate::cache) fn nvs_current_locked(
    &self,
    inner: &CacheInner,
    policy: &str,
    scheme: &str,
    host: &str,
    metadata: &CacheNvsMetadata,
  ) -> bool {
    let Ok(uri) = metadata.owner_uri.parse() else {
      return false;
    };
    let target = target(policy, scheme, host, &uri);
    let bucket = super::super::lookup::query_epoch_bucket(&target);
    let policy_bucket = super::super::lookup::query_epoch_bucket(&policy_target(policy));
    metadata.valid()
      && !inner.failed_query_invalidations.contains(&bucket)
      && !inner.failed_query_invalidations.contains(&policy_bucket)
      && inner
        .query_invalidation_generations
        .get(&policy_bucket)
        .copied()
        .unwrap_or(0)
        == metadata.policy_epoch
      && inner
        .query_invalidation_generations
        .get(&bucket)
        .copied()
        .unwrap_or(0)
        == metadata.epoch
  }

  /// Called only after exact L1/L2/L3 misses. Every candidate is rechecked
  /// against its actual owner object; directory records alone never make hits.
  pub(crate) async fn lookup_nvs_async(
    &self,
    ctx: CacheLookupContext<'_>,
    temp_dir: Option<&Path>,
  ) -> Option<CacheLookup> {
    if !self.no_vary_search_enabled()
      || lookup::cache_request_bypassed(&ctx, &self.bypass_request_headers)
      || lookup::query_context_origin_precondition_bypass(&ctx)
    {
      return None;
    }
    let policy = self.policy(ctx.policy_name)?;
    let request = ctx.no_vary_search?;
    let scope = scope(&ctx, policy)?;
    let limit = policy.max_vary_variants_per_key.min(1024);
    let mut candidates = {
      let inner = self.inner_guard();
      inner
        .nvs_index
        .get(&scope)
        .into_iter()
        .flatten()
        .take(limit)
        .filter_map(|key| inner.entries.get(key))
        .filter_map(|entry| {
          CacheNvsCandidate::from_parts(
            entry.no_vary_search.clone()?,
            &entry.headers,
            system_time_ms(entry.stored_at),
          )
        })
        .collect::<Vec<_>>()
    };
    if let Some(shared) = self.shared_state.as_ref().filter(|s| s.has_cache())
      && let Ok(more) = shared.cache_nvs_candidates(&scope, limit).await
    {
      candidates.extend(more.into_iter().take(limit));
    }
    if let Some(more) = self
      .external_nvs_candidates(&policy.name, &scope, limit)
      .await
    {
      candidates.extend(more.into_iter().take(limit));
    }
    candidates.sort_by(|a, b| {
      b.date_ms
        .cmp(&a.date_ms)
        .then_with(|| a.metadata.owner_uri.cmp(&b.metadata.owner_uri))
    });
    candidates.truncate(limit);
    let epoch_target = target(&policy.name, ctx.scheme, ctx.host, ctx.uri);
    let epoch = self.nvs_epoch(&epoch_target, false).await?;
    let policy_epoch = self.nvs_epoch(&policy_target(&policy.name), false).await?;
    for candidate in candidates {
      let metadata = &candidate.metadata;
      if metadata.scope != scope || metadata.epoch != epoch || metadata.policy_epoch != policy_epoch
      {
        continue;
      }
      let Some(rule) = candidate.rule() else {
        continue;
      };
      let Ok(owner_uri) = metadata.owner_uri.parse::<Uri>() else {
        continue;
      };
      let Ok(effective_uri) = metadata.effective_uri.parse::<Uri>() else {
        continue;
      };
      if !rule.equivalent(ctx.uri, &owner_uri)
        || !rule.equivalent(&request.effective_uri, &effective_uri)
      {
        continue;
      }
      let identity = ctx
        .query_identity
        .map(|identity| identity.for_nvs_owner(metadata));
      let owner = CacheLookupContext {
        no_vary_search: None,
        uri: &owner_uri,
        query_identity: identity.as_ref(),
        ..ctx.clone()
      };
      let mut result = match self.lookup_async(owner.clone()).await {
        Some(result) => result,
        None => match self.lookup_external(owner, temp_dir).await {
          Some(result) => result,
          None => continue,
        },
      };
      let entry = match &mut result {
        CacheLookup::Fresh(e) => e,
        CacheLookup::Stale(s) => &mut s.entry,
        CacheLookup::Revalidate(r) => &mut r.entry,
      };
      if entry.no_vary_search.as_ref() != Some(metadata)
        || fields(&entry.headers).as_ref() != Some(&candidate.fields)
      {
        continue;
      }
      if self.nvs_epoch(&epoch_target, false).await != Some(epoch)
        || self.nvs_epoch(&policy_target(&policy.name), false).await != Some(policy_epoch)
      {
        return None;
      }
      entry.nvs_alias = true;
      return Some(result);
    }
    None
  }

  pub(crate) async fn invalidate_nvs_all_policies(
    &self,
    scheme: &str,
    host: &str,
    uri: &Uri,
  ) -> anyhow::Result<()> {
    if !self.config.enabled {
      return Ok(());
    }
    for policy in self.policies.keys() {
      let target = target(policy, scheme, host, uri);
      if self.nvs_epoch(&target, true).await.is_none() {
        // Unsupported legacy L3 handlers never admit aliases.
        if self.shared_state.as_ref().is_some_and(|s| s.has_cache()) {
          bail!("No-Vary-Search invalidation authority unavailable");
        }
      }
    }
    Ok(())
  }
}
