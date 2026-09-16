//! External cache L3 integration built on top of local cache policy decisions.

use super::external_handler::{
  ExternalCacheBody, ExternalCacheEntryMetadata, ExternalCacheHeader, ExternalCacheLookupHit,
  ExternalCacheLookupRequest, ExternalCacheNvsCandidatesRequest, ExternalCacheNvsEpochRequest,
  ExternalCachePublishBody, ExternalCacheQueryCleanupReport, ExternalCacheQueryCleanupRequest,
  ExternalCacheQueryEpochRequest, ExternalCacheVary, PROTOCOL_VERSION,
};
#[cfg(feature = "admin-runtime")]
use super::external_handler::{
  ExternalCachePurgeKind, ExternalCachePurgeReport, ExternalCachePurgeRequest,
};
use super::*;

impl ResponseCache {
  pub(super) async fn external_nvs_epoch(
    &self,
    target: &CacheQueryInvalidationTarget,
    advance: bool,
  ) -> Option<u64> {
    let handler = self
      .policy(Some(&target.policy))?
      .external_handler
      .as_deref()?;
    self
      .external_cache
      .nvs_epoch(
        handler,
        ExternalCacheNvsEpochRequest::new(
          target.policy.clone(),
          target.scheme.clone(),
          target.host.clone(),
          target.uri.clone(),
          advance,
        ),
      )
      .await
      .map(|response| response.target_epoch)
  }

  pub(super) async fn external_nvs_candidates(
    &self,
    policy: &str,
    scope: &str,
    limit: usize,
  ) -> Option<Vec<CacheNvsCandidate>> {
    let handler = self.policy(Some(policy))?.external_handler.as_deref()?;
    self
      .external_cache
      .nvs_candidates(
        handler,
        ExternalCacheNvsCandidatesRequest::new(policy.to_string(), scope.to_string(), limit),
      )
      .await
      .map(|response| response.candidates)
  }

  pub(super) async fn external_query_epoch(
    &self,
    target: &CacheQueryInvalidationTarget,
    advance: bool,
  ) -> Option<u64> {
    let handler = self
      .policy(Some(&target.policy))?
      .external_handler
      .as_deref()?;
    self
      .external_cache
      .query_epoch(
        handler,
        ExternalCacheQueryEpochRequest::new(
          target.policy.clone(),
          target.scheme.clone(),
          target.host.clone(),
          target.uri.clone(),
          advance,
        ),
      )
      .await
      .map(|response| response.target_epoch)
  }

  /// Reclaims Q1 records only after the authoritative epoch has advanced. This
  /// is best effort and must never be used as the invalidation fence.
  pub(crate) async fn cleanup_external_query_before_epoch(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    before_epoch: u64,
    limit: usize,
  ) -> Option<ExternalCacheQueryCleanupReport> {
    let handler = self.policy(Some(policy))?.external_handler.as_deref()?;
    self
      .external_cache
      .query_cleanup(
        handler,
        ExternalCacheQueryCleanupRequest::new(
          policy.to_string(),
          scheme.to_string(),
          host.to_string(),
          uri.to_string(),
          before_epoch,
          limit,
        ),
      )
      .await
  }

  pub(crate) async fn lookup_external(
    &self,
    ctx: CacheLookupContext<'_>,
    temp_dir: Option<&Path>,
  ) -> Option<CacheLookup> {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if super::lookup::query_context_origin_precondition_bypass(&ctx) {
      return None;
    }
    if super::lookup::cache_request_bypassed(&ctx, &self.bypass_request_headers) {
      return None;
    }
    let operation = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      super::lookup::cache_view_headers(&ctx),
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.proxy_protocol_identity,
    )?;
    if self.query_target_cache_bypassed(&operation) {
      return None;
    }
    if !self
      .bind_query_generation_async(ctx.query_identity, &operation)
      .await
    {
      return None;
    }
    let handler = operation.policy.external_handler.as_deref()?;
    let request = ExternalCacheLookupRequest::new(
      external_cache_key_version(&operation.base_key).to_string(),
      operation.policy.name.clone(),
      operation.partition.clone(),
      operation.base_key.clone(),
      operation.scheme.clone(),
      operation.host.clone(),
      operation.uri.clone(),
      ctx.method.as_str().to_string(),
      request_no_cache(super::lookup::cache_view_headers(&ctx)),
      ctx
        .query_identity
        .and_then(CacheQueryIdentity::query_target_epoch),
    );
    let hit = self
      .external_cache
      .lookup(handler, request, temp_dir)
      .await?;
    if let Some(metadata) = hit.metadata.no_vary_search.as_ref() {
      if !metadata.valid() || metadata.owner_uri != operation.uri {
        return None;
      }
      let owner_uri = metadata.owner_uri.parse::<Uri>().ok()?;
      let path_target = super::nvs::target(
        &operation.policy.name,
        &operation.scheme,
        &operation.host,
        &owner_uri,
      );
      let policy_target = super::nvs::policy_target(&operation.policy.name);
      if self.nvs_epoch(&path_target, false).await != Some(metadata.epoch)
        || self.nvs_epoch(&policy_target, false).await != Some(metadata.policy_epoch)
      {
        return None;
      }
    }
    self.external_lookup_result(operation, ctx, hit)
  }

  pub(in crate::cache) fn external_lookup_result(
    &self,
    operation: CacheOperationContext,
    ctx: CacheLookupContext<'_>,
    hit: ExternalCacheLookupHit,
  ) -> Option<CacheLookup> {
    let metadata = hit.metadata;
    metadata
      .validate_versions(external_cache_key_version(&operation.base_key))
      .ok()?;
    if is_query_v1_base_key(&operation.base_key)
      && metadata.query_target_epoch
        != ctx
          .query_identity
          .and_then(CacheQueryIdentity::query_target_epoch)
    {
      return None;
    }
    if metadata.policy != operation.policy.name
      || metadata.partition != operation.partition
      || metadata.base_key != operation.base_key
      || metadata.scheme != operation.scheme
      || metadata.host != operation.host
      || metadata.uri != operation.uri
    {
      return None;
    }
    let status = StatusCode::from_u16(metadata.status).ok()?;
    if !cacheable_status(&operation.policy, status) {
      return None;
    }
    if !metadata.security_headers_neutral {
      return None;
    }
    let headers = external_headers(&metadata.headers)?;
    let vary = external_vary_matchers(&metadata.vary, ctx.certificate_identity)?;
    if !external_vary_allowed(&vary)
      || !vary_matches(&vary, super::lookup::cache_view_headers(&ctx))
    {
      return None;
    }
    if metadata.variant_key != variant_key(&operation.partition, &operation.base_key, &vary) {
      return None;
    }
    let stored_at = system_time_from_ms(metadata.stored_at_ms)?;
    let expires_at = system_time_from_ms(metadata.expires_at_ms)?;
    if metadata.expires_at_ms < metadata.stored_at_ms {
      return None;
    }
    let now = SystemTime::now();
    let expired = expires_at <= now;
    let query_expired = is_query_v1_base_key(&metadata.base_key) && expired;
    if external_cache_retention_until_ms(&metadata) <= system_time_ms(now) {
      return None;
    }
    let stale_if_error_until = match metadata.stale_if_error_until_ms {
      Some(value) => Some(system_time_from_ms(value)?),
      None => None,
    };
    let stale_while_revalidate_until = match metadata.stale_while_revalidate_until_ms {
      Some(value) => Some(system_time_from_ms(value)?),
      None => None,
    };
    let size = metadata
      .body_len
      .checked_add(header_size(&headers))?
      .checked_add(nvs::metadata_size(metadata.no_vary_search.as_ref()))?;
    if size > self.config.max_size_bytes {
      return None;
    }
    let tags = external_tags(&metadata.tags, &operation.policy)?;
    let entry = match hit.body {
      ExternalCacheBody::Memory(body) => {
        if body.len() != metadata.body_len {
          return None;
        }
        let stored = StoredEntry {
          policy: operation.policy.name.clone(),
          no_vary_search: metadata.no_vary_search.clone(),
          partition: operation.partition.clone(),
          base_key: operation.base_key.clone(),
          variant_key: metadata.variant_key.clone(),
          scheme: operation.scheme.clone(),
          host: operation.host.clone(),
          uri: operation.uri.clone(),
          status,
          headers: headers.clone(),
          security_headers_neutral: metadata.security_headers_neutral,
          body: StoredBody::Memory(body),
          expires_at,
          stale_if_error_until,
          stale_while_revalidate_until,
          must_revalidate: metadata.must_revalidate,
          stored_at,
          vary,
          tags,
          query_target_epoch: metadata.query_target_epoch,
          size,
        };
        let entry = stored.to_cache_entry()?;
        self.promote_external_memory_entry(stored, &operation.policy);
        entry
      }
      ExternalCacheBody::TemporaryFile(file) => {
        let body_len = file.as_file().metadata().ok()?.len().try_into().ok()?;
        if body_len != metadata.body_len {
          return None;
        }
        let mut entry = CacheEntry::temporary_file(status, headers, file, body_len, stored_at)
          .with_expires_at(expires_at);
        entry.no_vary_search = metadata.no_vary_search.clone();
        entry
      }
    };
    if request_no_cache(super::lookup::cache_view_headers(&ctx))
      || metadata.must_revalidate
      || expired
    {
      let validators = validator_headers(&entry.headers);
      if query_expired
        && !request_no_cache(super::lookup::cache_view_headers(&ctx))
        && !metadata.must_revalidate
        && metadata
          .stale_while_revalidate_until_ms
          .is_some_and(|until| until > system_time_ms(now))
      {
        return Some(CacheLookup::Stale(StaleEntry {
          entry,
          request_headers: validators,
          serve_stale_on_error: metadata
            .stale_if_error_until_ms
            .is_some_and(|until| until > system_time_ms(now)),
          background_refresh: operation.policy.background_refresh,
        }));
      }
      if validators.is_empty() {
        if is_query_v1_base_key(&metadata.base_key)
          && (request_no_cache(super::lookup::cache_view_headers(&ctx)) || metadata.must_revalidate)
        {
          return None;
        }
        if query_expired
          && metadata
            .stale_while_revalidate_until_ms
            .is_some_and(|until| until > system_time_ms(now))
        {
          return Some(CacheLookup::Stale(StaleEntry {
            entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: metadata
              .stale_if_error_until_ms
              .is_some_and(|until| until > system_time_ms(now)),
            background_refresh: operation.policy.background_refresh,
          }));
        }
        if query_expired
          && metadata
            .stale_if_error_until_ms
            .is_some_and(|until| until > system_time_ms(now))
        {
          return Some(CacheLookup::Revalidate(Revalidation {
            entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: true,
          }));
        }
        return None;
      }
      return Some(CacheLookup::Revalidate(Revalidation {
        entry,
        request_headers: validators,
        serve_stale_on_error: query_expired
          && !metadata.must_revalidate
          && metadata
            .stale_if_error_until_ms
            .is_some_and(|until| until > system_time_ms(now)),
      }));
    }
    Some(CacheLookup::Fresh(entry))
  }

  fn promote_external_memory_entry(&self, stored: StoredEntry, policy: &CachePolicyRuntime) {
    if !matches!(stored.body, StoredBody::Memory(_)) || stored.size > policy.memory_max_size_bytes {
      return;
    }
    let mut inner = self.inner_guard();
    if variant_count_exceeded(
      &inner,
      policy,
      &stored.partition,
      &stored.base_key,
      &stored.variant_key,
    ) {
      return;
    }
    while inner.memory_size.saturating_add(stored.size) > policy.memory_max_size_bytes
      || total_size(&inner).saturating_add(stored.size) > self.config.max_size_bytes
    {
      let Some(oldest) = inner.order.pop_front() else {
        break;
      };
      remove_entry(&mut inner, &oldest);
    }
    if inner.memory_size.saturating_add(stored.size) > policy.memory_max_size_bytes
      || total_size(&inner).saturating_add(stored.size) > self.config.max_size_bytes
    {
      return;
    }
    if let Some(existing) = detach_entry(&mut inner, &stored.variant_key) {
      remove_replaced_entry_files(existing, &stored);
    }
    add_size(&mut inner, &stored);
    inner.order.push_back(stored.variant_key.clone());
    index_entry(&mut inner, &stored);
    inner.entries.insert(stored.variant_key.clone(), stored);
  }

  pub(in crate::cache) fn external_entry_for_stored(
    &self,
    entry: &StoredEntry,
  ) -> Option<(String, ExternalCacheEntryMetadata, ExternalCachePublishBody)> {
    let (handler, metadata) = self.external_metadata_for_stored(entry)?;
    let body = external_publish_body(entry, metadata.body_len)?;
    Some((handler, metadata, body))
  }

  pub(in crate::cache) fn external_metadata_for_stored(
    &self,
    entry: &StoredEntry,
  ) -> Option<(String, ExternalCacheEntryMetadata)> {
    let policy = self.policies.get(&entry.policy)?;
    let handler = policy.external_handler.clone()?;
    if !external_vary_allowed(&entry.vary) {
      return None;
    }
    if is_query_v1_base_key(&entry.base_key) && entry.query_target_epoch.is_none() {
      return None;
    }
    let body_len = stored_body_len(&entry.body)?;
    Some((
      handler,
      ExternalCacheEntryMetadata {
        protocol_version: PROTOCOL_VERSION.to_string(),
        cache_key_version: external_cache_key_version(&entry.base_key).to_string(),
        policy: entry.policy.clone(),
        partition: entry.partition.clone(),
        base_key: entry.base_key.clone(),
        variant_key: entry.variant_key.clone(),
        scheme: entry.scheme.clone(),
        host: entry.host.clone(),
        uri: entry.uri.clone(),
        status: entry.status.as_u16(),
        headers: entry
          .headers
          .iter()
          .map(|(name, value)| {
            ExternalCacheHeader::new(name.as_str().to_string(), value.as_bytes())
          })
          .collect(),
        security_headers_neutral: entry.security_headers_neutral,
        body_len,
        stored_at_ms: system_time_ms(entry.stored_at),
        expires_at_ms: system_time_ms(entry.expires_at),
        stale_if_error_until_ms: entry.stale_if_error_until.map(system_time_ms),
        stale_while_revalidate_until_ms: entry.stale_while_revalidate_until.map(system_time_ms),
        must_revalidate: entry.must_revalidate,
        vary: entry
          .vary
          .iter()
          .map(|item| ExternalCacheVary {
            name: item.name.clone(),
            value: item.value.clone(),
          })
          .collect(),
        tags: entry.tags.clone(),
        query_target_epoch: entry.query_target_epoch,
        no_vary_search: entry.no_vary_search.clone(),
      },
    ))
  }

  pub(in crate::cache) fn spawn_external_fill(
    &self,
    handler: String,
    metadata: ExternalCacheEntryMetadata,
    body: ExternalCachePublishBody,
  ) {
    self.external_cache.spawn_fill(handler, metadata, body);
  }

  pub(in crate::cache) fn spawn_external_revalidate(
    &self,
    handler: String,
    metadata: ExternalCacheEntryMetadata,
  ) {
    self.external_cache.spawn_revalidate(handler, metadata);
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) async fn purge_external_exact_partition(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> Vec<ExternalCachePurgeReport> {
    let mut reports = self
      .purge_external(
        policy,
        ExternalCachePurgeRequest::new(
          ExternalCachePurgeKind::Exact,
          policy.to_string(),
          Some(scheme.to_string()),
          Some(host.to_string()),
          Some(uri.to_string()),
          None,
          None,
          partition.map(str::to_string),
        ),
      )
      .await;
    reports.extend(
      self
        .purge_external(
          policy,
          ExternalCachePurgeRequest::with_cache_key_version(
            QUERY_EXTERNAL_CACHE_KEY_VERSION.to_string(),
            ExternalCachePurgeKind::Exact,
            policy.to_string(),
            Some(scheme.to_string()),
            Some(host.to_string()),
            Some(uri.to_string()),
            None,
            None,
            partition.map(str::to_string),
            None,
          ),
        )
        .await,
    );
    reports
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) async fn purge_external_prefix_partition(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> Vec<ExternalCachePurgeReport> {
    let mut reports = self
      .purge_external(
        policy,
        ExternalCachePurgeRequest::new(
          ExternalCachePurgeKind::Prefix,
          policy.to_string(),
          Some(scheme.to_string()),
          Some(host.to_string()),
          None,
          Some(path_prefix.to_string()),
          None,
          partition.map(str::to_string),
        ),
      )
      .await;
    reports.extend(
      self
        .purge_external(
          policy,
          ExternalCachePurgeRequest::with_cache_key_version(
            QUERY_EXTERNAL_CACHE_KEY_VERSION.to_string(),
            ExternalCachePurgeKind::Prefix,
            policy.to_string(),
            Some(scheme.to_string()),
            Some(host.to_string()),
            None,
            Some(path_prefix.to_string()),
            None,
            partition.map(str::to_string),
            None,
          ),
        )
        .await,
    );
    reports
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) async fn purge_external_tag_partition(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
    partition: Option<&str>,
  ) -> Vec<ExternalCachePurgeReport> {
    let mut reports = self
      .purge_external(
        policy,
        ExternalCachePurgeRequest::new(
          ExternalCachePurgeKind::Tag,
          policy.to_string(),
          scheme.map(str::to_string),
          host.map(str::to_string),
          None,
          None,
          Some(tag.to_string()),
          partition.map(str::to_string),
        ),
      )
      .await;
    reports.extend(
      self
        .purge_external(
          policy,
          ExternalCachePurgeRequest::with_cache_key_version(
            QUERY_EXTERNAL_CACHE_KEY_VERSION.to_string(),
            ExternalCachePurgeKind::Tag,
            policy.to_string(),
            scheme.map(str::to_string),
            host.map(str::to_string),
            None,
            None,
            Some(tag.to_string()),
            partition.map(str::to_string),
            None,
          ),
        )
        .await,
    );
    reports
  }

  #[cfg(feature = "admin-runtime")]
  async fn purge_external(
    &self,
    policy: &str,
    purge: ExternalCachePurgeRequest,
  ) -> Vec<ExternalCachePurgeReport> {
    // Legacy-only policies must not send a second, unsupported Q1 purge to
    // their external handler or change the Admin result shape.
    if purge.cache_key_version == QUERY_EXTERNAL_CACHE_KEY_VERSION
      && !self
        .config
        .cache_methods
        .iter()
        .any(|method| method == "QUERY")
    {
      return Vec::new();
    }
    let Some(handler) = self
      .policy(Some(policy))
      .and_then(|policy| policy.external_handler.as_deref())
    else {
      return Vec::new();
    };
    vec![self.external_cache.purge(handler, purge).await]
  }
}

fn external_cache_retention_until_ms(metadata: &ExternalCacheEntryMetadata) -> i64 {
  let mut retention = metadata.expires_at_ms;
  if is_query_v1_base_key(&metadata.base_key) {
    retention = retention
      .max(
        metadata
          .stale_if_error_until_ms
          .unwrap_or(metadata.expires_at_ms),
      )
      .max(
        metadata
          .stale_while_revalidate_until_ms
          .unwrap_or(metadata.expires_at_ms),
      );
  }
  retention
}

fn external_headers(headers: &[ExternalCacheHeader]) -> Option<HeaderMap> {
  let mut result = HeaderMap::new();
  for header in headers {
    let name = HeaderName::from_bytes(header.name.as_bytes()).ok()?;
    let value = HeaderValue::from_bytes(&header.value_bytes().ok()?).ok()?;
    result.append(name, value);
  }
  Some(result)
}

pub(super) fn external_vary_matchers(
  vary: &[ExternalCacheVary],
  certificate_identity: Option<&CacheCertificateIdentity>,
) -> Option<Vec<VaryMatcher>> {
  let mut result = Vec::with_capacity(vary.len());
  for item in vary {
    let lower = item.name.to_ascii_lowercase();
    HeaderName::from_bytes(lower.as_bytes()).ok()?;
    // Cache-produced metadata omits this matcher because the opaque base-key
    // namespace already varies by certificate. Reject external metadata that
    // attempts to carry a certificate-header value rather than accepting and
    // retaining potentially sensitive material.
    if certificate_identity
      .is_some_and(|identity| identity.header_name().as_str() == lower.as_str())
    {
      return None;
    }
    result.push(VaryMatcher {
      name: lower,
      value: item.value.clone(),
    });
  }
  result.sort_by(|left, right| left.name.cmp(&right.name));
  if result
    .windows(2)
    .any(|items| items[0].name == items[1].name)
  {
    return None;
  }
  Some(result)
}

fn external_vary_allowed(vary: &[VaryMatcher]) -> bool {
  vary.iter().all(|item| {
    !matches!(
      item.name.as_str(),
      "authorization" | "cookie" | "proxy-authorization"
    )
  })
}

fn external_tags(tags: &[String], policy: &CachePolicyRuntime) -> Option<Vec<String>> {
  if tags.len() > policy.max_tags_per_entry {
    return None;
  }
  let mut result = Vec::with_capacity(tags.len());
  for tag in tags {
    if tag.len() > policy.max_tag_bytes
      || tag.bytes().any(|byte| byte.is_ascii_control())
      || result.iter().any(|existing| existing == tag)
    {
      return None;
    }
    result.push(tag.clone());
  }
  Some(result)
}

fn stored_body_len(body: &StoredBody) -> Option<usize> {
  match body {
    StoredBody::Memory(body) => Some(body.len()),
    StoredBody::Tmpfs(path) | StoredBody::Disk(path) => {
      std::fs::metadata(path).ok()?.len().try_into().ok()
    }
  }
}

fn external_publish_body(
  entry: &StoredEntry,
  expected_body_len: usize,
) -> Option<ExternalCachePublishBody> {
  match &entry.body {
    StoredBody::Memory(body) if body.len() == expected_body_len => {
      Some(ExternalCachePublishBody::Memory(body.clone()))
    }
    StoredBody::Tmpfs(path) | StoredBody::Disk(path)
      if stored_body_len(&entry.body) == Some(expected_body_len) =>
    {
      Some(ExternalCachePublishBody::File(path.clone()))
    }
    _ => None,
  }
}

fn system_time_from_ms(value: i64) -> Option<SystemTime> {
  let value = u64::try_from(value).ok()?;
  UNIX_EPOCH.checked_add(Duration::from_millis(value))
}
