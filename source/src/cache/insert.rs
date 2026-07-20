//! Fill coordination, admission, insertion, and revalidation orchestration.

use super::*;

impl ResponseCache {
  pub fn begin_fill(self: &Arc<Self>, ctx: CacheLookupContext<'_>) -> Option<CacheFillPermit> {
    self
      .begin_fill_decision(ctx)
      .and_then(|decision| match decision {
        CacheFillDecision::Leader(guard) => Some(CacheFillPermit::Leader(guard)),
        CacheFillDecision::Follower(waiter) => Some(CacheFillPermit::Follower(waiter)),
        CacheFillDecision::SharedConflict => Some(CacheFillPermit::SharedConflict),
        CacheFillDecision::Suppressed(_) => None,
      })
  }

  pub async fn begin_fill_async(
    self: &Arc<Self>,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheFillPermit> {
    self
      .begin_fill_decision_async(ctx)
      .await
      .and_then(|decision| match decision {
        CacheFillDecision::Leader(guard) => Some(CacheFillPermit::Leader(guard)),
        CacheFillDecision::Follower(waiter) => Some(CacheFillPermit::Follower(waiter)),
        CacheFillDecision::SharedConflict => Some(CacheFillPermit::SharedConflict),
        CacheFillDecision::Suppressed(_) => None,
      })
  }

  pub(crate) async fn begin_fill_decision_async(
    self: &Arc<Self>,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheFillDecision> {
    let key = self
      .operation_context(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        ctx.request_headers,
      )?
      .fill_key;
    let decision = self.begin_fill_decision(ctx)?;
    let CacheFillDecision::Leader(mut guard) = decision else {
      return Some(decision);
    };
    let Some(shared) = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    else {
      return Some(CacheFillDecision::Leader(guard));
    };
    match shared.cache_try_lock_result(&key).await {
      Ok(Some(shared_lock)) => {
        guard.set_shared_lock(shared_lock);
        Some(CacheFillDecision::Leader(guard))
      }
      Ok(None) => {
        drop(guard);
        Some(CacheFillDecision::SharedConflict)
      }
      Err(error) => {
        warn!(error = %error, "shared cache fill lock failed; using local fill lock");
        Some(CacheFillDecision::Leader(guard))
      }
    }
  }

  pub fn note_fill_not_stored(&self, ctx: CacheInsertContext<'_>) {
    self.note_fill_not_stored_reason(ctx, CacheFillSuppressionReason::Unknown);
  }

  pub(crate) fn note_fill_not_stored_reason(
    &self,
    ctx: CacheInsertContext<'_>,
    reason: CacheFillSuppressionReason,
  ) {
    if !self.config.lock {
      return;
    }
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return;
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return;
    }
    let Some(key) = self
      .operation_context(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        ctx.request_headers,
      )
      .map(|operation| operation.fill_key)
    else {
      return;
    };
    self.fills.suppress(key, reason);
  }

  pub fn insert(&self, ctx: CacheInsertContext<'_>, entry: CacheEntry) -> CacheInsertOutcome {
    self.insert_with_external(ctx, entry, true)
  }

  pub async fn insert_async(
    &self,
    ctx: CacheInsertContext<'_>,
    entry: CacheEntry,
  ) -> CacheInsertOutcome {
    let shared_context = ctx.clone();
    let status = entry.status;
    let headers = entry.headers.clone();
    let body_len = entry.body.len();
    let outcome = self.insert(ctx, entry);
    if outcome == CacheInsertOutcome::Stored {
      self
        .write_shared_entry_for_insert(shared_context, status, &headers, body_len)
        .await;
    }
    outcome
  }

  pub(super) fn insert_with_external(
    &self,
    ctx: CacheInsertContext<'_>,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    match self.prepare_insert(ctx, entry.status, &entry.headers, Some(entry.body.len())) {
      CachePreparedInsertDecision::Cacheable(prepared) => {
        self.insert_prepared_with_external(*prepared, entry, publish_external)
      }
      CachePreparedInsertDecision::NotCacheable(_) => CacheInsertOutcome::NotCacheable,
      CachePreparedInsertDecision::Rejected(_) => CacheInsertOutcome::Rejected,
    }
  }

  pub(crate) fn insert_prepared(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
  ) -> CacheInsertOutcome {
    self.insert_prepared_with_external(prepared, entry, true)
  }

  pub(crate) async fn insert_prepared_async(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
  ) -> CacheInsertOutcome {
    let variant_key = prepared.variant_key.clone();
    let outcome = self.insert_prepared(prepared, entry);
    if outcome == CacheInsertOutcome::Stored {
      self.write_shared_entry_for_variant(&variant_key).await;
    }
    outcome
  }

  pub(super) fn insert_prepared_with_external(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    let body_len = entry.body_len();
    let size = match body_len.checked_add(prepared.header_bytes) {
      Some(size) if size <= self.config.max_size_bytes => size,
      _ => return CacheInsertOutcome::Rejected,
    };
    let external_entry = {
      let mut inner = self.inner_guard();
      if variant_count_exceeded(
        &inner,
        &prepared.policy,
        &prepared.partition,
        &prepared.base_key,
        &prepared.variant_key,
      ) {
        return CacheInsertOutcome::Rejected;
      }
      match admit_prepared_body(
        &mut inner,
        &prepared.policy,
        &prepared.variant_key,
        body_len,
      ) {
        PreparedBodyAdmission::Admitted => {}
        PreparedBodyAdmission::Warming => return CacheInsertOutcome::AdmissionWarming,
        PreparedBodyAdmission::Rejected => return CacheInsertOutcome::Rejected,
      }
      let selected_store = select_store_for_insert(&inner, &prepared.policy, &entry.headers, size);
      let Some(body) = self.store_body(
        &prepared.policy,
        selected_store,
        &prepared.variant_key,
        &entry,
        size,
      ) else {
        return CacheInsertOutcome::StoreFailed;
      };
      let tags = extract_tags(&entry.headers, &prepared.policy);
      let stored = StoredEntry {
        policy: prepared.policy.name.clone(),
        partition: prepared.partition,
        base_key: prepared.base_key,
        variant_key: prepared.variant_key.clone(),
        scheme: prepared.scheme,
        host: prepared.host,
        uri: prepared.uri,
        status: prepared.status,
        headers: prepared.stored_headers,
        security_headers_neutral: entry.security_headers_neutral,
        body,
        expires_at: prepared.metadata.expires_at,
        stale_if_error_until: prepared.metadata.stale_if_error_until,
        stale_while_revalidate_until: prepared.metadata.stale_while_revalidate_until,
        must_revalidate: prepared.metadata.must_revalidate,
        stored_at: prepared.metadata.stored_at,
        vary: prepared.metadata.vary,
        tags,
        size,
      };
      if let Err(error) = self.persist_metadata(&stored) {
        warn!(error = %error, "failed to persist cache metadata");
        if matches!(stored.body, StoredBody::Disk(_)) {
          stored.remove_body_files();
          return CacheInsertOutcome::StoreFailed;
        }
      }
      if variant_count_exceeded(
        &inner,
        &prepared.policy,
        &stored.partition,
        &stored.base_key,
        &prepared.variant_key,
      ) {
        remove_metadata(&stored);
        stored.remove_body_files();
        return CacheInsertOutcome::Rejected;
      }
      if let Some(existing) = detach_entry(&mut inner, &prepared.variant_key) {
        remove_replaced_entry_files(existing, &stored);
      }
      add_size(&mut inner, &stored);
      inner.order.push_back(prepared.variant_key.clone());
      index_entry(&mut inner, &stored);
      let external_entry = publish_external
        .then(|| self.external_entry_for_stored(&stored))
        .flatten();
      inner.entries.insert(prepared.variant_key, stored);
      self.evict_if_needed(&mut inner, &prepared.policy);
      external_entry
    };
    if let Some((handler, metadata, body)) = external_entry {
      self.spawn_external_fill(handler, metadata, body);
    }
    CacheInsertOutcome::Stored
  }

  pub(super) async fn write_shared_entry_for_insert(
    &self,
    ctx: CacheInsertContext<'_>,
    status: StatusCode,
    headers: &HeaderMap,
    body_len: usize,
  ) {
    let Some(prepared) = (match self.prepare_insert(ctx, status, headers, Some(body_len)) {
      CachePreparedInsertDecision::Cacheable(prepared) => Some(prepared),
      CachePreparedInsertDecision::NotCacheable(_) | CachePreparedInsertDecision::Rejected(_) => {
        None
      }
    }) else {
      return;
    };
    self
      .write_shared_entry_for_variant(&prepared.variant_key)
      .await;
  }

  pub(super) async fn write_shared_entry_for_variant(&self, variant_key: &str) {
    let Some(shared) = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    else {
      return;
    };
    let shared_entry = {
      let inner = self.inner_guard();
      inner.entries.get(variant_key).and_then(shared_cache_entry)
    };
    if let Some(shared_entry) = shared_entry {
      shared.cache_put(&shared_entry).await;
    }
  }

  pub fn update_from_not_modified(
    &self,
    ctx: CacheInsertContext<'_>,
    cached_entry: &CacheEntry,
    not_modified_headers: &HeaderMap,
  ) {
    revalidation::update_from_not_modified(self, ctx, cached_entry, not_modified_headers);
  }

  pub async fn update_from_not_modified_async(
    &self,
    ctx: CacheInsertContext<'_>,
    cached_entry: &CacheEntry,
    not_modified_headers: &HeaderMap,
  ) {
    self.update_from_not_modified(ctx.clone(), cached_entry, not_modified_headers);
    let mut headers = cached_entry.headers.clone();
    for (name, value) in not_modified_headers {
      if matches!(
        name.as_str(),
        "cache-control" | "expires" | "etag" | "last-modified" | "vary"
      ) {
        headers.insert(name.clone(), value.clone());
      }
    }
    self
      .write_shared_entry_for_insert(ctx, cached_entry.status, &headers, cached_entry.body_len())
      .await;
  }

  pub fn response_head_decision(
    &self,
    ctx: CacheInsertContext<'_>,
    status: StatusCode,
    response_headers: &HeaderMap,
    content_length: Option<usize>,
  ) -> CacheResponseHeadDecision {
    match self.prepare_insert(ctx, status, response_headers, content_length) {
      CachePreparedInsertDecision::Cacheable(_) => CacheResponseHeadDecision::Cacheable,
      CachePreparedInsertDecision::NotCacheable(_) => CacheResponseHeadDecision::NotCacheable,
      CachePreparedInsertDecision::Rejected(_) => CacheResponseHeadDecision::Rejected,
    }
  }

  pub(crate) fn prepare_insert(
    &self,
    ctx: CacheInsertContext<'_>,
    status: StatusCode,
    response_headers: &HeaderMap,
    content_length: Option<usize>,
  ) -> CachePreparedInsertDecision {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    if ctx.method == Method::HEAD {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    let Some(operation) = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
    ) else {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    };
    let metadata = match cache_metadata(
      &self.config,
      &operation.policy,
      ctx.request_headers,
      status,
      response_headers,
    ) {
      Ok(metadata) => metadata,
      Err(reason) => return CachePreparedInsertDecision::NotCacheable(reason),
    };
    let stored_headers = stored_response_headers(response_headers, &self.config);
    let header_bytes = header_size(&stored_headers);
    if content_length.is_some_and(|body_len| {
      body_len
        .checked_add(header_bytes)
        .is_none_or(|size| size > self.config.max_size_bytes)
    }) {
      return CachePreparedInsertDecision::Rejected(CacheFillSuppressionReason::TooLarge);
    }
    if !admit_response_head(&operation.policy, status, response_headers, content_length) {
      return CachePreparedInsertDecision::Rejected(CacheFillSuppressionReason::AdmissionRejected);
    }
    let variant_key = variant_key(&operation.partition, &operation.base_key, &metadata.vary);
    CachePreparedInsertDecision::Cacheable(Box::new(CachePreparedInsert {
      policy: operation.policy,
      partition: operation.partition,
      base_key: operation.base_key,
      variant_key,
      scheme: operation.scheme,
      host: operation.host,
      uri: operation.uri,
      status,
      stored_headers,
      metadata,
      header_bytes,
    }))
  }
}
