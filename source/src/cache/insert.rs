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
    let operation = self.operation_context_with_dictionary(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      super::lookup::cache_view_headers(&ctx),
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.dictionary_identity,
      ctx.proxy_protocol_identity,
      ctx.group_request,
    )?;
    if !self
      .bind_query_generation_async(ctx.query_identity, &operation)
      .await
    {
      return None;
    }
    let key = operation.fill_key;
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
    if cache_insert_request_bypassed(&ctx, &self.bypass_request_headers) {
      return;
    }
    let Some(key) = self
      .operation_context_with_dictionary(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        cache_insert_view_headers(&ctx),
        ctx.query_identity,
        ctx.certificate_identity,
        ctx.dictionary_identity,
        ctx.proxy_protocol_identity,
        ctx.group_request,
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
    if ctx.method.as_str() == "QUERY" {
      let Some(operation) = self.operation_context_with_dictionary(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        cache_insert_view_headers(&ctx),
        ctx.query_identity,
        ctx.certificate_identity,
        ctx.dictionary_identity,
        ctx.proxy_protocol_identity,
        ctx.group_request,
      ) else {
        return CacheInsertOutcome::NotCacheable;
      };
      if !self
        .bind_query_generation_async(ctx.query_identity, &operation)
        .await
      {
        return CacheInsertOutcome::NotCacheable;
      }
    }
    match self.prepare_insert(ctx, entry.status, &entry.headers, Some(entry.body_len())) {
      CachePreparedInsertDecision::Cacheable(prepared) => {
        self.insert_prepared_async(*prepared, entry).await
      }
      CachePreparedInsertDecision::NotCacheable(_) => CacheInsertOutcome::NotCacheable,
      CachePreparedInsertDecision::Rejected(_) => CacheInsertOutcome::Rejected,
    }
  }

  pub(super) fn insert_with_external(
    &self,
    ctx: CacheInsertContext<'_>,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    match self.prepare_insert(ctx, entry.status, &entry.headers, Some(entry.body.len())) {
      CachePreparedInsertDecision::Cacheable(mut prepared) => {
        if entry.group_stamp.is_some() {
          prepared.group_stamp = entry.group_stamp.clone();
          // Promotion retains an already-authorized remote representation.
          prepared.group_published = true;
        }
        if prepared.no_vary_search.is_none() {
          prepared.no_vary_search = entry
            .no_vary_search
            .clone()
            .filter(|nvs| nvs.valid() && nvs.owner_uri == prepared.uri);
          prepared.header_bytes = header_size(&prepared.stored_headers)
            .saturating_add(nvs::metadata_size(prepared.no_vary_search.as_ref()))
            .saturating_add(groups::metadata_size(prepared.group_stamp.as_ref()));
        }
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
    mut prepared: CachePreparedInsert,
    entry: CacheEntry,
  ) -> CacheInsertOutcome {
    let publication = match self.publish_group_prepared(&prepared).await {
      Ok(publication) => publication,
      Err(_) => return CacheInsertOutcome::NotCacheable,
    };
    prepared.group_published = true;
    // Negotiate L3 group support before the synchronous metadata builder runs.
    // Legacy or unavailable handlers suppress only external publication.
    let _ = self
      .external_group_publish_capable(&prepared.policy.name)
      .await;
    let variant_key = prepared.variant_key.clone();
    let outcome = self.insert_prepared(prepared, entry);
    if outcome == CacheInsertOutcome::Stored {
      self.write_shared_entry_for_variant(&variant_key).await;
    } else if let Some(publication) = publication {
      self.rollback_group_publication(publication).await;
    }
    outcome
  }

  pub(super) fn insert_prepared_with_external(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    let publication = match self.publish_group_prepared_local(&prepared) {
      Ok(publication) => publication,
      Err(_) => return CacheInsertOutcome::NotCacheable,
    };
    let outcome = self.insert_prepared_with_external_published(prepared, entry, publish_external);
    if outcome != CacheInsertOutcome::Stored
      && let Some(publication) = publication
    {
      self.rollback_group_publication_local(publication);
    }
    outcome
  }

  fn insert_prepared_with_external_published(
    &self,
    prepared: CachePreparedInsert,
    entry: CacheEntry,
    publish_external: bool,
  ) -> CacheInsertOutcome {
    if self.prepared_query_cache_bypassed(&prepared) {
      return CacheInsertOutcome::NotCacheable;
    }
    let body_len = entry.body_len();
    let size = match body_len.checked_add(prepared.header_bytes) {
      Some(size) if size <= self.config.max_size_bytes => size,
      _ => return CacheInsertOutcome::Rejected,
    };
    let external_entry = {
      let mut inner = self.inner_guard();
      if !self.prepared_generation_current_locked(&inner, &prepared) {
        return CacheInsertOutcome::NotCacheable;
      }
      if self.variant_count_exceeded(
        &mut inner,
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
        group_stamp: prepared.group_stamp,
        no_vary_search: prepared.no_vary_search,
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
        query_target_epoch: prepared.query_generation.as_ref().map(|bound| bound.value),
        dictionary_identity: prepared.dictionary_identity,
        size,
      };
      if let Err(error) = self.persist_metadata(&stored) {
        warn!(error = %error, "failed to persist cache metadata");
        if matches!(stored.body, StoredBody::Disk(_)) {
          stored.remove_body_files();
          return CacheInsertOutcome::StoreFailed;
        }
      }
      if self.variant_count_exceeded(
        &mut inner,
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
    // Group authorities may be remote. Request paths must await their atomic
    // old/new membership check through update_from_not_modified_async.
    if self.groups_enabled(ctx.policy_name.unwrap_or("default")) {
      return;
    }
    revalidation::update_from_not_modified(self, ctx, cached_entry, not_modified_headers);
  }

  pub async fn update_from_not_modified_async(
    &self,
    ctx: CacheInsertContext<'_>,
    cached_entry: &CacheEntry,
    not_modified_headers: &HeaderMap,
  ) -> bool {
    if self.groups_enabled(ctx.policy_name.unwrap_or("default")) {
      let Some(previous) = cached_entry.group_stamp.as_ref() else {
        return false;
      };
      let mut headers = cached_entry.headers.clone();
      for name in [
        "cache-control",
        "expires",
        "etag",
        "last-modified",
        "vary",
        "cache-groups",
        "cache-group-invalidation",
        "no-vary-search",
        "repr-digest",
        "unencoded-digest",
      ] {
        if not_modified_headers.contains_key(name) {
          headers.remove(name);
          for value in not_modified_headers.get_all(name) {
            headers.append(name, value.clone());
          }
        }
      }
      let CachePreparedInsertDecision::Cacheable(mut prepared) = self.prepare_insert(
        ctx,
        cached_entry.status,
        &headers,
        Some(cached_entry.body_len()),
      ) else {
        return false;
      };
      prepared.group_previous = Some(previous.clone());
      if !not_modified_headers.contains_key("no-vary-search") {
        prepared.no_vary_search = cached_entry.no_vary_search.clone();
      }
      let mut entry = cached_entry.clone();
      entry.headers = headers;
      return self.insert_prepared_async(*prepared, entry).await == CacheInsertOutcome::Stored;
    }
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
    revalidation::merge_nvs_not_modified_headers(&mut headers, not_modified_headers);
    revalidation::merge_digest_not_modified_headers(&mut headers, not_modified_headers);
    self
      .write_shared_entry_for_insert(ctx, cached_entry.status, &headers, cached_entry.body_len())
      .await;
    true
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
    if cache_insert_request_bypassed(&ctx, &self.bypass_request_headers) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    let Some(operation) = self.operation_context_with_dictionary(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      cache_insert_view_headers(&ctx),
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.dictionary_identity,
      ctx.proxy_protocol_identity,
      ctx.group_request,
    ) else {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    };
    if self.query_target_cache_bypassed(&operation) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    if self.fills.is_fenced(&operation.fill_key) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    if !self.bind_query_generation(ctx.query_identity, &operation) {
      return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
    }
    let metadata = match cache_metadata(
      &self.config,
      &operation.policy,
      cache_insert_origin_vary_headers(&ctx),
      ctx.certificate_identity,
      status,
      response_headers,
    ) {
      Ok(metadata) => metadata,
      Err(reason) => return CachePreparedInsertDecision::NotCacheable(reason),
    };
    let mut group_stamp = match self.prepare_group_stamp(
      &ctx,
      response_headers,
      extract_tags(response_headers, &operation.policy),
    ) {
      Ok(stamp) => stamp,
      Err(_) => {
        return CachePreparedInsertDecision::NotCacheable(CacheFillSuppressionReason::Unknown);
      }
    };
    let stored_headers = stored_response_headers(response_headers, &self.config);
    let no_vary_search = self.prepare_nvs(&ctx, &stored_headers);
    if let Some(stamp) = &mut group_stamp {
      stamp.equivalent_path = no_vary_search
        .as_ref()
        .and_then(|nvs| nvs.owner_uri.parse::<Uri>().ok())
        .map(|uri| uri.path().to_string());
    }
    let header_bytes = header_size(&stored_headers)
      .saturating_add(nvs::metadata_size(no_vary_search.as_ref()))
      .saturating_add(groups::metadata_size(group_stamp.as_ref()));
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
    let mut variant_key = variant_key(&operation.partition, &operation.base_key, &metadata.vary);
    if let Some(stamp) = &group_stamp {
      variant_key.push_str(&format!(
        "\ngroup-generation={}:{}",
        stamp.incarnation, stamp.sequence
      ));
    }
    CachePreparedInsertDecision::Cacheable(Box::new(CachePreparedInsert {
      group_stamp,
      group_previous: None,
      group_published: false,
      no_vary_search,
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
      dictionary_identity: operation.dictionary_identity,
      header_bytes,
      fill_key: operation.fill_key,
      query_target: operation.query_target,
      query_generation: ctx.query_identity.and_then(|identity| {
        identity
          .generation
          .lock()
          .unwrap_or_else(|error| error.into_inner())
          .clone()
      }),
    }))
  }
}

pub(in crate::cache) fn cache_insert_view_headers<'a>(
  ctx: &'a CacheInsertContext<'_>,
) -> &'a HeaderMap {
  ctx
    .query_identity
    .map(CacheQueryIdentity::cache_view_headers)
    .unwrap_or(ctx.request_headers)
}

pub(in crate::cache) fn cache_insert_origin_vary_headers<'a>(
  ctx: &'a CacheInsertContext<'_>,
) -> &'a HeaderMap {
  ctx
    .origin_vary_headers
    .unwrap_or_else(|| cache_insert_view_headers(ctx))
}

fn cache_insert_request_bypassed(
  ctx: &CacheInsertContext<'_>,
  bypass_headers: &[HeaderName],
) -> bool {
  request_no_store(ctx.request_headers, bypass_headers)
    || ctx
      .query_identity
      .is_some_and(|identity| request_no_store(identity.cache_view_headers(), bypass_headers))
}
