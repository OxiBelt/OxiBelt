//! Cache lookup projection, response insertion, revalidation, and body collection.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_cache_lookup_result(
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  lookup: crate::cache::CacheLookup,
  outbound: &mut Request<ProxyBody>,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  downstream_scheme: &'static str,
  host: &str,
  request_method: &Method,
  request_uri: &http::Uri,
  request_headers: &HeaderMap,
  request_version: http::Version,
  listener_bind: Option<SocketAddr>,
  transport_network: WafTransportNetwork,
  stale_on_error: &mut Option<crate::cache::CacheEntry>,
  revalidation_entry: &mut Option<crate::cache::CacheEntry>,
  record_events: bool,
) -> Option<Response<ProxyBody>> {
  match lookup {
    crate::cache::CacheLookup::Fresh(entry) => {
      if cache_entry_blocked_by_waf_body_transform(state.as_ref(), resolved, &entry) {
        return None;
      }
      state.metrics.record_cache_hit();
      record_cache_hit_fast_path_selection(state, request_version);
      if record_events {
        record_route_cache_event(state, resolved.route, "hit", "fresh");
      }
      let mut response = cache_status::cached_downstream_response(
        state,
        resolved.route,
        entry,
        request_method,
        request_headers,
        timeouts,
        transport_network,
        CacheOutcome::Hit,
        CacheReason::Fresh,
      );
      route_runtime::apply_response_actions(
        response.headers_mut(),
        resolved.route,
        request_headers,
      );
      apply_response_alt_svc(
        &mut response,
        state.as_ref(),
        downstream_scheme,
        request_version,
        listener_bind,
      );
      Some(response)
    }
    crate::cache::CacheLookup::Stale(stale) => {
      let stale_blocked_by_transform =
        cache_entry_blocked_by_waf_body_transform(state.as_ref(), resolved, &stale.entry);
      if stale.background_refresh
        && !stale_blocked_by_transform
        && cache_refresh::can_background_refresh(
          resolved.execution_plan.waf,
          upstream,
          upstream_version,
        )
        && cache_refresh::spawn_background_refresh(
          state.clone(),
          outbound,
          upstream,
          upstream_version,
          timeouts,
          resolved.route.cache.as_deref(),
          resolved.route.security_headers.as_deref(),
          downstream_scheme,
          host.to_string(),
          request_method.clone(),
          request_uri.clone(),
          request_headers.clone(),
          stale.clone(),
        )
      {
        state.metrics.record_cache_stale();
        if record_events {
          record_route_cache_event(state, resolved.route, "stale", "background_refresh");
        }
        let mut response = cache_status::cached_downstream_response(
          state,
          resolved.route,
          stale.entry,
          request_method,
          request_headers,
          timeouts,
          transport_network,
          CacheOutcome::Stale,
          CacheReason::BackgroundRefresh,
        );
        route_runtime::apply_response_actions(
          response.headers_mut(),
          resolved.route,
          request_headers,
        );
        apply_response_alt_svc(
          &mut response,
          state.as_ref(),
          downstream_scheme,
          request_version,
          listener_bind,
        );
        return Some(response);
      }
      if !stale.request_headers.is_empty() {
        state.metrics.record_cache_revalidation();
        if record_events {
          record_route_cache_event(state, resolved.route, "revalidate", "stale_validators");
        }
        for (name, value) in &stale.request_headers {
          outbound.headers_mut().insert(name.clone(), value.clone());
        }
        if !stale_blocked_by_transform {
          if stale.serve_stale_on_error {
            *stale_on_error = Some(stale.entry.clone());
          }
          *revalidation_entry = Some(stale.entry);
        }
        None
      } else {
        if stale_blocked_by_transform {
          return None;
        }
        state.metrics.record_cache_hit();
        record_cache_hit_fast_path_selection(state, request_version);
        if record_events {
          record_route_cache_event(state, resolved.route, "hit", "stale_without_validators");
        }
        let mut response = cache_status::cached_downstream_response(
          state,
          resolved.route,
          stale.entry,
          request_method,
          request_headers,
          timeouts,
          transport_network,
          CacheOutcome::Stale,
          CacheReason::StaleWithoutValidators,
        );
        route_runtime::apply_response_actions(
          response.headers_mut(),
          resolved.route,
          request_headers,
        );
        apply_response_alt_svc(
          &mut response,
          state.as_ref(),
          downstream_scheme,
          request_version,
          listener_bind,
        );
        Some(response)
      }
    }
    crate::cache::CacheLookup::Revalidate(revalidation) => {
      let revalidation_blocked_by_transform =
        cache_entry_blocked_by_waf_body_transform(state.as_ref(), resolved, &revalidation.entry);
      state.metrics.record_cache_revalidation();
      if record_events {
        record_route_cache_event(state, resolved.route, "revalidate", "explicit");
      }
      for (name, value) in &revalidation.request_headers {
        outbound.headers_mut().insert(name.clone(), value.clone());
      }
      if !revalidation_blocked_by_transform {
        if revalidation.serve_stale_on_error {
          *stale_on_error = Some(revalidation.entry.clone());
        }
        *revalidation_entry = Some(revalidation.entry);
      }
      None
    }
  }
}

pub(super) fn record_cache_hit_fast_path_selection(
  state: &AppSnapshot,
  request_version: http::Version,
) {
  let protocol = match request_version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => "h1",
    http::Version::HTTP_2 => "h2",
    http::Version::HTTP_3 => "h3",
    _ => "other",
  };
  state
    .metrics
    .record_fast_path_selection("cache_hit", protocol, "selected", "used");
}

pub(super) fn cache_entry_blocked_by_waf_body_transform(
  state: &AppSnapshot,
  resolved: &crate::routes::ResolvedRoute<'_>,
  entry: &crate::cache::CacheEntry,
) -> bool {
  crate::waf::route_http_body_compression_transform_enabled(&state.config, resolved.route)
    && resolved.execution_plan.waf.response.body_need() != BodyNeed::None
    && has_non_identity_content_encoding(&entry.headers)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) async fn maybe_cache_response(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
  route: Option<&RouteConfig>,
) -> Response<ProxyBody> {
  maybe_cache_response_with_store_permission(
    response,
    state,
    route_cache,
    scheme,
    host,
    method,
    uri,
    request_headers,
    route,
    true,
    None,
    None,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn maybe_cache_response_with_store_permission(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
  route: Option<&RouteConfig>,
  allow_store: bool,
  mut cache_fill_guard: Option<crate::cache::CacheFillGuard>,
  applied_route_security_headers: Option<&AppliedRouteSecurityHeaders>,
) -> Response<ProxyBody> {
  if !state.request_path_features.cache || !state.cache.policy_enabled(route_cache, method) {
    let mut response = response;
    cache_status::strip_headers(response.headers_mut());
    return response;
  }
  let (mut parts, mut body) = response.into_parts();
  cache_status::strip_headers(&mut parts.headers);
  let mut cache_headers = parts.headers.clone();
  if let Some(applied) = applied_route_security_headers {
    neutralize_applied_route_security_headers(&mut cache_headers, applied);
  }
  if !allow_store {
    if state.cache.strip_surrogate_control(route_cache) {
      parts.headers.remove("surrogate-control");
    }
    let mut response = Response::from_parts(parts, body);
    cache_status::apply(
      &mut response,
      CacheOutcome::Miss,
      CacheReason::StoreNotAllowed,
    );
    return response;
  }
  let content_length = cache_streaming::exact_response_content_length(&cache_headers);
  let insert_ctx = || crate::cache::CacheInsertContext {
    policy_name: route_cache,
    scheme,
    host,
    method,
    uri,
    request_headers,
  };
  let record_fill_stage = |stage: &str, outcome: &str, started: Instant| {
    if let Some(route) = route {
      record_route_cache_fill_stage(state, route, stage, outcome, started);
    }
  };
  let head_started = Instant::now();
  let prepared =
    match state
      .cache
      .prepare_insert(insert_ctx(), parts.status, &cache_headers, content_length)
    {
      crate::cache::CachePreparedInsertDecision::Cacheable(prepared) => {
        record_fill_stage("head_decision", "cacheable", head_started);
        prepared
      }
      crate::cache::CachePreparedInsertDecision::Rejected(reason) => {
        record_fill_stage("head_decision", reason.as_str(), head_started);
        state.metrics.record_cache_admission_rejection();
        state
          .cache
          .note_fill_not_stored_reason(insert_ctx(), reason);
        if state.cache.strip_surrogate_control(route_cache) {
          parts.headers.remove("surrogate-control");
        }
        let mut response = Response::from_parts(parts, body);
        cache_status::apply(
          &mut response,
          CacheOutcome::Miss,
          CacheReason::from_rejection(reason),
        );
        return response;
      }
      crate::cache::CachePreparedInsertDecision::NotCacheable(reason) => {
        record_fill_stage("head_decision", reason.as_str(), head_started);
        state
          .cache
          .note_fill_not_stored_reason(insert_ctx(), reason);
        if state.cache.strip_surrogate_control(route_cache) {
          parts.headers.remove("surrogate-control");
        }
        let mut response = Response::from_parts(parts, body);
        cache_status::apply(
          &mut response,
          CacheOutcome::Miss,
          CacheReason::from_rejection(reason),
        );
        return response;
      }
    };
  let collect_limit = cache_streaming::response_collect_limit(&state.config);
  let body_size_hint = body.size_hint();
  let known_body_len =
    content_length.or_else(|| cache_streaming::exact_body_size_hint_len(&body_size_hint));
  if known_body_len.is_none_or(|len| len > collect_limit) {
    if let Some(expected_body_len) = known_body_len {
      match cache_streaming::maybe_stream_cache_response(
        state,
        route_cache,
        scheme,
        host,
        method,
        uri,
        request_headers,
        route,
        parts,
        body,
        prepared,
        expected_body_len,
        cache_fill_guard.take(),
      ) {
        Ok(response) => return response,
        Err(returned) => {
          let (returned_parts, returned_body) = *returned;
          parts = returned_parts;
          body = returned_body;
        }
      }
    }
    record_fill_stage("body_collect", "too_large", Instant::now());
    state.cache.note_fill_not_stored_reason(
      insert_ctx(),
      crate::cache::CacheFillSuppressionReason::TooLarge,
    );
    if state.cache.strip_surrogate_control(route_cache) {
      parts.headers.remove("surrogate-control");
      cache_headers.remove("surrogate-control");
    }
    let mut response = Response::from_parts(parts, body);
    cache_status::apply(&mut response, CacheOutcome::Miss, CacheReason::TooLarge);
    return response;
  }
  let collect_started = Instant::now();
  match collect_cache_response_body(body, collect_limit).await {
    Ok(bytes) => {
      record_fill_stage("body_collect", "ok", collect_started);
      if state.cache.strip_surrogate_control(route_cache) {
        parts.headers.remove("surrogate-control");
        cache_headers.remove("surrogate-control");
      }
      let store_started = Instant::now();
      let reason = match state
        .cache
        .insert_prepared_async(
          *prepared,
          crate::cache::CacheEntry::memory(parts.status, cache_headers.clone(), bytes.clone()),
        )
        .await
      {
        crate::cache::CacheInsertOutcome::Rejected => {
          record_fill_stage("local_store", "rejected", store_started);
          state.metrics.record_cache_admission_rejection();
          state.cache.note_fill_not_stored_reason(
            insert_ctx(),
            crate::cache::CacheFillSuppressionReason::AdmissionRejected,
          );
          CacheReason::AdmissionRejected
        }
        crate::cache::CacheInsertOutcome::AdmissionWarming => {
          record_fill_stage("local_store", "admission_warming", store_started);
          state.metrics.record_cache_admission_rejection();
          CacheReason::AdmissionWarming
        }
        crate::cache::CacheInsertOutcome::StoreFailed => {
          record_fill_stage("local_store", "store_failed", store_started);
          state.metrics.record_cache_fill_error();
          state.cache.note_fill_not_stored_reason(
            insert_ctx(),
            crate::cache::CacheFillSuppressionReason::StoreFailed,
          );
          CacheReason::StoreFailed
        }
        crate::cache::CacheInsertOutcome::NotCacheable => {
          record_fill_stage("local_store", "not_cacheable", store_started);
          state.cache.note_fill_not_stored(insert_ctx());
          CacheReason::NotCacheable
        }
        crate::cache::CacheInsertOutcome::Stored => {
          record_fill_stage("local_store", "stored", store_started);
          if state.cache.shared_cache_enabled() {
            record_fill_stage("shared_store", "submitted", Instant::now());
          }
          CacheReason::Stored
        }
      };
      let body_len = bytes.len();
      let mut response = Response::from_parts(parts, full_body(bytes));
      cache_status::apply(&mut response, CacheOutcome::Miss, reason);
      if body::is_known_small_response_body_len(body_len) {
        response
          .extensions_mut()
          .insert(body::KnownSmallResponseBody);
      }
      response
    }
    Err(error) if error_is_timeout(&error, BodyTimeoutKind::UpstreamResponseRead) => {
      record_fill_stage("body_collect", "timeout", collect_started);
      state.metrics.record_cache_fill_error();
      cache_status::store_failed_response(text_response(
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      ))
    }
    Err(error) => {
      record_fill_stage("body_collect", "error", collect_started);
      state.metrics.record_cache_fill_error();
      cache_status::store_failed_response(text_response(
        StatusCode::BAD_GATEWAY,
        &format!("failed to read upstream response body: {error}"),
      ))
    }
  }
}

pub(super) async fn collect_cache_response_body(
  mut body: ProxyBody,
  limit: usize,
) -> Result<bytes::Bytes, self::body::BoxError> {
  let mut chunks = Vec::new();
  let mut total = 0usize;
  while let Some(frame) = body.frame().await {
    let frame = frame?;
    let Ok(data) = frame.into_data() else {
      continue;
    };
    total = total
      .checked_add(data.len())
      .ok_or_else(|| boxed_error(std::io::Error::other("cache fill body length overflow")))?;
    if total > limit {
      return Err(boxed_error(std::io::Error::other(
        "cache fill body exceeds memory limit",
      )));
    }
    chunks.push(data);
  }

  if chunks.len() == 1 {
    return Ok(chunks.pop().unwrap_or_default());
  }
  let mut bytes = bytes::BytesMut::with_capacity(total);
  for chunk in chunks {
    bytes.extend_from_slice(&chunk);
  }
  Ok(bytes.freeze())
}

pub(super) fn merge_not_modified_headers(headers: &mut HeaderMap, not_modified: &HeaderMap) {
  for (name, value) in not_modified {
    if matches!(
      name.as_str(),
      "cache-control" | "expires" | "etag" | "last-modified" | "vary"
    ) {
      headers.insert(name.clone(), value.clone());
    }
  }
}

pub(super) fn full_body(bytes: bytes::Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> self::body::BoxError { match never {} })
    .boxed()
}
