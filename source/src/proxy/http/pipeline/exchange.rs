//! Upstream exchange, error fallback, response WAF, buffering, and finalization.

use super::*;

pub(super) async fn run(context: ExchangeContext<'_, '_, '_, '_, '_>) -> Response<ProxyBody> {
  let ExchangeContext {
    state,
    resolved,
    host,
    client_addr,
    tcp_max_hop,
    tls,
    protocol,
    transport_network,
    transport_metadata,
    downstream_scheme,
    request_version,
    listener_bind,
    access_log,
    route_circuit_breaker_lease,
    tags,
    effective_buffering,
    request_method,
    request_uri,
    client_asn,
    response_waf_enabled,
    response_body_need,
    response_waf_body_compression_transform,
    request_waf,
    captured_body,
    mut outbound,
    mut upstream,
    mut upstream_index,
    selected_pool_name,
    pool_retry_cookie,
    mut sticky_cookie,
    mut pool_selection,
    timeouts,
    grpc_timeout_caps,
    upstream_version,
    grpc_web_mode,
    native_grpc_request,
    request_headers,
    stale_on_error,
    revalidation_entry,
    cache_store_allowed,
    cache_fill_guard,
  } = context;
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  let request_body = captured_body.as_ref().map(waf_body_input);
  let mut _cache_fill_guard = cache_fill_guard;
  let stale_if_error_response = |entry| {
    let mut response = cache_status::stale_if_error_response(
      state,
      resolved.route,
      entry,
      &request_method,
      &request_headers,
    );
    apply_response_alt_svc(
      &mut response,
      state.as_ref(),
      downstream_scheme,
      request_version,
      listener_bind,
    );
    response
  };
  debug!(
      route = %resolved.route.name,
      upstream = %upstream.name,
      method = %outbound.method(),
      uri = %outbound.uri(),
      "proxying downstream request"
  );

  let upstream_started_at = Instant::now();
  let mut report_pool_success = true;
  let upstream_response = if upstream_version == HttpVersion::H3 {
    let mut upstream_admission = match state
      .circuit_breakers
      .admit_upstream_attempt(
        &resolved.route.name,
        selected_pool_name.as_deref(),
        Instant::now().checked_add(timeouts.upstream_request),
      )
      .await
    {
      Ok(lease) => lease,
      Err(rejection) => {
        return route_security.apply(circuit_breaker_rejection_response(state, rejection));
      }
    };
    let upstream_stream_lease = match state
      .circuit_breakers
      .admit_upstream_stream(
        &resolved.route.name,
        selected_pool_name.as_deref(),
        Instant::now().checked_add(timeouts.upstream_request),
      )
      .await
    {
      Ok(lease) => lease,
      Err(rejection) => {
        return route_security.apply(circuit_breaker_rejection_response(state, rejection));
      }
    };
    match tokio::time::timeout(
      timeouts.upstream_first_byte,
      crate::proxy::http3::forward_request(outbound, upstream, state.as_ref(), timeouts),
    )
    .await
    {
      Err(_) => {
        upstream_admission.record_outcome(crate::circuit_breakers::CircuitOutcome::Failure(
          crate::circuit_breakers::CircuitOutcomeFailure::FirstByteTimeout,
        ));
        if should_report_upstream_request_failure(true, grpc_timeout_caps) {
          state.pools.report_failure_async(&upstream.name).await;
        }
        warn!(upstream = %upstream.name, "upstream HTTP/3 request timed out");
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("read_timeout", "upstream request timed out");
        if let Some(entry) = stale_on_error.clone()
          && state
            .cache
            .stale_if_error_allows_read_timeout(resolved.route.cache.as_deref())
        {
          state.metrics.record_cache_stale();
          return stale_if_error_response(entry);
        }
        return upstream_error_response(
          state,
          resolved.route,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          transport_metadata,
          request_body,
          tags_ref(&tags),
          &upstream.name,
          upstream.origin.scheme(),
          access_log.upstream_connect_time_ms,
          access_log.upstream_first_byte_time_ms,
          "read_timeout",
          "upstream request timed out",
          &request_waf.response_header_mutations,
          access_log,
        );
      }
      Ok(Ok(response)) => {
        upstream_admission.record_outcome(crate::circuit_breakers::CircuitOutcome::Failure(
          crate::circuit_breakers::CircuitOutcomeFailure::Status(response.status().as_u16()),
        ));
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        with_circuit_breaker_request_lease(response, upstream_stream_lease)
      }
      Ok(Err(error)) => {
        if let Some(rejection) = circuit_breakers::admission_rejection(&error) {
          return route_security.apply(circuit_breaker_rejection_response(state, rejection));
        }
        upstream_admission.record_outcome(crate::circuit_breakers::CircuitOutcome::Failure(
          crate::circuit_breakers::CircuitOutcomeFailure::ConnectError,
        ));
        state.pools.report_failure_async(&upstream.name).await;
        warn!(
            error = %error,
            upstream = %upstream.name,
            "upstream HTTP/3 request failed"
        );
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("connect_error", &error.to_string());
        if let Some(entry) = stale_on_error.clone()
          && state
            .cache
            .stale_if_error_allows_connect(resolved.route.cache.as_deref())
        {
          state.metrics.record_cache_stale();
          return stale_if_error_response(entry);
        }
        return upstream_error_response(
          state,
          resolved.route,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          transport_metadata,
          request_body,
          tags_ref(&tags),
          &upstream.name,
          upstream.origin.scheme(),
          access_log.upstream_connect_time_ms,
          access_log.upstream_first_byte_time_ms,
          "connect_error",
          &error.to_string(),
          &request_waf.response_header_mutations,
          access_log,
        );
      }
    }
  } else {
    let mut pool_failures_reported = false;
    let result = if upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off {
      let Some(client) = state.clients.for_upstream_version(
        &upstream.name,
        upstream.origin.scheme(),
        upstream_version,
      ) else {
        warn!(
            upstream = %upstream.name,
            "missing upstream client pool"
        );
        return route_security.text(StatusCode::BAD_GATEWAY, "upstream client is not configured");
      };
      let early_hints_capture =
        semantics::attach_early_hints_capture(&mut outbound, state.config.proxy.http.early_hints);
      let retry_policy = if native_grpc_request {
        EffectiveRetryPolicy::for_grpc_request(
          &state.config,
          resolved.route,
          semantics::should_retry_grpc(&state.config),
        )
      } else if pool_selection.is_some() {
        EffectiveRetryPolicy::for_http_request(&state.config, resolved.route, &request_method)
      } else {
        EffectiveRetryPolicy::for_direct_http_request(
          &state.config,
          resolved.route,
          &request_method,
        )
      };
      if let Some(selection) = pool_selection.take() {
        pool_failures_reported = true;
        send_pool_with_retry(
          state.as_ref(),
          outbound,
          upstream_index,
          selection,
          resolved.route,
          &request_uri,
          &resolved.path_captures,
          client_addr,
          host,
          downstream_scheme,
          pool_retry_cookie.as_ref(),
          &request_waf,
          timeouts,
          &retry_policy,
        )
        .await
        .map(|success| {
          upstream_index = success.upstream_index;
          upstream = &state.upstreams[upstream_index];
          access_log.set_upstream(&upstream.name, upstream.origin.scheme());
          report_pool_success = success.report_success;
          sticky_cookie = success.pool_selection.sticky_cookie();
          pool_selection = Some(success.pool_selection);
          let mut response = success.response;
          if let Some(capture) = early_hints_capture {
            semantics::attach_interim_responses(&mut response, capture.take());
          }
          response
        })
      } else {
        let result = if retry_policy.enabled {
          send_with_retry(
            client,
            outbound,
            timeouts,
            state,
            &retry_policy,
            Some(RetryAdmissionContext {
              route_name: &resolved.route.name,
              pool_name: None,
            }),
          )
          .await
        } else {
          send_one_shot_with_state(
            client,
            outbound,
            timeouts,
            state.as_ref(),
            Some(RetryAdmissionContext {
              route_name: &resolved.route.name,
              pool_name: None,
            }),
          )
          .await
        };
        result.map(|mut response| {
          if let Some(capture) = early_hints_capture {
            semantics::attach_interim_responses(&mut response, capture.take());
          }
          response
        })
      }
    } else {
      send_one_shot_with_proxy_protocol(
        outbound,
        upstream,
        state,
        selected_pool_name.as_deref(),
        upstream_version,
        client_addr,
        timeouts,
      )
      .await
    };
    match result {
      Ok(mut response) => {
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let stream_lease = retry::take_stream_lease(&mut response);
        let response = response.map(|body| body.map_err(boxed_error).boxed());
        match stream_lease {
          Some(lease) => with_circuit_breaker_request_lease(response, lease),
          None => response,
        }
      }
      Err(error) => {
        if error_indicates_body_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return route_security.text(StatusCode::REQUEST_TIMEOUT, "request body timed out");
        }
        if let Some(rejection) = circuit_breakers::admission_rejection(&error) {
          return route_security.apply(circuit_breaker_rejection_response(state, rejection));
        }
        let upstream_first_byte_timeout = error_is_upstream_first_byte_timeout(&error);
        if !pool_failures_reported
          && should_report_upstream_request_failure(upstream_first_byte_timeout, grpc_timeout_caps)
        {
          state.pools.report_failure_async(&upstream.name).await;
        }
        warn!(
            error = %error,
            error_debug = ?error,
            upstream = %upstream.name,
            "upstream request failed"
        );
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let error_message = error.to_string();
        let error_code = if upstream_first_byte_timeout || error_message.contains("timed out") {
          "read_timeout"
        } else {
          "connect_error"
        };
        access_log.record_upstream_error(error_code, &error_message);
        if let Some(entry) = stale_on_error.clone()
          && if error_code == "read_timeout" {
            state
              .cache
              .stale_if_error_allows_read_timeout(resolved.route.cache.as_deref())
          } else {
            state
              .cache
              .stale_if_error_allows_connect(resolved.route.cache.as_deref())
          }
        {
          state.metrics.record_cache_stale();
          return stale_if_error_response(entry);
        }
        return upstream_error_response(
          state,
          resolved.route,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          transport_metadata,
          request_body,
          tags_ref(&tags),
          &upstream.name,
          upstream.origin.scheme(),
          access_log.upstream_connect_time_ms,
          access_log.upstream_first_byte_time_ms,
          error_code,
          &error_message,
          &request_waf.response_header_mutations,
          access_log,
        );
      }
    }
  };
  if report_pool_success {
    if let Some(latency_ms) = access_log.upstream_first_byte_time_ms {
      state
        .pools
        .report_success_latency_async(&upstream.name, latency_ms)
        .await;
    } else {
      state.pools.report_success_async(&upstream.name).await;
    }
  }
  drop(pool_selection);

  let upstream_response = if let Some(mode) = grpc_web_mode {
    grpc_web::encode_response(upstream_response, mode)
  } else {
    upstream_response
  };
  let (mut parts, body) = upstream_response.into_parts();
  if let Some(entry) = stale_on_error.clone()
    && state
      .cache
      .stale_if_error_allows_status(resolved.route.cache.as_deref(), parts.status)
  {
    state.metrics.record_cache_stale();
    return stale_if_error_response(entry);
  }
  if parts.status == StatusCode::NOT_MODIFIED
    && let Some(entry) = revalidation_entry.clone()
  {
    if cache_store_allowed {
      state
        .cache
        .update_from_not_modified_async(
          crate::cache::CacheInsertContext {
            policy_name: resolved.route.cache.as_deref(),
            scheme: downstream_scheme,
            host,
            method: &request_method,
            uri: &request_uri,
            request_headers: &request_headers,
          },
          &entry,
          &parts.headers,
        )
        .await;
    }
    let mut cached_entry = entry;
    let mut headers = cached_entry.headers.clone();
    merge_not_modified_headers(&mut headers, &parts.headers);
    cached_entry.headers = headers;
    state.metrics.record_cache_hit();
    record_cache_hit_fast_path_selection(state, request_version);
    let mut response =
      cache_status::cached_entry_response(cached_entry, &request_method, &request_headers);
    cache_status::reconcile_cached_security(&mut response, state, resolved.route);
    route_runtime::apply_response_actions(response.headers_mut(), resolved.route, &request_headers);
    cache_status::apply(
      &mut response,
      CacheOutcome::Revalidated,
      CacheReason::NotModified,
    );
    apply_response_alt_svc(
      &mut response,
      state.as_ref(),
      downstream_scheme,
      request_version,
      listener_bind,
    );
    let response = compression::maybe_compress_response(
      response,
      &request_method,
      &request_headers,
      resolved.route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    );
    return with_downstream_response_timeout(
      response,
      timeouts.response_send,
      transport_network,
      true,
    );
  }
  let body = body::with_read_timeout(
    body,
    timeouts.upstream_read,
    BodyTimeoutKind::UpstreamResponseRead,
  );
  strip_hop_by_hop_headers(&mut parts.headers);
  if state.config.proxy.http.trailers == crate::config::TrailerMode::Drop && !native_grpc_request {
    parts.headers.remove(http::header::TRAILER);
  }
  semantics::apply_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
  let applied_route_security_headers = apply_route_security_headers_with_snapshot(
    &mut parts.headers,
    &state.config.security,
    resolved.route,
  );
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  let response_inspection_lease = if response_body_need != BodyNeed::None {
    match state
      .circuit_breakers
      .admit_body_inspection(&resolved.route.name, None)
      .await
    {
      Ok(lease) => Some(lease),
      Err(rejection) => {
        return route_security.apply(circuit_breaker_rejection_response(state, rejection));
      }
    }
  } else {
    None
  };
  let response_decompression_lease = if response_waf_body_compression_transform {
    match state
      .circuit_breakers
      .admit_decompression(&resolved.route.name, None)
      .await
    {
      Ok(lease) => Some(lease),
      Err(rejection) => {
        return route_security.apply(circuit_breaker_rejection_response(state, rejection));
      }
    }
  } else {
    None
  };
  let (body, captured_response_body) = if response_body_need != BodyNeed::None {
    match capture_response_body_for_waf(
      parts.version,
      &mut parts.headers,
      body,
      response_body_need,
      state.config.waf.limits.max_body_inspection_bytes,
      response_waf_body_compression_transform,
      &state.config.waf.http_body_compression,
      &state.waf_body_coding,
    )
    .await
    {
      Ok(result) => result,
      Err(error) => {
        let (status, message) = response_body_capture_error_response(&error);
        warn!(error = %error, status = status.as_u16(), "failed to read upstream response body for WAF inspection");
        return route_security.text(status, message);
      }
    }
  } else {
    (body, None)
  };
  let response_body = captured_response_body.as_ref().map(waf_body_input);

  if response_waf_enabled {
    access_log.ensure_response_ids();
    access_log.response_received_at_unix_ms = crate::waf::current_unix_ms();
    let request_input = WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: &request_headers,
      body: request_body,
      peer_addr: client_addr,
      client_asn,
      downstream_host: host,
      downstream_scheme,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      tags: tags_ref(&tags),
      dynamic_policy: &access_log.dynamic_policy,
    };
    let Some(person_proof) = access_log.person_proof_snapshot() else {
      tracing::error!(route = %resolved.route.name, "response WAF request context is unavailable");
      return route_security.text(
        StatusCode::INTERNAL_SERVER_ERROR,
        "response security context is unavailable",
      );
    };
    let response_waf = state.waf.evaluate_response_with_person_proof_snapshot(
      WafResponseInput {
        request: request_input,
        response_id: access_log.response_id(),
        received_at_unix_ms: access_log.response_received_at_unix_ms,
        version: parts.version,
        status: parts.status,
        headers: &parts.headers,
        body: response_body,
        upstream_name: &upstream.name,
        upstream_pool: access_log.upstream_pool.as_deref(),
        upstream_scheme: upstream.origin.scheme(),
        upstream_connect_time_ms: access_log.upstream_connect_time_ms,
        upstream_first_byte_time_ms: access_log.upstream_first_byte_time_ms,
        upstream_error: None,
      },
      person_proof,
    );
    for access_log in &response_waf.access_logs {
      state.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return route_security.waf_http_terminal(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }
  drop(response_decompression_lease);
  drop(response_inspection_lease);
  route_runtime::apply_response_actions(&mut parts.headers, resolved.route, &request_headers);
  cache_status::strip_headers(&mut parts.headers);
  let mut response_buffering = effective_buffering.response;
  if state.config.proxy.http.sse_auto_streaming && semantics::is_sse(&parts.headers) {
    response_buffering.mode = crate::config::BufferingMode::Streaming;
  }
  let body = filter_trailers(body, state.config.proxy.http.trailers, native_grpc_request);
  let body = match buffering::buffer_body(
    body,
    response_buffering,
    effective_buffering.temp_dir.as_deref(),
  )
  .await
  {
    Ok(body) => body,
    Err(error) => {
      return route_security.apply(response_buffering_error_response(error));
    }
  };

  let mut response = maybe_cache_response_with_store_permission(
    Response::from_parts(parts, body),
    state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    host,
    &request_method,
    &request_uri,
    &request_headers,
    Some(resolved.route),
    cache_store_allowed,
    _cache_fill_guard.take(),
    Some(&applied_route_security_headers),
  )
  .await;
  let response_status = response.status();
  apply_alt_svc_header(
    response.headers_mut(),
    response_status,
    state.as_ref(),
    downstream_scheme,
    request_version,
    listener_bind,
  );
  let response = compression::maybe_compress_response(
    response,
    &request_method,
    &request_headers,
    resolved.route.compression.as_deref(),
    &state.config.compression,
    &state.compression,
  );
  let mut response =
    with_downstream_response_timeout(response, timeouts.response_send, transport_network, true);
  apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
  let response = with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
  state.record_hot_path_response(response.status());
  response
}
