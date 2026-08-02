//! Upstream selection, outbound request construction, and cache coordination.

use super::*;

pub(super) async fn run(context: UpstreamContext<'_, '_, '_, '_, '_>) -> Response<ProxyBody> {
  let UpstreamContext {
    request,
    state,
    resolved,
    host,
    downstream_port,
    client_addr,
    forwarded_client_addr,
    forwarded_header_cache,
    tcp_max_hop,
    tls,
    protocol,
    transport_network,
    transport_metadata,
    downstream_scheme,
    request_version,
    listener_bind,
    access_log,
    trace_context,
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
    verified_early_data,
  } = context;
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  let pool_cookie_header = if request_waf.upstream_override.is_none()
    && (request_waf.upstream_pool_override.is_some() || resolved.route.upstream_pool.is_some())
  {
    request.headers().get(http::header::COOKIE)
  } else {
    None
  };
  let selected = match select_request_upstream(
    state.as_ref(),
    &resolved,
    client_addr,
    host,
    request.uri(),
    pool_cookie_header,
    &request_waf,
  )
  .await
  {
    Ok(selected) => selected,
    Err(error) => {
      return route_security.apply(upstream_selection_error_response(error));
    }
  };
  let upstream = selected.upstream;
  let upstream_index = selected.upstream_index;
  let selected_pool_name = selected.pool_name().map(str::to_string);
  let pool_retry_cookie = selected
    .pool_name()
    .and_then(|_| pool_cookie_header.cloned());
  if let Some(pool_name) = selected.pool_name() {
    if response_waf_enabled {
      access_log.upstream_pool = Some(pool_name.to_string());
    } else {
      access_log.set_upstream_pool(pool_name);
    }
  }
  let sticky_cookie = selected.sticky_cookie();
  let pool_selection = selected.into_pool_selection();
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  let native_grpc_request = semantics::is_native_grpc_request(request.headers(), &state.config);
  let mut timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  let mut grpc_timeout_caps = semantics::GrpcTimeoutCaps::default();
  if native_grpc_request {
    (timeouts, grpc_timeout_caps) = semantics::cap_timeouts_for_grpc(
      timeouts,
      request.headers(),
      state.config.proxy.http.grpc.respect_grpc_timeout,
    );
  }

  let mut upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  });
  let grpc_web_mode = if state.config.proxy.grpc_web.enabled && resolved.route.grpc_web {
    grpc_web::request_mode(request.headers())
  } else {
    None
  };
  if grpc_web_mode.is_some() {
    if upstream.max_http_version < HttpVersion::H2 {
      return route_security.text(
        StatusCode::BAD_GATEWAY,
        "gRPC-Web upstream requires HTTP/2 support",
      );
    }
    upstream_version = HttpVersion::H2;
  }

  if upstream_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
    return route_security.text(
      StatusCode::BAD_GATEWAY,
      "upstream HTTP/3 requires https origin",
    );
  }
  if upstream_version == HttpVersion::H3
    && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return route_security.text(
      StatusCode::BAD_GATEWAY,
      "PROXY protocol egress is not supported for HTTP/3 upstream",
    );
  }

  let request =
    match buffering::buffer_request_body(request, &effective_buffering, state.as_ref()).await {
      Ok(request) => request,
      Err(error) => {
        return route_security.apply(request_buffering_error_response(error));
      }
    };
  let cache_enabled_for_route = resolved.execution_plan.features.cache
    && state
      .cache
      .policy_enabled(resolved.route.cache.as_deref(), &request_method);
  let response_actions_need_request_headers =
    resolved.route.actions.response_headers.has_actions() || resolved.route.actions.cors.is_some();
  let request_headers = if cache_enabled_for_route
    || response_waf_enabled
    || native_grpc_request
    || response_actions_need_request_headers
  {
    request.headers().clone()
  } else if resolved.execution_plan.features.compression {
    compression::request_header_subset(request.headers())
  } else {
    HeaderMap::new()
  };

  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return route_security.text(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
  };
  let target_uri = match route_actions::build_resolved_upstream_uri(
    upstream_uri,
    &resolved,
    downstream_scheme,
    host,
    &request_uri,
  ) {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
      return route_security.text(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite");
    }
  };
  let route_request_mutations = route_runtime::request_header_mutations(resolved.route);

  let rebuild = RebuildRequestOptions {
    target_uri,
    compression: &state.config.compression,
    route_compression: resolved.route.compression.as_deref(),
    forwarded_client_addr,
    downstream_scheme,
    downstream_host: host,
    downstream_port,
    forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
    forwarded_header_cache,
    forwarded_request_header_values: None,
    preserve_host: upstream.preserve_host,
    authority_override: resolved
      .route
      .actions
      .rewrite
      .as_ref()
      .and_then(|rewrite| rewrite.authority.as_deref()),
    upstream_version,
    waf_mutations: &request_waf.request_header_mutations,
    route_mutations: &route_request_mutations,
    force_strip_accept_encoding: response_waf_body_compression_transform,
  };
  let mut outbound = rebuild_request(request, rebuild);
  early_data::apply_verified_upstream_header(outbound.headers_mut(), verified_early_data);
  semantics::strip_accepted_expect(outbound.headers_mut());
  semantics::apply_priority_policy(outbound.headers_mut(), state.config.proxy.http.priority);
  if let Some(mode) = grpc_web_mode {
    grpc_web::rewrite_request_headers(outbound.headers_mut(), mode);
    let (parts, body) = outbound.into_parts();
    let body = match grpc_web::decode_request_body(body, mode).await {
      Ok(body) => body,
      Err(error) => {
        warn!(error = %error, "failed to prepare gRPC-Web upstream request");
        return route_security.text(StatusCode::BAD_REQUEST, "invalid gRPC-Web request body");
      }
    };
    outbound = Request::from_parts(parts, body);
  }
  let outbound = outbound
    .map(|body| filter_trailers(body, state.config.proxy.http.trailers, native_grpc_request));
  let mut outbound = if upstream_version == HttpVersion::H3 {
    outbound
  } else {
    outbound.map(|body| {
      body::with_backpressure_send_timeout(
        body,
        timeouts.upstream_send,
        BodyTimeoutKind::UpstreamRequestSend,
      )
    })
  };
  state
    .telemetry
    .inject_trace_context(outbound.headers_mut(), trace_context);
  request_mirror::spawn_request_mirrors(
    state.clone(),
    resolved.route,
    &mut outbound,
    &request_uri,
    client_addr,
    host,
    downstream_scheme,
  );

  let mut revalidation_entry = None;
  let mut stale_on_error = None;
  let mut _cache_fill_guard = None;
  let mut cache_store_allowed = !cache_enabled_for_route || !state.config.cache.lock;
  let initial_cache_lookup = crate::cache::CacheLookupContext {
    policy_name: resolved.route.cache.as_deref(),
    scheme: downstream_scheme,
    host,
    method: &request_method,
    uri: &request_uri,
    request_headers: &request_headers,
  };
  let lookup = match state.cache.lookup_async(initial_cache_lookup.clone()).await {
    Some(lookup) => Some(lookup),
    None => {
      state
        .cache
        .lookup_external(
          initial_cache_lookup,
          state.config.proxy.buffering.temp_dir.as_deref(),
        )
        .await
    }
  };
  if let Some(lookup) = lookup {
    if let Some(response) = handle_cache_lookup_result(
      state,
      &resolved,
      lookup,
      &mut outbound,
      upstream,
      upstream_version,
      timeouts,
      downstream_scheme,
      host,
      &request_method,
      &request_uri,
      &request_headers,
      request_version,
      listener_bind,
      transport_network,
      &mut stale_on_error,
      &mut revalidation_entry,
      true,
    ) {
      return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
    }
  } else if cache_enabled_for_route {
    state.metrics.record_cache_miss();
    record_route_cache_event(state, resolved.route, "miss", "lookup");
  }

  if cache_enabled_for_route {
    loop {
      let Some(permit) = state
        .cache
        .begin_fill_decision_async(crate::cache::CacheLookupContext {
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: &request_uri,
          request_headers: &request_headers,
        })
        .await
      else {
        break;
      };
      match permit {
        crate::cache::CacheFillDecision::Leader(guard) => {
          _cache_fill_guard = Some(guard);
          cache_store_allowed = true;
          if let Some(lookup) = state
            .cache
            .lookup_async(crate::cache::CacheLookupContext {
              policy_name: resolved.route.cache.as_deref(),
              scheme: downstream_scheme,
              host,
              method: &request_method,
              uri: &request_uri,
              request_headers: &request_headers,
            })
            .await
            && let Some(response) = handle_cache_lookup_result(
              state,
              &resolved,
              lookup,
              &mut outbound,
              upstream,
              upstream_version,
              timeouts,
              downstream_scheme,
              host,
              &request_method,
              &request_uri,
              &request_headers,
              request_version,
              listener_bind,
              transport_network,
              &mut stale_on_error,
              &mut revalidation_entry,
              false,
            )
          {
            return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
          }
          break;
        }
        crate::cache::CacheFillDecision::Follower(waiter) => {
          state.metrics.record_cache_fill_waiter();
          let lock_wait_started = Instant::now();
          if !waiter
            .wait_timeout(
              state
                .cache
                .lock_wait_timeout(resolved.route.cache.as_deref()),
            )
            .await
          {
            record_route_cache_fill_stage(
              state,
              resolved.route,
              "lock_wait",
              "timeout",
              lock_wait_started,
            );
            state.metrics.record_cache_fill_lock_timeout();
            record_route_cache_event(state, resolved.route, "miss", "fill_lock_timeout");
            break;
          }
          record_route_cache_fill_stage(
            state,
            resolved.route,
            "lock_wait",
            "notified",
            lock_wait_started,
          );
          if let Some(lookup) = state
            .cache
            .lookup_async(crate::cache::CacheLookupContext {
              policy_name: resolved.route.cache.as_deref(),
              scheme: downstream_scheme,
              host,
              method: &request_method,
              uri: &request_uri,
              request_headers: &request_headers,
            })
            .await
          {
            if let Some(response) = handle_cache_lookup_result(
              state,
              &resolved,
              lookup,
              &mut outbound,
              upstream,
              upstream_version,
              timeouts,
              downstream_scheme,
              host,
              &request_method,
              &request_uri,
              &request_headers,
              request_version,
              listener_bind,
              transport_network,
              &mut stale_on_error,
              &mut revalidation_entry,
              false,
            ) {
              return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
            }
          } else {
            state.metrics.record_cache_miss();
            record_route_cache_event(state, resolved.route, "miss", "fill_not_stored");
            break;
          }
        }
        crate::cache::CacheFillDecision::SharedConflict => {
          if let Some(response) = cache_wait::wait_for_shared_fill(
            state,
            &resolved,
            &mut outbound,
            upstream,
            upstream_version,
            timeouts,
            downstream_scheme,
            host,
            &request_method,
            &request_uri,
            &request_headers,
            request_version,
            listener_bind,
            transport_network,
            &mut stale_on_error,
            &mut revalidation_entry,
          )
          .await
          {
            return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
          }
          break;
        }
        crate::cache::CacheFillDecision::Suppressed(reason) => {
          record_route_cache_event(state, resolved.route, "miss", reason.as_str());
          break;
        }
      }
    }
  }

  exchange::run(ExchangeContext {
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
    outbound,
    upstream,
    upstream_index,
    selected_pool_name,
    pool_retry_cookie,
    sticky_cookie,
    pool_selection,
    timeouts,
    grpc_timeout_caps,
    upstream_version,
    grpc_web_mode,
    native_grpc_request,
    request_headers,
    stale_on_error,
    revalidation_entry,
    cache_store_allowed,
    cache_fill_guard: _cache_fill_guard,
  })
  .await
}
