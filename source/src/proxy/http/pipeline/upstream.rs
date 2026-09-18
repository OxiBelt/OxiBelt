//! Upstream selection, outbound request construction, and cache coordination.

use super::*;

pub(in crate::proxy::http) async fn run(
  context: UpstreamContext<'_, '_, '_, '_, '_>,
) -> Response<ProxyBody> {
  let UpstreamContext {
    mut request,
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
  // A resumable relay must observe the origin exchange itself: cache hits,
  // fills, and stale/revalidation paths can neither forward live 1xx nor
  // preserve the request's one-shot semantics. This is deliberately separate
  // from Incremental, whose deadline and admission behavior is unchanged.
  let resumable_cache_bypass = resumable::request_marked(&request);
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
  access_log.proxy_tls_enabled = upstream.proxy_protocol_tls.is_some();
  if let Err(status) = proxy_tls::prepare(&mut request, upstream, client_addr) {
    return route_security.text(status, "PROXY TLS metadata is unavailable or inconsistent");
  }
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

  let mut upstream_version = select_route_upstream_http_version(
    resolved.route,
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
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

  if !effective_buffering.request.is_streaming() && !request.body().is_end_stream() {
    if incremental::request_marked(&request) {
      return route_security.apply(incremental::refused(request_version));
    }
    request
      .extensions_mut()
      .insert(incremental::BodyWasBuffered);
  }
  let request = if request
    .extensions()
    .get::<query::capture::OriginalQuery>()
    .is_some()
  {
    request
  } else {
    match buffering::buffer_request_body(request, &effective_buffering, state.as_ref()).await {
      Ok(request) => request,
      Err(error) => {
        return route_security.apply(request_buffering_error_response(error));
      }
    }
  };
  let cache_enabled_for_route = resolved.execution_plan.features.cache
    && state
      .cache
      .policy_enabled(resolved.route.cache.as_deref(), &request_method)
    && !resumable_cache_bypass;
  let response_actions_need_request_headers =
    resolved.route.actions.response_headers.has_actions() || resolved.route.actions.cors.is_some();
  let mut request_headers = if cache_enabled_for_route
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
  client_certificate::strip_reserved(&mut request_headers, state);

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
  incremental::latch_request(&mut outbound);
  let incremental_upload = incremental::request_marked(&outbound);
  if incremental_upload
    && outbound
      .extensions()
      .get::<incremental::BodyWasBuffered>()
      .is_some()
  {
    return route_security.apply(incremental::refused(request_version));
  }
  early_data::apply_verified_upstream_header(outbound.headers_mut(), verified_early_data);
  semantics::strip_accepted_expect(outbound.headers_mut());
  semantics::apply_priority_policy(outbound.headers_mut(), state.config.proxy.http.priority);
  if let Some(mode) = grpc_web_mode {
    grpc_web::rewrite_request_headers(outbound.headers_mut(), mode);
    let (parts, body) = outbound.into_parts();
    let body = match grpc_web::decode_request_body(body, mode, incremental_upload).await {
      Ok(body) => body,
      Err(error) => {
        warn!(error = %error, "failed to prepare gRPC-Web upstream request");
        return route_security.text(StatusCode::BAD_REQUEST, "invalid gRPC-Web request body");
      }
    };
    outbound = Request::from_parts(parts, body);
  }
  let mut identity_headers = state
    .external_auth
    .identity_headers_for(resolved.route.external_auth.as_deref());
  identity_headers.extend(state.client_certificate_forwarding_headers.iter().cloned());
  let outbound = outbound.map(|body| {
    let body = filter_trailers(body, state.config.proxy.http.trailers, native_grpc_request);
    semantics::sanitize_upstream_request_trailers(
      body,
      identity_headers,
      state.client_certificate_forwarding_header_aliases.clone(),
    )
  });
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
  if let Err(status) = client_certificate::apply_upstream(&mut outbound, state) {
    return route_security.text(status, "client certificate forwarding failed");
  }
  let certificate_identity = client_certificate::cache_identity(&outbound).cloned();
  proxy_tls::apply_upstream(&mut outbound);
  let proxy_protocol_identity = proxy_tls::cache_identity(&outbound).cloned();
  if let Err(message) = query::validate_content_type(outbound.method(), outbound.headers()) {
    return route_security.text(StatusCode::BAD_REQUEST, message);
  }
  let mut outbound = match query::prepare_cache_request(outbound, &effective_buffering, state).await
  {
    Ok(outbound) => outbound,
    Err(error) => return route_security.apply(request_buffering_error_response(error)),
  };
  let group_request = outbound
    .extensions()
    .get::<crate::cache::CacheGroupRequest>()
    .cloned();
  let query_identity = outbound
    .extensions()
    .get::<crate::cache::CacheQueryIdentity>()
    .cloned();
  if let Some(original) = outbound.extensions().get::<query::capture::OriginalQuery>() {
    request_headers = original.headers.clone();
    client_certificate::strip_reserved(&mut request_headers, state);
  }
  // NVS aliases are only safe after request WAF mutations and route rewrites
  // have produced the actual origin request. Response-WAF routes remain exact
  // because cached hits do not rerun response inspection.
  let no_vary_search = if cache_enabled_for_route
    && state.cache.no_vary_search_enabled()
    && !response_waf_enabled
  {
    let material = format!(
      "nvs-proxy-v1|route={:?}|upstream={:?}|pool={:?}|version={:?}|request_waf={:?}|response_headers={:?}",
      resolved.execution_plan.nvs_context_fingerprint,
      upstream.name,
      selected_pool_name,
      upstream_version,
      request_waf.request_header_mutations,
      request_waf.response_header_mutations,
    );
    crate::cache::CacheNvsRequest::new(outbound.uri().clone(), material.as_bytes())
  } else {
    None
  };
  if let Some(no_vary_search) = no_vary_search.as_ref() {
    outbound.extensions_mut().insert(no_vary_search.clone());
    state
      .cache
      .bind_nvs_epoch(crate::cache::CacheLookupContext {
        group_request: group_request.as_ref(),
        no_vary_search: Some(no_vary_search),
        query_identity: query_identity.as_ref(),
        proxy_protocol_identity: proxy_protocol_identity.as_ref(),
        certificate_identity: certificate_identity.as_ref(),
        policy_name: resolved.route.cache.as_deref(),
        scheme: downstream_scheme,
        host,
        method: &request_method,
        uri: &request_uri,
        request_headers: &request_headers,
      })
      .await;
  }
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
  let mut cache_store_allowed =
    !resumable_cache_bypass && (!cache_enabled_for_route || !state.config.cache.lock);
  let nvs_original_headers = no_vary_search.as_ref().map(|_| outbound.headers().clone());
  let initial_cache_lookup = crate::cache::CacheLookupContext {
    group_request: group_request.as_ref(),
    no_vary_search: None,
    query_identity: query_identity.as_ref(),
    proxy_protocol_identity: proxy_protocol_identity.as_ref(),
    certificate_identity: certificate_identity.as_ref(),
    policy_name: resolved.route.cache.as_deref(),
    scheme: downstream_scheme,
    host,
    method: &request_method,
    uri: &request_uri,
    request_headers: &request_headers,
  };
  let lookup = if cache_enabled_for_route {
    match state.cache.lookup_async(initial_cache_lookup.clone()).await {
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
    }
  } else {
    None
  };
  let lookup = if lookup.is_some() {
    lookup
  } else if let Some(no_vary_search) = no_vary_search.as_ref() {
    state
      .cache
      .lookup_nvs_async(
        crate::cache::CacheLookupContext {
          group_request: group_request.as_ref(),
          no_vary_search: Some(no_vary_search),
          query_identity: query_identity.as_ref(),
          proxy_protocol_identity: proxy_protocol_identity.as_ref(),
          certificate_identity: certificate_identity.as_ref(),
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: &request_uri,
          request_headers: &request_headers,
        },
        state.config.proxy.buffering.temp_dir.as_deref(),
      )
      .await
  } else {
    None
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

  if cache_enabled_for_route && !incremental_upload {
    // An NVS alias revalidation sends a conditional request for its owner.
    // Coordinate the fill under that owner key, while every post-wait cache
    // read below remains anchored to the original alias and rechecks NVS.
    loop {
      let owner_fill_metadata = revalidation_entry
        .as_ref()
        .filter(|entry| entry.nvs_alias)
        .and_then(|entry| entry.no_vary_search.as_ref());
      let owner_fill_uri =
        owner_fill_metadata.and_then(|metadata| metadata.owner_uri.parse::<http::Uri>().ok());
      let owner_revalidation = owner_fill_uri.is_some();
      let owner_fill_query_identity = owner_fill_metadata.and_then(|metadata| {
        query_identity
          .as_ref()
          .map(|identity| identity.for_nvs_owner(metadata))
      });
      let fill_uri = owner_fill_uri.as_ref().unwrap_or(&request_uri);
      let fill_query_identity = owner_fill_query_identity
        .as_ref()
        .or(query_identity.as_ref());
      let Some(permit) = state
        .cache
        .begin_fill_decision_async(crate::cache::CacheLookupContext {
          group_request: group_request.as_ref(),
          no_vary_search: None,
          query_identity: fill_query_identity,
          proxy_protocol_identity: proxy_protocol_identity.as_ref(),
          certificate_identity: certificate_identity.as_ref(),
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: fill_uri,
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
          let lookup = state
            .cache
            .lookup_async(crate::cache::CacheLookupContext {
              group_request: group_request.as_ref(),
              no_vary_search: None,
              query_identity: query_identity.as_ref(),
              proxy_protocol_identity: proxy_protocol_identity.as_ref(),
              certificate_identity: certificate_identity.as_ref(),
              policy_name: resolved.route.cache.as_deref(),
              scheme: downstream_scheme,
              host,
              method: &request_method,
              uri: &request_uri,
              request_headers: &request_headers,
            })
            .await;
          let lookup = if lookup.is_some() {
            lookup
          } else {
            lookup_nvs_for_original_alias(
              state,
              no_vary_search.as_ref(),
              query_identity.as_ref(),
              proxy_protocol_identity.as_ref(),
              certificate_identity.as_ref(),
              resolved.route.cache.as_deref(),
              downstream_scheme,
              host,
              &request_method,
              &request_uri,
              &request_headers,
              group_request.as_ref(),
            )
            .await
          };
          if let Some(lookup) = lookup
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
          let lookup = state
            .cache
            .lookup_async(crate::cache::CacheLookupContext {
              group_request: group_request.as_ref(),
              no_vary_search: None,
              query_identity: query_identity.as_ref(),
              proxy_protocol_identity: proxy_protocol_identity.as_ref(),
              certificate_identity: certificate_identity.as_ref(),
              policy_name: resolved.route.cache.as_deref(),
              scheme: downstream_scheme,
              host,
              method: &request_method,
              uri: &request_uri,
              request_headers: &request_headers,
            })
            .await;
          let lookup = if lookup.is_some() {
            lookup
          } else {
            lookup_nvs_for_original_alias(
              state,
              no_vary_search.as_ref(),
              query_identity.as_ref(),
              proxy_protocol_identity.as_ref(),
              certificate_identity.as_ref(),
              resolved.route.cache.as_deref(),
              downstream_scheme,
              host,
              &request_method,
              &request_uri,
              &request_headers,
              group_request.as_ref(),
            )
            .await
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
              false,
            ) {
              let mut response = response;
              cache_wait::mark_collapsed_follower_response(&mut response);
              return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
            }
          } else {
            state.metrics.record_cache_miss();
            record_route_cache_event(state, resolved.route, "miss", "fill_not_stored");
            break;
          }
        }
        crate::cache::CacheFillDecision::SharedConflict => {
          if owner_revalidation {
            if let Some(lookup) = wait_for_shared_nvs_alias_fill(
              state,
              &resolved,
              no_vary_search.as_ref(),
              query_identity.as_ref(),
              proxy_protocol_identity.as_ref(),
              certificate_identity.as_ref(),
              resolved.route.cache.as_deref(),
              downstream_scheme,
              host,
              &request_method,
              &request_uri,
              &request_headers,
              group_request.as_ref(),
            )
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
              let mut response = response;
              cache_wait::mark_collapsed_follower_response(&mut response);
              return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
            }
            break;
          }
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
          if let Some(lookup) = lookup_nvs_for_original_alias(
            state,
            no_vary_search.as_ref(),
            query_identity.as_ref(),
            proxy_protocol_identity.as_ref(),
            certificate_identity.as_ref(),
            resolved.route.cache.as_deref(),
            downstream_scheme,
            host,
            &request_method,
            &request_uri,
            &request_headers,
            group_request.as_ref(),
          )
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
            let mut response = response;
            cache_wait::mark_collapsed_follower_response(&mut response);
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

  if let Some(entry) = revalidation_entry.as_ref().filter(|entry| entry.nvs_alias)
    && !state
      .cache
      .nvs_owner_current(
        crate::cache::CacheLookupContext {
          group_request: group_request.as_ref(),
          no_vary_search: no_vary_search.as_ref(),
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: &request_uri,
          request_headers: &request_headers,
          query_identity: query_identity.as_ref(),
          certificate_identity: certificate_identity.as_ref(),
          proxy_protocol_identity: proxy_protocol_identity.as_ref(),
        },
        entry,
      )
      .await
  {
    // A leader or purge replaced the owner's policy while this alias waited.
    // Its former validators and response may no longer authorize this alias.
    if let Some(request) = no_vary_search.as_ref() {
      *outbound.uri_mut() = request.effective_uri.clone();
    }
    if let Some(headers) = nvs_original_headers {
      *outbound.headers_mut() = headers;
    }
    if let Some(identity) = query_identity.as_ref() {
      outbound.extensions_mut().insert(identity.clone());
    }
    outbound
      .extensions_mut()
      .remove::<cache_operations::NvsOwnerTarget>();
    revalidation_entry = None;
    stale_on_error = None;
    cache_store_allowed = false;
    drop(_cache_fill_guard.take());
  }

  if incremental_upload {
    let exchange = if upstream_version == HttpVersion::H3 {
      incremental_exchange::IncrementalExchange::new()
    } else {
      incremental_exchange::IncrementalExchange::with_upload_deadline(
        timeouts.incremental_upload_deadline(),
      )
    };
    if upstream_version == HttpVersion::H3 {
      exchange.arm_unstarted_upload();
    } else {
      outbound =
        outbound.map(|body| incremental_exchange::wrap_request_body(body, exchange.clone()));
    }
    outbound.extensions_mut().insert(exchange);
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
    no_vary_search,
    certificate_identity,
    proxy_protocol_identity,
    stale_on_error,
    revalidation_entry,
    cache_store_allowed,
    cache_fill_guard: _cache_fill_guard,
  })
  .await
}

const SHARED_FILL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

#[allow(clippy::too_many_arguments)]
async fn wait_for_shared_nvs_alias_fill(
  state: &AppSnapshot,
  resolved: &crate::routes::ResolvedRoute<'_>,
  no_vary_search: Option<&crate::cache::CacheNvsRequest>,
  query_identity: Option<&crate::cache::CacheQueryIdentity>,
  proxy_protocol_identity: Option<&crate::cache::CacheProxyProtocolIdentity>,
  certificate_identity: Option<&crate::cache::CacheCertificateIdentity>,
  policy_name: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
  group_request: Option<&crate::cache::CacheGroupRequest>,
) -> Option<crate::cache::CacheLookup> {
  state.metrics.record_cache_fill_lock_conflict();
  record_route_cache_event(state, resolved.route, "miss", "shared_lock_conflict");
  let started = Instant::now();
  let timeout = state.cache.lock_wait_timeout(policy_name);
  loop {
    let elapsed = started.elapsed();
    if elapsed >= timeout {
      record_route_cache_fill_stage(state, resolved.route, "lock_wait", "timeout", started);
      state.metrics.record_cache_fill_lock_timeout();
      record_route_cache_event(state, resolved.route, "miss", "fill_lock_timeout");
      return None;
    }
    tokio::time::sleep(SHARED_FILL_POLL_INTERVAL.min(timeout - elapsed)).await;
    let exact = state
      .cache
      .lookup_async(crate::cache::CacheLookupContext {
        group_request,
        no_vary_search: None,
        query_identity,
        proxy_protocol_identity,
        certificate_identity,
        policy_name,
        scheme,
        host,
        method,
        uri,
        request_headers,
      })
      .await;
    let lookup = if exact.is_some() {
      exact
    } else {
      lookup_nvs_for_original_alias(
        state,
        no_vary_search,
        query_identity,
        proxy_protocol_identity,
        certificate_identity,
        policy_name,
        scheme,
        host,
        method,
        uri,
        request_headers,
        group_request,
      )
      .await
    };
    if lookup.is_some() {
      record_route_cache_fill_stage(state, resolved.route, "lock_wait", "shared_lookup", started);
      return lookup;
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn lookup_nvs_for_original_alias(
  state: &AppSnapshot,
  no_vary_search: Option<&crate::cache::CacheNvsRequest>,
  query_identity: Option<&crate::cache::CacheQueryIdentity>,
  proxy_protocol_identity: Option<&crate::cache::CacheProxyProtocolIdentity>,
  certificate_identity: Option<&crate::cache::CacheCertificateIdentity>,
  policy_name: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
  request_headers: &HeaderMap,
  group_request: Option<&crate::cache::CacheGroupRequest>,
) -> Option<crate::cache::CacheLookup> {
  state
    .cache
    .lookup_nvs_async(
      crate::cache::CacheLookupContext {
        group_request,
        no_vary_search: Some(no_vary_search?),
        query_identity,
        proxy_protocol_identity,
        certificate_identity,
        policy_name,
        scheme,
        host,
        method,
        uri,
        request_headers,
      },
      state.config.proxy.buffering.temp_dir.as_deref(),
    )
    .await
}
