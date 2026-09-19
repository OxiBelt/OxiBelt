//! Upstream exchange, error fallback, response WAF, buffering, and finalization.

use super::*;

#[derive(Clone)]
struct NvsAliasReplay {
  method: Method,
  uri: http::Uri,
  version: http::Version,
  headers: HeaderMap,
  query_snapshot: Option<query::capture::QueryReplaySnapshot>,
  query_identity: Option<crate::cache::CacheQueryIdentity>,
}

pub(super) async fn run(context: ExchangeContext<'_, '_, '_, '_, '_>) -> Response<ProxyBody> {
  let incremental_request = incremental::request_marked(&context.outbound);
  let request_version = context.request_version;
  let exchange = context
    .outbound
    .extensions()
    .get::<incremental_exchange::IncrementalExchange>()
    .cloned();
  let response_guard = exchange.as_ref().map(|exchange| exchange.begin_response());
  let mut response = run_inner(context).await;
  incremental::adapt_admission_rejection(&mut response, incremental_request, request_version);
  if let Some(exchange) = exchange {
    if response
      .extensions()
      .get::<incremental_exchange::IncrementalExchange>()
      .is_none()
    {
      // A local refusal/error replaced the upstream response: stop its upload.
      exchange.cancel();
      exchange.mark_response_complete();
      response
        .extensions_mut()
        .insert(incremental::LocalTerminalResponse);
    }
    response.extensions_mut().insert(exchange);
  }
  if let Some(guard) = response_guard
    && response
      .extensions()
      .get::<incremental::LocalTerminalResponse>()
      .is_none()
  {
    guard.disarm();
  }
  response
}

async fn run_inner(context: ExchangeContext<'_, '_, '_, '_, '_>) -> Response<ProxyBody> {
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
    mut no_vary_search,
    certificate_identity,
    proxy_protocol_identity,
    mut stale_on_error,
    mut revalidation_entry,
    mut cache_store_allowed,
    cache_fill_guard,
  } = context;
  let digest_request = outbound
    .extensions()
    .get::<integrity_digest::DigestRequest>()
    .cloned();
  let group_request = outbound
    .extensions()
    .get::<crate::cache::CacheGroupRequest>()
    .cloned();
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  let incremental_exchange = outbound
    .extensions()
    .get::<incremental_exchange::IncrementalExchange>()
    .cloned();
  let upstream_response_observed = outbound
    .extensions()
    .get::<resumable::UpstreamResponseObserved>()
    .cloned();
  let proxy_tls_certificate = proxy_tls::has_certificate_identity(&outbound);
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
  // Cache QUERY identity is captured before any transport attempt consumes
  // the outbound body. It is later handed to both 304 revalidation and the
  // cache-store response path without changing their public call shape.
  let mut query_identity = outbound
    .extensions()
    .get::<crate::cache::CacheQueryIdentity>()
    .cloned();
  let revalidation_owner_uri = revalidation_entry
    .as_ref()
    .filter(|entry| entry.nvs_alias)
    .and_then(|entry| entry.no_vary_search.as_ref())
    .and_then(|metadata| metadata.owner_uri.parse::<http::Uri>().ok());
  let revalidation_owner_nvs = revalidation_entry
    .as_ref()
    .filter(|entry| entry.nvs_alias)
    .and_then(|entry| entry.no_vary_search.as_ref())
    .and_then(|metadata| no_vary_search.as_ref()?.for_owner(metadata));
  // A rejected alias 304 may need an unconditional replay. Keep that replay
  // inside the upstream request budget that started before the conditional
  // owner request, including reopening a QUERY snapshot.
  let nvs_alias_deadline = revalidation_entry
    .as_ref()
    .filter(|entry| entry.nvs_alias)
    .and_then(|_| {
      timeouts
        .upstream_deadline
        .or_else(|| std::time::Instant::now().checked_add(timeouts.upstream_request))
    });
  // A 304 is only safe to turn back into a cached body while the stored
  // representation still belongs to the current cache-group generation.
  // Keep an unconditional replay of the original request so an invalidated
  // representation can be refetched within the same upstream deadline.
  let revalidation_replay_deadline = revalidation_entry.as_ref().and_then(|_| {
    timeouts
      .upstream_deadline
      .or_else(|| std::time::Instant::now().checked_add(timeouts.upstream_request))
  });
  let revalidation_replay = revalidation_entry.as_ref().map(|_| {
    let mut headers = outbound.headers().clone();
    headers.remove(http::header::IF_NONE_MATCH);
    headers.remove(http::header::IF_MODIFIED_SINCE);
    NvsAliasReplay {
      method: outbound.method().clone(),
      uri: request_uri.clone(),
      version: outbound.version(),
      headers,
      query_snapshot: outbound
        .extensions()
        .get::<query::capture::QueryReplaySnapshot>()
        .cloned(),
      query_identity: outbound
        .extensions()
        .get::<crate::cache::CacheQueryIdentity>()
        .cloned(),
    }
  });
  let alias_replay = revalidation_entry
    .as_ref()
    .filter(|entry| entry.nvs_alias)
    .and(no_vary_search.as_ref())
    .map(|request| {
      let mut headers = outbound.headers().clone();
      headers.remove(http::header::IF_NONE_MATCH);
      headers.remove(http::header::IF_MODIFIED_SINCE);
      NvsAliasReplay {
        method: outbound.method().clone(),
        uri: request.effective_uri.clone(),
        version: outbound.version(),
        headers,
        query_snapshot: outbound
          .extensions()
          .get::<query::capture::QueryReplaySnapshot>()
          .cloned(),
        query_identity: outbound
          .extensions()
          .get::<cache_operations::NvsAliasQueryIdentity>()
          .map(|identity| identity.0.clone()),
      }
    });
  let mut report_pool_success = true;
  let upstream_response = if upstream_version == HttpVersion::H3 {
    let retry_policy = if native_grpc_request {
      EffectiveRetryPolicy::for_grpc_request(
        &state.config,
        resolved.route,
        semantics::should_retry_grpc(&state.config),
      )
    } else {
      EffectiveRetryPolicy::for_http_request(&state.config, resolved.route, &request_method)
    };
    let mut pool_failures_reported = false;
    let result = if let Some(selection) = pool_selection.take() {
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
        if !success.cache_identity_unchanged {
          no_vary_search = None;
          // A pool retry selected a new effective origin target. Forward the
          // response, but bypass QUERY cache insertion rather than binding it
          // to the identity captured for the first target.
          query_identity = None;
          if query::is_query(&request_method) {
            stale_on_error = None;
            revalidation_entry = None;
          }
        }
        upstream_index = success.upstream_index;
        upstream = &state.upstreams[upstream_index];
        access_log.set_upstream(&upstream.name, upstream.origin.scheme());
        report_pool_success = success.report_success;
        sticky_cookie = success.pool_selection.sticky_cookie();
        pool_selection = Some(success.pool_selection);
        success.response
      })
    } else {
      send_h3_with_retry(
        outbound,
        upstream,
        timeouts,
        state,
        &retry_policy,
        Some(RetryAdmissionContext {
          route_name: &resolved.route.name,
          pool_name: selected_pool_name.as_deref(),
        }),
      )
      .await
    };
    match result {
      Ok(mut response) => {
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let stream_lease = retry::take_stream_lease(&mut response);
        if let Some(exchange) = &incremental_exchange {
          response.extensions_mut().insert(exchange.clone());
          if let Some(lease) = stream_lease {
            exchange.retain(lease);
          }
          response
        } else if let Some(lease) = stream_lease {
          with_circuit_breaker_request_lease(response, lease)
        } else {
          response
        }
      }
      Err(error) => {
        if let Some(rejection) = circuit_breakers::admission_rejection(&error) {
          return route_security.apply(circuit_breaker_rejection_response(state, rejection));
        }
        let upstream_first_byte_timeout = error_is_upstream_first_byte_timeout(&error);
        if !pool_failures_reported
          && should_report_upstream_request_failure(upstream_first_byte_timeout, grpc_timeout_caps)
        {
          state.pools.report_failure_async(&upstream.name).await;
        }
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let error_message = error.to_string();
        let error_code = if upstream_first_byte_timeout || error_message.contains("timed out") {
          "read_timeout"
        } else {
          "connect_error"
        };
        warn!(error = %error, upstream = %upstream.name, "upstream HTTP/3 request failed");
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
          && state
            .cache
            .group_entry_current(
              resolved.route.cache.as_deref().unwrap_or("default"),
              entry.group_stamp.as_ref(),
            )
            .await
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
          crate::upstream_failure::classify(error.as_ref()).map(|failure| failure.as_str()),
          &error_message,
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
      let upstream_informational_capture = semantics::attach_upstream_informational_capture(
        &mut outbound,
        state.config.proxy.http.early_hints,
      );
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
      let upstream_request = async {
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
            if !success.cache_identity_unchanged {
              no_vary_search = None;
              // A pool retry selected a new effective origin target. Forward the
              // response, but bypass QUERY cache insertion rather than binding it
              // to the identity captured for the first target.
              query_identity = None;
              if query::is_query(&request_method) {
                stale_on_error = None;
                revalidation_entry = None;
              }
            }
            upstream_index = success.upstream_index;
            upstream = &state.upstreams[upstream_index];
            access_log.set_upstream(&upstream.name, upstream.origin.scheme());
            report_pool_success = success.report_success;
            sticky_cookie = success.pool_selection.sticky_cookie();
            pool_selection = Some(success.pool_selection);
            success.response
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
          result.map(|response| response.map(|body| body.map_err(boxed_error).boxed()))
        }
      };
      tokio::pin!(upstream_request);
      let result = if let Some(capture) = upstream_informational_capture.as_ref() {
        tokio::select! {
          result = &mut upstream_request => result,
          error = capture.relay_failed() => {
            Err(anyhow::anyhow!("downstream informational response rejected: {error:?}"))
          }
        }
      } else {
        upstream_request.await
      };
      result.and_then(|mut response| {
        if let Some(observed) = &upstream_response_observed {
          observed.mark();
        }
        if let Some(capture) = upstream_informational_capture {
          if let Some(error) = capture.take_relay_failure() {
            anyhow::bail!("downstream informational response rejected: {error:?}");
          }
          semantics::attach_interim_responses(&mut response, capture.take_early_hints());
        }
        Ok(response)
      })
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
      .map(|response| response.map(|body| body.map_err(boxed_error).boxed()))
    };
    match result {
      Ok(mut response) => {
        if let Some(observed) = &upstream_response_observed {
          observed.mark();
        }
        if let Some(exchange) = &incremental_exchange {
          response.extensions_mut().insert(exchange.clone());
        }
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        let stream_lease = retry::take_stream_lease(&mut response);
        let response = match stream_lease {
          Some(lease) => with_circuit_breaker_request_lease(response, lease),
          None => response,
        };
        if upstream_version != HttpVersion::H3
          && let Some(exchange) = &incremental_exchange
        {
          exchange.arm_upload_deadline();
        }
        response
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
          && state
            .cache
            .group_entry_current(
              resolved.route.cache.as_deref().unwrap_or("default"),
              entry.group_stamp.as_ref(),
            )
            .await
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
          crate::upstream_failure::classify(error.as_ref()).map(|failure| failure.as_str()),
          &error_message,
          &request_waf.response_header_mutations,
          access_log,
        );
      }
    }
  };
  query::invalidate_after_origin_response(
    state.as_ref(),
    &request_method,
    upstream_response.status(),
    downstream_scheme,
    host,
    &request_uri,
  )
  .await;
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
  if let Some(exchange) = &incremental_exchange {
    exchange.retain(pool_selection);
  } else {
    drop(pool_selection);
  }

  let upstream_incremental = incremental::response_marked(&upstream_response);
  let response_is_empty = request_method == Method::HEAD
    || upstream_response.status() == StatusCode::NO_CONTENT
    || upstream_response.status() == StatusCode::NOT_MODIFIED
    || upstream_response.body().is_end_stream();
  if upstream_incremental && !response_is_empty {
    let response_headers = upstream_response.headers();
    let sse_streaming =
      state.config.proxy.http.sse_auto_streaming && semantics::is_sse(response_headers);
    if (!effective_buffering.response.is_streaming() && !sse_streaming)
      || waf_body_capture::response_capture_blocks_incremental(
        upstream_response.version(),
        response_headers,
        response_body_need,
        response_waf_body_compression_transform,
      )
    {
      return route_security.apply(incremental::refused(request_version));
    }
  }
  let mut upstream_response = upstream_response;
  if let Some(no_vary_search) = no_vary_search.as_ref() {
    no_vary_search.capture_origin(upstream_response.headers());
  }
  if let Some(owner_nvs) = revalidation_owner_nvs.as_ref() {
    owner_nvs.capture_origin(upstream_response.headers());
  }
  status_headers::capture_upstream(&mut upstream_response);
  let revalidation_reason = revalidation_entry.as_ref().map(|entry| {
    if entry
      .expires_at
      .is_some_and(|expiry| expiry > std::time::SystemTime::now())
    {
      "request"
    } else {
      "stale"
    }
  });
  if let Some(reason) = revalidation_reason {
    status_headers::set_cache_forward_reason(&mut upstream_response, reason);
  }
  let upstream_response = if let Some(mode) = grpc_web_mode {
    grpc_web::encode_response(upstream_response, mode, upstream_incremental)
  } else {
    upstream_response
  };
  let (mut parts, mut body) = upstream_response.into_parts();
  if let Some(request) = &group_request {
    parts.extensions.insert(request.clone());
  }
  let mut origin_response_guard = state
    .cache
    .group_origin_response_guard(resolved.route.cache.as_deref(), &request_method);
  if upstream_incremental {
    parts.extensions.insert(incremental::IncrementalIntent);
  }
  if parts.status == StatusCode::NOT_MODIFIED && revalidation_entry.is_some() {
    // A revalidation head participates in cache metadata just like a full
    // origin response. Apply the header-only portion of the response policy
    // before parsing Cache-Groups or publishing the replacement entry. These
    // headers are consumed by the update operation, not returned directly, so
    // the cached response still receives the normal one-time finalization.
    strip_hop_by_hop_headers(&mut parts.headers);
    if state.config.proxy.http.trailers == crate::config::TrailerMode::Drop && !native_grpc_request
    {
      parts.headers.remove(http::header::TRAILER);
    }
    semantics::apply_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
    apply_route_security_headers_with_snapshot(
      &mut parts.headers,
      &state.config.security,
      resolved.route,
    );
    if let Some(digest_request) = digest_request.as_ref() {
      digest_request
        .suppression()
        .record_mutations(&request_waf.response_header_mutations);
    }
    apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);
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
          upstream_certificate: parts
            .extensions
            .get::<crate::waf::metadata::UpstreamCertificateMetadata>()
            .map(|value| value.0.as_ref()),
          request: request_input,
          response_id: access_log.response_id(),
          received_at_unix_ms: access_log.response_received_at_unix_ms,
          version: parts.version,
          status: parts.status,
          headers: &parts.headers,
          body: None,
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
        if let Some(digest_request) = digest_request.as_ref() {
          digest_request.suppression().record_mutations(&mutations);
        }
        return route_security.waf_http_terminal(terminal, &mutations);
      }
      if let Some(digest_request) = digest_request.as_ref() {
        digest_request
          .suppression()
          .record_mutations(&response_waf.response_header_mutations);
      }
      apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
    }
    if let Some(digest_request) = digest_request.as_ref() {
      digest_request.suppression().record_route(resolved.route);
    }
    route_runtime::apply_response_actions(&mut parts.headers, resolved.route, &request_headers);
  }
  let owner_current =
    if let Some(entry) = revalidation_entry.as_ref().filter(|entry| entry.nvs_alias) {
      state
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
    } else {
      true
    };
  let group_revalidation_current = if parts.status == StatusCode::NOT_MODIFIED {
    if let Some(entry) = revalidation_entry.as_ref() {
      state
        .cache
        .group_entry_current(
          resolved.route.cache.as_deref().unwrap_or("default"),
          entry.group_stamp.as_ref(),
        )
        .await
    } else {
      true
    }
  } else {
    true
  };
  let alias_policy_rejected = revalidation_entry
    .as_ref()
    .is_some_and(|entry| entry.nvs_alias)
    && (!group_revalidation_current
      || !owner_current
      || !revalidation_entry.as_ref().is_some_and(|entry| {
        no_vary_search.as_ref().is_some_and(|request| {
          state.cache.nvs_response_allows_alias(
            entry,
            &request_uri,
            request,
            &parts.headers,
            parts.status == StatusCode::NOT_MODIFIED,
          )
        })
      }))
    && !(owner_current
      && stale_on_error.is_some()
      && state
        .cache
        .stale_if_error_allows_status(resolved.route.cache.as_deref(), parts.status));
  if let Some(entry) = revalidation_entry.as_ref()
    && state.cache.nvs_policy_changed(
      entry,
      &parts.headers,
      parts.status == StatusCode::NOT_MODIFIED,
    )
  {
    let replacement_allowed = state
      .cache
      .replace_nvs_policy(
        crate::cache::CacheLookupContext {
          group_request: group_request.as_ref(),
          no_vary_search: revalidation_owner_nvs.as_ref().or(no_vary_search.as_ref()),
          policy_name: resolved.route.cache.as_deref(),
          scheme: downstream_scheme,
          host,
          method: &request_method,
          uri: revalidation_owner_uri.as_ref().unwrap_or(&request_uri),
          request_headers: &request_headers,
          query_identity: query_identity.as_ref(),
          certificate_identity: certificate_identity.as_ref(),
          proxy_protocol_identity: proxy_protocol_identity.as_ref(),
        },
        entry,
      )
      .await;
    cache_store_allowed &= replacement_allowed;
  }
  if alias_policy_rejected {
    // The conditional request still revalidated the owner representation.
    // Update its metadata and indexes before fetching the original alias, so
    // a broader, superseded policy cannot serve concurrent aliases.
    if parts.status == StatusCode::NOT_MODIFIED
      && cache_store_allowed
      && let Some(entry) = revalidation_entry.as_ref()
    {
      state
        .cache
        .update_from_not_modified_async(
          crate::cache::CacheInsertContext {
            group_request: group_request.as_ref(),
            no_vary_search: revalidation_owner_nvs.as_ref().or(no_vary_search.as_ref()),
            proxy_protocol_identity: proxy_protocol_identity.as_ref(),
            query_identity: query_identity.as_ref(),
            certificate_identity: certificate_identity.as_ref(),
            policy_name: resolved.route.cache.as_deref(),
            scheme: downstream_scheme,
            host,
            method: &request_method,
            uri: revalidation_owner_uri.as_ref().unwrap_or(&request_uri),
            request_headers: &request_headers,
          },
          entry,
          &parts.headers,
        )
        .await;
    }
    // Even a non-cacheable replacement must retire the superseded owner.
    // Keep this exchange exact-only: rebinding an old fill could conceal a
    // concurrent unsafe-request fence while the owner was being revalidated.
    if let Some(request) = no_vary_search.as_ref() {
      request.reset_epoch_for_replay();
    }
    let Some(replay) = alias_replay else {
      return route_security.text(
        StatusCode::BAD_GATEWAY,
        "No-Vary-Search alias revalidation cannot be replayed",
      );
    };
    let alias_identity = replay.query_identity.clone();
    let response = match replay_nvs_alias_request(
      replay,
      upstream,
      upstream_version,
      timeouts,
      nvs_alias_deadline.unwrap_or_else(std::time::Instant::now),
      state,
      selected_pool_name.as_deref(),
      client_addr,
      &resolved.route.name,
    )
    .await
    {
      Ok(response) => response,
      Err(error) => {
        warn!(error = %error, upstream = %upstream.name, "NVS alias replay failed");
        return route_security.text(
          StatusCode::BAD_GATEWAY,
          "No-Vary-Search alias revalidation failed",
        );
      }
    };
    let (mut replay_parts, replay_body) = response.into_parts();
    if let Some(request) = &group_request {
      replay_parts.extensions.insert(request.clone());
    }
    if replay_parts.status == StatusCode::NOT_MODIFIED {
      return route_security.text(
        StatusCode::BAD_GATEWAY,
        "No-Vary-Search alias replay returned not modified",
      );
    }
    if let Some(no_vary_search) = no_vary_search.as_ref() {
      no_vary_search.capture_origin(&replay_parts.headers);
    }
    status_headers::capture_upstream_parts(&mut replay_parts);
    parts = replay_parts;
    body = replay_body;
    query_identity = alias_identity;
    revalidation_entry = None;
    stale_on_error = None;
  }
  if let Some(entry) = stale_on_error.clone()
    && state
      .cache
      .stale_if_error_allows_status(resolved.route.cache.as_deref(), parts.status)
    && state
      .cache
      .group_entry_current(
        resolved.route.cache.as_deref().unwrap_or("default"),
        entry.group_stamp.as_ref(),
      )
      .await
  {
    state.metrics.record_cache_stale();
    let mut response = stale_if_error_response(entry);
    if let Some(facts) = response
      .extensions_mut()
      .get_mut::<cache_status::StandardCacheStatus>()
    {
      facts.forwarded = Some("stale");
      facts.forwarded_status = Some(parts.status.as_u16());
    }
    return response;
  }
  if parts.status == StatusCode::NOT_MODIFIED
    && let Some(entry) = revalidation_entry.clone()
    && (!entry.nvs_alias
      || no_vary_search.as_ref().is_some_and(|request| {
        state
          .cache
          .nvs_revalidation_allows_alias(&entry, &request_uri, request, &parts.headers)
      }))
  {
    let metadata_current = if !group_revalidation_current {
      false
    } else if cache_store_allowed {
      state
        .cache
        .update_from_not_modified_async(
          crate::cache::CacheInsertContext {
            group_request: group_request.as_ref(),
            no_vary_search: revalidation_owner_nvs.as_ref().or(no_vary_search.as_ref()),
            proxy_protocol_identity: proxy_protocol_identity.as_ref(),
            query_identity: query_identity.as_ref(),
            certificate_identity: certificate_identity.as_ref(),
            policy_name: resolved.route.cache.as_deref(),
            scheme: downstream_scheme,
            host,
            method: &request_method,
            uri: revalidation_owner_uri.as_ref().unwrap_or(&request_uri),
            request_headers: &request_headers,
          },
          &entry,
          &parts.headers,
        )
        .await
    } else {
      true
    };
    if !metadata_current {
      let Some(replay) = revalidation_replay else {
        return route_security.text(
          StatusCode::BAD_GATEWAY,
          "cache revalidation cannot be replayed",
        );
      };
      let response = match replay_nvs_alias_request(
        replay,
        upstream,
        upstream_version,
        timeouts,
        revalidation_replay_deadline.unwrap_or_else(std::time::Instant::now),
        state,
        selected_pool_name.as_deref(),
        client_addr,
        &resolved.route.name,
      )
      .await
      {
        Ok(response) => response,
        Err(error) => {
          warn!(error = %error, upstream = %upstream.name, "cache revalidation replay failed");
          return route_security.text(StatusCode::BAD_GATEWAY, "cache revalidation failed");
        }
      };
      let (mut replay_parts, replay_body) = response.into_parts();
      if replay_parts.status == StatusCode::NOT_MODIFIED {
        return route_security.text(
          StatusCode::BAD_GATEWAY,
          "cache revalidation replay returned not modified",
        );
      }
      if let Some(request) = &group_request {
        replay_parts.extensions.insert(request.clone());
      }
      if let Some(no_vary_search) = no_vary_search.as_ref() {
        no_vary_search.capture_origin(&replay_parts.headers);
      }
      status_headers::capture_upstream_parts(&mut replay_parts);
      parts = replay_parts;
      body = replay_body;
      revalidation_entry = None;
    } else {
      let mut cached_entry = entry;
      let mut headers = cached_entry.headers.clone();
      merge_not_modified_headers(&mut headers, &parts.headers);
      cached_entry.headers = headers;
      state.metrics.record_cache_hit();
      record_cache_hit_fast_path_selection(state, request_version);
      let mut response =
        cache_status::cached_entry_response(cached_entry, &request_method, &request_headers);
      if let Some(exchange) = &incremental_exchange {
        // Replacing a bodyless 304 must not drop the original exchange's receive
        // guard and cancel an upload which the origin is still reading.
        exchange.retain(body);
        response.extensions_mut().insert(exchange.clone());
      }
      cache_status::reconcile_cached_security(&mut response, state, resolved.route);
      if let Some(digest_request) = digest_request.as_ref() {
        digest_request.suppression().record_route(resolved.route);
      }
      route_runtime::apply_response_actions(
        response.headers_mut(),
        resolved.route,
        &request_headers,
      );
      cache_status::apply(
        &mut response,
        CacheOutcome::Revalidated,
        CacheReason::NotModified,
      );
      if let Some(facts) = response
        .extensions_mut()
        .get_mut::<cache_status::StandardCacheStatus>()
      {
        facts.hit = false;
        facts.forwarded = Some(revalidation_reason.unwrap_or("stale"));
        facts.forwarded_status = Some(304);
        facts.expires_at = None;
      } else {
        response
          .extensions_mut()
          .insert(cache_status::StandardCacheStatus {
            forwarded: Some(revalidation_reason.unwrap_or("stale")),
            forwarded_status: Some(304),
            ..Default::default()
          });
      }
      apply_response_alt_svc(
        &mut response,
        state.as_ref(),
        downstream_scheme,
        request_version,
        listener_bind,
      );
      let response = if proxy_tls_certificate
        || certificate_identity
          .as_ref()
          .is_some_and(crate::cache::CacheCertificateIdentity::is_authenticated)
      {
        response
      } else {
        compression::maybe_compress_response(
          response,
          &request_method,
          &request_headers,
          resolved.route.compression.as_deref(),
          &state.config.compression,
          &state.compression,
        )
      };
      return with_downstream_response_timeout(
        response,
        timeouts.response_send,
        transport_network,
        true,
      );
    }
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
  if let Some(digest_request) = digest_request.as_ref() {
    digest_request
      .suppression()
      .record_mutations(&request_waf.response_header_mutations);
  }
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  if (upstream_incremental || incremental::requested(&parts.headers))
    && !response_is_empty
    && waf_body_capture::response_capture_blocks_incremental(
      parts.version,
      &parts.headers,
      response_body_need,
      response_waf_body_compression_transform,
    )
  {
    return route_security.apply(incremental::refused(request_version));
  }

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
        upstream_certificate: parts
          .extensions
          .get::<crate::waf::metadata::UpstreamCertificateMetadata>()
          .map(|value| value.0.as_ref()),
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
      // A terminal response WAF result replaces the upstream response for
      // the client, but cannot undo a completed unsafe origin request.
      // Preserve origin-derived invalidation semantics without allowing the
      // synthetic WAF response to provide cache metadata.
      let mut origin_headers = parts.headers.clone();
      apply_header_mutations(&mut origin_headers, &response_waf.response_header_mutations);
      route_runtime::apply_response_actions(&mut origin_headers, resolved.route, &request_headers);
      state
        .cache
        .groups_after_origin_response(
          crate::cache::CacheLookupContext {
            group_request: group_request.as_ref(),
            no_vary_search: no_vary_search.as_ref(),
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
          parts.status,
          &origin_headers,
        )
        .await;
      origin_response_guard.disarm();
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      if let Some(digest_request) = digest_request.as_ref() {
        digest_request.suppression().record_mutations(&mutations);
      }
      return route_security.waf_http_terminal(terminal, &mutations);
    }
    if let Some(digest_request) = digest_request.as_ref() {
      digest_request
        .suppression()
        .record_mutations(&response_waf.response_header_mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }
  drop(response_decompression_lease);
  drop(response_inspection_lease);
  if let Some(digest_request) = digest_request.as_ref() {
    digest_request.suppression().record_route(resolved.route);
  }
  route_runtime::apply_response_actions(&mut parts.headers, resolved.route, &request_headers);
  state
    .cache
    .groups_after_origin_response(
      crate::cache::CacheLookupContext {
        group_request: group_request.as_ref(),
        no_vary_search: no_vary_search.as_ref(),
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
      parts.status,
      &parts.headers,
    )
    .await;
  origin_response_guard.disarm();
  cache_status::strip_headers(&mut parts.headers);
  let mut response_buffering = effective_buffering.response;
  if state.config.proxy.http.sse_auto_streaming && semantics::is_sse(&parts.headers) {
    response_buffering.mode = crate::config::BufferingMode::Streaming;
  }
  let incremental_response = upstream_incremental || incremental::requested(&parts.headers);
  if incremental_response {
    if !response_is_empty
      && (!response_buffering.is_streaming()
        || captured_response_body
          .as_ref()
          .is_some_and(|body| !body.bytes.is_empty())
        || (grpc_web_mode.is_some() && !upstream_incremental))
    {
      return route_security.apply(incremental::refused(request_version));
    }
    parts.extensions.insert(incremental::IncrementalIntent);
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

  let mut cache_candidate = Response::from_parts(parts, body);
  if let Some(query_identity) = query_identity {
    cache_candidate.extensions_mut().insert(query_identity);
  }
  let mut response = maybe_cache_response_with_store_permission(
    cache_candidate,
    state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    host,
    &request_method,
    if revalidation_entry
      .as_ref()
      .is_some_and(|entry| entry.nvs_alias)
    {
      revalidation_owner_uri.as_ref().unwrap_or(&request_uri)
    } else {
      &request_uri
    },
    &request_headers,
    Some(resolved.route),
    if revalidation_entry
      .as_ref()
      .is_some_and(|entry| entry.nvs_alias)
    {
      revalidation_owner_nvs.as_ref()
    } else {
      no_vary_search.as_ref()
    },
    certificate_identity.as_ref(),
    proxy_protocol_identity.as_ref(),
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
  let response = if proxy_tls_certificate
    || certificate_identity
      .as_ref()
      .is_some_and(crate::cache::CacheCertificateIdentity::is_authenticated)
  {
    response
  } else {
    compression::maybe_compress_response(
      response,
      &request_method,
      &request_headers,
      resolved.route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    )
  };
  let mut response =
    with_downstream_response_timeout(response, timeouts.response_send, transport_network, true);
  apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
  let response = with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
  state.record_hot_path_response(response.status());
  response
}

#[allow(clippy::too_many_arguments)]
async fn replay_nvs_alias_request(
  replay: NvsAliasReplay,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  deadline: std::time::Instant,
  state: &AppSnapshot,
  pool_name: Option<&str>,
  client_addr: SocketAddr,
  route_name: &str,
) -> anyhow::Result<Response<ProxyBody>> {
  let timeouts = timeouts.cap_upstream_to_deadline(deadline);
  let mut builder = Request::builder()
    .method(replay.method.clone())
    .uri(replay.uri)
    .version(replay.version);
  let Some(headers) = builder.headers_mut() else {
    anyhow::bail!("request builder did not expose headers");
  };
  *headers = replay.headers;
  let mut request = builder.body(full_body(bytes::Bytes::new()))?;
  if let Some(snapshot) = replay.query_snapshot {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
      anyhow::bail!("No-Vary-Search alias replay exhausted its upstream deadline");
    }
    *request.body_mut() = tokio::time::timeout(remaining, snapshot.body())
      .await
      .map_err(|_| {
        anyhow::anyhow!("No-Vary-Search alias replay exhausted its upstream deadline")
      })??;
  }
  let policy = EffectiveRetryPolicy::disabled_direct();
  let admission = Some(RetryAdmissionContext {
    route_name,
    pool_name,
  });
  if upstream_version == HttpVersion::H3 {
    return send_h3_with_retry(request, upstream, timeouts, state, &policy, admission).await;
  }
  if upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off {
    return send_one_shot_with_proxy_protocol(
      request,
      upstream,
      state,
      pool_name,
      upstream_version,
      client_addr,
      timeouts,
    )
    .await
    .map(|response| response.map(|body| body.map_err(boxed_error).boxed()));
  }
  let client = state
    .clients
    .for_upstream_version(&upstream.name, upstream.origin.scheme(), upstream_version)
    .ok_or_else(|| anyhow::anyhow!("upstream client is not configured"))?;
  send_with_retry(client, request, timeouts, state, &policy, admission)
    .await
    .map(|response| response.map(|body| body.map_err(boxed_error).boxed()))
}
