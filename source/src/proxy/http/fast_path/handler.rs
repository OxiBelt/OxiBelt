//! Plain-proxy fast-path handler.

use http_body_util::BodyExt;

use super::*;

pub(crate) struct PlainProxyFastPath;

impl PlainProxyFastPath {
  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn handle<B>(
    request: Request<B>,
    state: &Arc<AppSnapshot>,
    resolved: &ResolvedRoute<'_>,
    forwarded_client_addr: SocketAddr,
    forwarded_header_cache: Option<&ForwardedHeaderCache>,
    client_addr: SocketAddr,
    host: &str,
    downstream_port: u16,
    tcp_max_hop: Option<u8>,
    tls: &WafTlsMetadata,
    protocol: WafProtocol,
    downstream_scheme: &'static str,
    request_version: http::Version,
    transport_network: WafTransportNetwork,
    transport_metadata: WafTransportMetadataInput<'_>,
    request_waf: RequestWafDecision,
    request_headers: Option<HeaderMap>,
    tags: Option<HashMap<String, String>>,
    compiled_actions: Option<&CompiledRouteFastPathActions>,
    access_log: &mut SystemAccessLogContext<'_>,
    trace_context: Option<TraceContext>,
  ) -> Response<ProxyBody>
  where
    B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
    B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
  {
    let metric_protocol = fast_path_metric_protocol(request_version);
    let snapshot = state.as_ref();
    let timing_enabled = snapshot.request_path_features.stage_timing_metrics;
    let prepare_started = timing::start(timing_enabled);
    let request_waf_has_upstream_override =
      request_waf.upstream_override.is_some() || request_waf.upstream_pool_override.is_some();
    let compiled_proxy = match select_compiled_proxy_action(
      snapshot,
      compiled_actions,
      &request,
      request_version,
      request_waf_has_upstream_override,
    ) {
      Ok(selection) => selection,
      Err(error) => {
        warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
        return with_route_security_headers(
          text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
          &state.config.security,
          resolved.route,
        );
      }
    };
    let direct_retry_enabled = if compiled_proxy.is_none() {
      direct_http_retry_enabled(snapshot, resolved.route, request.method())
    } else {
      false
    };
    let direct_selection = if compiled_proxy.is_none() {
      select_direct_fast_path_upstream(snapshot, resolved, &request_waf, direct_retry_enabled)
    } else {
      None
    };
    let direct_candidate = compiled_proxy.is_some() || direct_selection.is_some();
    let (
      mut upstream,
      mut upstream_index,
      upstream_version,
      retry_policy,
      pool_retry_context,
      mut sticky_cookie,
      mut pool_selection,
      preserve_host,
      forwarded_header_mode,
      priority_mode,
      timeouts,
      response_waf_enabled,
    ) = if let Some(compiled) = compiled_proxy.as_ref() {
      (
        compiled.upstream,
        compiled.upstream_index,
        compiled.upstream_version,
        EffectiveRetryPolicy::disabled_direct(),
        None,
        None,
        None,
        compiled.preserve_host,
        compiled.forwarded_header_mode,
        compiled.priority,
        compiled.timeouts,
        compiled.response_waf_enabled,
      )
    } else if let Some(selected) = direct_selection {
      let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, selected.upstream);
      (
        selected.upstream,
        selected.upstream_index,
        selected.upstream_version,
        EffectiveRetryPolicy::disabled_direct(),
        None,
        None,
        None,
        selected.upstream.preserve_host,
        state.config.proxy.forwarded_headers.mode,
        state.config.proxy.http.priority,
        timeouts,
        resolved.execution_plan.waf.response.enabled(),
      )
    } else {
      let pool_cookie_header = if request_waf.upstream_override.is_none()
        && (request_waf.upstream_pool_override.is_some() || resolved.route.upstream_pool.is_some())
      {
        request.headers().get(COOKIE)
      } else {
        None
      };
      let selected = match select_request_upstream(
        state.as_ref(),
        resolved,
        client_addr,
        host,
        request.uri(),
        pool_cookie_header,
        &request_waf,
      ) {
        Ok(selected) => selected,
        Err(error) => {
          return with_route_security_headers(
            super::super::upstream_selection_error_response(error),
            &state.config.security,
            resolved.route,
          );
        }
      };
      let upstream = selected.upstream;
      let upstream_index = selected.upstream_index;
      let upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
        select_upstream_http_version(
          state.config.proxy.auto_upgrade.enabled,
          state.config.proxy.auto_upgrade.max_http_version,
          upstream.max_http_version,
        )
      });
      let pool_retry_context = if let Some(pool_name) = selected.pool_name() {
        access_log.set_upstream_pool(pool_name);
        Some((request.uri().clone(), pool_cookie_header.cloned()))
      } else {
        None
      };
      let sticky_cookie = selected.sticky_cookie();
      let pool_selection = selected.into_pool_selection();
      let retry_policy = if pool_selection.is_some() {
        EffectiveRetryPolicy::for_http_request(&state.config, resolved.route, request.method())
      } else if direct_retry_enabled {
        EffectiveRetryPolicy::for_direct_http_request(
          &state.config,
          resolved.route,
          request.method(),
        )
      } else {
        EffectiveRetryPolicy::disabled_direct()
      };
      (
        upstream,
        upstream_index,
        upstream_version,
        retry_policy,
        pool_retry_context,
        sticky_cookie,
        pool_selection,
        upstream.preserve_host,
        state.config.proxy.forwarded_headers.mode,
        state.config.proxy.http.priority,
        EffectiveTimeouts::new(&state.config, resolved.route, upstream),
        resolved.execution_plan.waf.response.enabled(),
      )
    };
    if upstream_version == HttpVersion::H3
      || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
    {
      return with_route_security_headers(
        text_response(StatusCode::BAD_GATEWAY, "unsupported fast-path upstream"),
        &state.config.security,
        resolved.route,
      );
    }
    access_log.set_upstream(&upstream.name, upstream.origin.scheme());
    let request_method = request.method().clone();
    let request_context =
      response_waf_enabled.then(|| (request_method.clone(), request.uri().clone()));
    let request_body_definitely_empty = request_body_definitely_empty(&request);
    let verified_early_data = crate::proxy::http::early_data::is_verified(&request);
    let (parts, body) = request.into_parts();
    let forwarded_request_header_values = ForwardedRequestHeaderValues::new(host, downstream_port);
    let upstream_rebuild_started = timing::start(timing_enabled);
    let record_upstream_rebuild = |success| {
      timing::record_upstream_request_rebuild(
        snapshot,
        metric_protocol,
        success,
        upstream_rebuild_started,
      );
    };
    let direct_h1_build_started = timing::start(timing_enabled);
    let preparation = match prepare_downstream_direct_h1_or_generic(
      parts,
      body,
      request_body_definitely_empty
        .then(|| {
          compiled_proxy
            .as_ref()
            .map(|compiled| DownstreamDirectH1RequestOptions {
              selected: compiled,
              downstream_version: request_version,
              forwarded_client_addr,
              downstream_scheme,
              downstream_host: host,
              downstream_port,
              forwarded_header_cache,
              forwarded_request_header_values: &forwarded_request_header_values,
              compression_enabled: state.config.compression.enabled,
              request_body_definitely_empty,
              request_waf_context_disabled: request_headers.is_none() && tags.is_none(),
              request_waf: &request_waf,
              verified_early_data,
            })
        })
        .flatten(),
    ) {
      Ok(preparation) => preparation,
      Err(error) => {
        record_upstream_rebuild(false);
        warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
        return with_route_security_headers(
          text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
          &state.config.security,
          resolved.route,
        );
      }
    };

    let (outbound, request_body_proven_empty) = match preparation {
      DownstreamDirectH1Preparation::DirectH1(mut outbound) => {
        timing::direct_h1_build_ok(snapshot, metric_protocol, direct_h1_build_started);
        state
          .telemetry
          .inject_trace_context(outbound.headers_mut(), trace_context);
        timing::record_fast_path_prepare(snapshot, metric_protocol, prepare_started);
        record_upstream_rebuild(true);
        let request_body_started = timing::start(timing_enabled);
        record_empty_request_body(snapshot, metric_protocol, outbound.extensions());
        timing::record_request_body_prepare(snapshot, metric_protocol, request_body_started);
        (outbound, true)
      }
      DownstreamDirectH1Preparation::Generic(parts, body) => {
        if request_body_definitely_empty {
          timing::direct_h1_build_fallback(snapshot, metric_protocol, direct_h1_build_started);
        }
        let target_uri = if let Some(compiled) = compiled_proxy.as_ref() {
          match compiled.target_uri(&parts.uri) {
            Ok(uri) => uri,
            Err(error) => {
              record_upstream_rebuild(false);
              warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
              return with_route_security_headers(
                text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
                &state.config.security,
                resolved.route,
              );
            }
          }
        } else {
          let Some(upstream_uri) = state.upstream_uri_parts_by_index.get(upstream_index) else {
            record_upstream_rebuild(false);
            warn!(
              upstream = %upstream.name,
              upstream_index,
              "missing precomputed upstream URI parts"
            );
            return with_route_security_headers(
              text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured"),
              &state.config.security,
              resolved.route,
            );
          };
          match fast_path_target_uri(upstream_uri, resolved, downstream_scheme, host, &parts.uri) {
            Ok(uri) => uri,
            Err(error) => {
              record_upstream_rebuild(false);
              warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
              return with_route_security_headers(
                text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
                &state.config.security,
                resolved.route,
              );
            }
          }
        };

        let request_body_started = timing::start(timing_enabled);
        let request_body = if request_body_definitely_empty {
          record_empty_request_body(snapshot, metric_protocol, &parts.extensions);
          FastPathRequestBody::empty()
        } else {
          match fast_path_prepare_nonempty_request_body(
            body,
            &parts.method,
            request_version,
            &parts.headers,
            state.as_ref(),
            resolved,
            upstream_version,
            retry_policy.enabled,
            metric_protocol,
          )
          .await
          {
            Ok(request_body) => request_body,
            Err(error) => {
              record_upstream_rebuild(false);
              let (status, message) = fast_path_request_body_error_status(&error);
              if status == StatusCode::BAD_REQUEST {
                warn!(error = %error, route = %resolved.route.name, "failed to read small direct-H1 request body");
              }
              return with_route_security_headers(
                text_response(status, message),
                &state.config.security,
                resolved.route,
              );
            }
          }
        };
        timing::record_request_body_prepare(snapshot, metric_protocol, request_body_started);
        let request_body_proven_empty = request_body.proven_empty();
        let mut parts = Some(parts);
        let mut post_probe_outbound = None;
        if !request_body_definitely_empty && request_body_proven_empty {
          let direct_h1_build_started = timing::start(timing_enabled);
          if let Some(compiled) = compiled_proxy.as_ref() {
            let current_parts = parts
              .take()
              .expect("generic request parts should be available before direct-H1 retry");
            match try_build_downstream_direct_h1_request(
              current_parts,
              DownstreamDirectH1RequestOptions {
                selected: compiled,
                downstream_version: request_version,
                forwarded_client_addr,
                downstream_scheme,
                downstream_host: host,
                downstream_port,
                forwarded_header_cache,
                forwarded_request_header_values: &forwarded_request_header_values,
                compression_enabled: state.config.compression.enabled,
                request_body_definitely_empty: true,
                request_waf_context_disabled: request_headers.is_none() && tags.is_none(),
                request_waf: &request_waf,
                verified_early_data,
              },
            ) {
              Ok(DownstreamDirectH1RequestBuild::Built(mut outbound)) => {
                timing::direct_h1_build_ok(snapshot, metric_protocol, direct_h1_build_started);
                state
                  .telemetry
                  .inject_trace_context(outbound.headers_mut(), trace_context);
                timing::record_fast_path_prepare(snapshot, metric_protocol, prepare_started);
                post_probe_outbound = Some(outbound);
              }
              Ok(DownstreamDirectH1RequestBuild::Fallback(returned_parts)) => {
                timing::direct_h1_build_fallback(
                  snapshot,
                  metric_protocol,
                  direct_h1_build_started,
                );
                parts = Some(returned_parts);
              }
              Err(error) => {
                record_upstream_rebuild(false);
                warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
                return with_route_security_headers(
                  text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
                  &state.config.security,
                  resolved.route,
                );
              }
            }
          } else {
            timing::direct_h1_build_fallback(snapshot, metric_protocol, direct_h1_build_started);
          }
        } else if !request_body_definitely_empty {
          let direct_h1_build_started = timing::start(timing_enabled);
          timing::direct_h1_build_fallback(snapshot, metric_protocol, direct_h1_build_started);
        }
        if let Some(outbound) = post_probe_outbound {
          record_upstream_rebuild(true);
          (outbound, true)
        } else {
          let mut parts =
            parts.expect("generic request parts should remain after direct-H1 fallback");
          let rebuild = RebuildRequestOptions {
            target_uri,
            compression: &state.config.compression,
            route_compression: resolved.route.compression.as_deref(),
            forwarded_client_addr,
            downstream_scheme,
            downstream_host: host,
            downstream_port,
            forwarded_header_mode,
            forwarded_header_cache,
            forwarded_request_header_values: Some(&forwarded_request_header_values),
            preserve_host,
            upstream_version,
            waf_mutations: &request_waf.request_header_mutations,
            route_mutations: &[],
            force_strip_accept_encoding: false,
          };
          rebuild_request_parts(&mut parts, rebuild);
          semantics::strip_accepted_expect(&mut parts.headers);
          apply_fast_path_priority_policy(&mut parts.headers, priority_mode);
          crate::proxy::http::early_data::apply_verified_upstream_header(
            &mut parts.headers,
            verified_early_data,
          );
          state
            .telemetry
            .inject_trace_context(&mut parts.headers, trace_context);
          timing::record_fast_path_prepare(snapshot, metric_protocol, prepare_started);
          record_upstream_rebuild(true);
          let outbound_body = if request_body_proven_empty {
            request_body.into_body()
          } else if request_body.is_small_exact() {
            body::with_poll_send_timeout(
              request_body.into_body(),
              timeouts.upstream_send,
              BodyTimeoutKind::UpstreamRequestSend,
            )
          } else {
            let body = request_body.into_body();
            fast_path_outbound_request_body(
              body,
              state.config.proxy.http.trailers,
              timeouts.upstream_send,
            )
          };
          (
            Request::from_parts(parts, outbound_body),
            request_body_proven_empty,
          )
        }
      }
    };

    let upstream_started_at = fast_path_upstream_timing_required(
      state.as_ref(),
      response_waf_enabled,
      pool_selection.is_some(),
    )
    .then(Instant::now);
    let mut report_pool_success = false;
    let mut direct_h1_lease = None;
    let mut direct_h2_lease = None;
    let transport_selection_started = timing::start(timing_enabled);
    let direct_transport = direct_fast_path_transport(upstream_version, direct_candidate);
    timing::record_transport_selection(
      snapshot,
      metric_protocol,
      direct_transport,
      transport_selection_started,
    );
    let transport_started = timing::start(timing_enabled);
    let direct_attempt = match direct_transport {
      Some(DirectFastPathTransport::H1) => match try_send_direct_h1(
        &state.direct_h1_pools,
        &state.metrics,
        upstream_index,
        upstream,
        upstream_version,
        request_version,
        true,
        request_body_proven_empty,
        retry_policy.enabled,
        state.config.runtime.direct_h1_io,
        outbound,
        timeouts,
        snapshot.request_path_features.hot_path_metrics,
        snapshot.request_path_features.hot_path_diagnostic_metrics,
        timing_enabled,
      )
      .await
      {
        DirectH1SendResult::Sent(result) => {
          DirectTransportAttempt::Sent(result.map(|mut direct| {
            direct_h1_lease = direct.take_lease();
            direct.response
          }))
        }
        DirectH1SendResult::Fallback(outbound) => DirectTransportAttempt::Fallback(outbound),
      },
      Some(DirectFastPathTransport::H2) => match try_send_direct_h2(
        &state.direct_h2_pools,
        &state.metrics,
        upstream_index,
        upstream,
        upstream_version,
        request_version,
        true,
        request_body_proven_empty,
        outbound,
        timeouts,
        snapshot.request_path_features.hot_path_metrics,
        timing_enabled,
      )
      .await
      {
        DirectH2SendResult::Sent(result) => {
          DirectTransportAttempt::Sent(result.map(|mut direct| {
            direct_h2_lease = direct.take_lease();
            direct
              .response
              .map(|body| body.map_err(body::boxed_error).boxed())
          }))
        }
        DirectH2SendResult::Fallback(outbound) => DirectTransportAttempt::Fallback(outbound),
      },
      None => DirectTransportAttempt::Fallback(outbound),
    };
    let upstream_response_result = match direct_attempt {
      DirectTransportAttempt::Sent(result) => {
        timing::transport_result(
          snapshot,
          metric_protocol,
          direct_transport,
          result.is_ok(),
          transport_started,
        );
        result
      }
      DirectTransportAttempt::Fallback(outbound) => {
        let general_started = timing::general_start(
          snapshot,
          metric_protocol,
          direct_transport,
          transport_started,
          timing_enabled,
        );
        let Some(client) = state.clients.for_upstream_index(
          upstream_index,
          upstream.origin.scheme(),
          upstream_version,
        ) else {
          timing::general_result(snapshot, metric_protocol, false, general_started);
          warn!(upstream = %upstream.name, "missing upstream client pool");
          return with_route_security_headers(
            text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured"),
            &state.config.security,
            resolved.route,
          );
        };
        let result = if let Some(selection) = pool_selection.take() {
          let (original_uri, pool_retry_cookie) = pool_retry_context
            .as_ref()
            .expect("pool retry context should exist for pool selections");
          send_pool_with_retry(
            state.as_ref(),
            outbound,
            upstream_index,
            selection,
            resolved.route,
            original_uri,
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
            success.response
          })
        } else if retry_policy.enabled {
          send_with_retry(client, outbound, timeouts, state.as_ref(), &retry_policy).await
        } else {
          send_one_shot(client, outbound, timeouts).await
        };
        timing::general_result(snapshot, metric_protocol, result.is_ok(), general_started);
        result.map(|response| response.map(|body| body.map_err(body::boxed_error).boxed()))
      }
    };
    let upstream_response = match upstream_response_result {
      Ok(response) => response,
      Err(error) => {
        if error_indicates_body_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
          return with_route_security_headers(
            text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out"),
            &state.config.security,
            resolved.route,
          );
        }
        warn!(error = %error, upstream = %upstream.name, "upstream fast-path request failed");
        let message = error.to_string();
        let code = if message.contains("timed out") {
          "read_timeout"
        } else {
          "connect_error"
        };
        if let Some(upstream_first_byte_time_ms) = upstream_started_at.map(elapsed_ms) {
          access_log.set_upstream_first_byte_time_ms(upstream_first_byte_time_ms);
        }
        access_log.record_upstream_error(code, &message);
        let status = if code == "read_timeout" {
          StatusCode::GATEWAY_TIMEOUT
        } else {
          StatusCode::BAD_GATEWAY
        };
        let response = with_route_security_headers(
          configured_error_response(&state.config, "", status, "upstream request failed", code),
          &state.config.security,
          resolved.route,
        );
        state.record_hot_path_response(response.status());
        return response;
      }
    };
    if report_pool_success && let Some(latency_ms) = upstream_started_at.map(elapsed_ms) {
      state
        .pools
        .report_success_latency(&upstream.name, latency_ms);
    }

    let upstream_first_byte_time_ms = upstream_started_at.map(elapsed_ms);
    if let Some(upstream_first_byte_time_ms) = upstream_first_byte_time_ms {
      access_log.set_upstream_first_byte_time_ms(upstream_first_byte_time_ms);
    }
    let (parts, response_body) = upstream_response.into_parts();
    let response_body_started = timing::start(timing_enabled);
    let compiled_known_small_noop_candidate = compiled_known_small_noop_static_candidate(
      compiled_proxy.as_ref(),
      request_version,
      transport_network,
      &request_waf,
      pool_selection.as_ref(),
      sticky_cookie.as_ref(),
    );
    let FastPathResponseBody {
      body: response_body,
      known_small_response_body,
      inlined_known_small_body,
      known_no_trailers,
      trailers_handled,
      disposition: response_body_disposition,
      reason: response_body_reason,
    } = match fast_path_response_body(
      FastPathResponseSemantics::new(request_method, parts.status),
      &parts.headers,
      response_body,
      FastPathResponseBodyOptions {
        upstream_read_timeout: timeouts.upstream_read,
        trailer_mode: state.config.proxy.http.trailers,
        request_version,
        compiled_known_small_noop_candidate,
        direct_h1_first_frame_timing: (direct_h1_lease.is_some() && timing_enabled)
          .then(|| (state.metrics.clone(), metric_protocol)),
      },
    )
    .await
    {
      Ok(response_body) => {
        timing::response_body_result(snapshot, metric_protocol, true, response_body_started);
        response_body
      }
      Err(error) => {
        timing::response_body_result(snapshot, metric_protocol, false, response_body_started);
        if state.request_path_features.hot_path_diagnostic_metrics {
          state.metrics.record_fast_path_response_body(
            metric_protocol.as_str(),
            "error",
            error.reason,
          );
        }
        let response =
          with_route_security_headers(error.response, &state.config.security, resolved.route);
        state.record_hot_path_response(response.status());
        return response;
      }
    };
    if state.request_path_features.hot_path_diagnostic_metrics {
      state.metrics.record_fast_path_response_body(
        metric_protocol.as_str(),
        response_body_disposition,
        response_body_reason,
      );
    }
    let finalize_started = timing::start(timing_enabled);
    finalize_response(
      snapshot,
      resolved,
      request_version,
      transport_network,
      downstream_scheme,
      client_addr,
      host,
      tcp_max_hop,
      tls,
      protocol,
      transport_metadata,
      upstream,
      upstream_first_byte_time_ms,
      &request_waf,
      response_waf_enabled,
      request_context.as_ref(),
      request_headers.as_ref(),
      &tags,
      pool_selection.as_ref(),
      sticky_cookie.as_ref(),
      access_log,
      compiled_known_small_noop_candidate,
      metric_protocol,
      finalize_started,
      direct_h1_lease.take(),
      direct_h2_lease.take(),
      parts,
      response_body,
      known_small_response_body,
      known_no_trailers,
      inlined_known_small_body,
      trailers_handled,
      timeouts.response_send,
    )
  }
}
