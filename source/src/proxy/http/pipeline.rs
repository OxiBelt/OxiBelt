//! Staged HTTP request pipeline after route selection and framing validation.
//! The stages preserve the original request-path ordering and lease lifetimes.

use super::*;

mod ct;
mod exchange;
mod upstream;

pub(super) struct InitialContext<'state, 'request, 'access, 'transport, 'metadata, B> {
  pub(super) request: Request<B>,
  pub(super) state: &'state Arc<AppSnapshot>,
  pub(super) resolved: crate::routes::ResolvedRoute<'state>,
  pub(super) host: &'request str,
  pub(super) downstream_port: u16,
  pub(super) client_addr: SocketAddr,
  pub(super) forwarded_client_addr: SocketAddr,
  pub(super) forwarded_header_cache: Option<&'request headers::ForwardedHeaderCache>,
  pub(super) tcp_max_hop: Option<u8>,
  pub(super) tls: &'request Arc<WafTlsMetadata>,
  pub(super) protocol: WafProtocol,
  pub(super) transport_network: WafTransportNetwork,
  pub(super) transport_metadata: WafTransportMetadataInput<'transport>,
  pub(super) downstream_scheme: &'static str,
  pub(super) request_version: http::Version,
  pub(super) listener_bind: Option<SocketAddr>,
  pub(super) connection_limit_context: Option<&'request ConnectionLimitContext>,
  pub(super) drain: ConnectionDrain,
  pub(super) access_log: &'access mut SystemAccessLogContext<'metadata>,
  pub(super) request_connection_permit: &'access mut Option<ConnectionPermit>,
  pub(super) trace_context: Option<TraceContext>,
  pub(super) route_circuit_breaker_lease: crate::circuit_breakers::AdmissionLease,
  pub(super) tags: Option<HashMap<String, String>>,
  pub(super) client_body_timeout: Duration,
  pub(super) upload_bandwidth_limited: bool,
  pub(super) max_request_body_bytes: u64,
  pub(super) verified_early_data: bool,
}

pub(super) struct UpstreamContext<'state, 'request, 'access, 'transport, 'metadata> {
  pub(super) request: Request<ProxyBody>,
  pub(super) state: &'state Arc<AppSnapshot>,
  pub(super) resolved: crate::routes::ResolvedRoute<'state>,
  pub(super) host: &'request str,
  pub(super) downstream_port: u16,
  pub(super) client_addr: SocketAddr,
  pub(super) forwarded_client_addr: SocketAddr,
  pub(super) forwarded_header_cache: Option<&'request headers::ForwardedHeaderCache>,
  pub(super) tcp_max_hop: Option<u8>,
  pub(super) tls: &'request Arc<WafTlsMetadata>,
  pub(super) protocol: WafProtocol,
  pub(super) transport_network: WafTransportNetwork,
  pub(super) transport_metadata: WafTransportMetadataInput<'transport>,
  pub(super) downstream_scheme: &'static str,
  pub(super) request_version: http::Version,
  pub(super) listener_bind: Option<SocketAddr>,
  pub(super) access_log: &'access mut SystemAccessLogContext<'metadata>,
  pub(super) trace_context: Option<TraceContext>,
  pub(super) route_circuit_breaker_lease: crate::circuit_breakers::AdmissionLease,
  pub(super) tags: Option<HashMap<String, String>>,
  pub(super) effective_buffering: buffering::EffectiveBuffering,
  pub(super) request_method: Method,
  pub(super) request_uri: http::Uri,
  pub(super) client_asn: Option<u32>,
  pub(super) response_waf_enabled: bool,
  pub(super) response_body_need: BodyNeed,
  pub(super) response_waf_body_compression_transform: bool,
  pub(super) request_waf: crate::waf::RequestWafDecision,
  pub(super) captured_body: Option<body::CapturedBody>,
  pub(super) verified_early_data: bool,
}

pub(super) struct ExchangeContext<'state, 'request, 'access, 'transport, 'metadata> {
  pub(super) state: &'state Arc<AppSnapshot>,
  pub(super) resolved: crate::routes::ResolvedRoute<'state>,
  pub(super) host: &'request str,
  pub(super) client_addr: SocketAddr,
  pub(super) tcp_max_hop: Option<u8>,
  pub(super) tls: &'request Arc<WafTlsMetadata>,
  pub(super) protocol: WafProtocol,
  pub(super) transport_network: WafTransportNetwork,
  pub(super) transport_metadata: WafTransportMetadataInput<'transport>,
  pub(super) downstream_scheme: &'static str,
  pub(super) request_version: http::Version,
  pub(super) listener_bind: Option<SocketAddr>,
  pub(super) access_log: &'access mut SystemAccessLogContext<'metadata>,
  pub(super) route_circuit_breaker_lease: crate::circuit_breakers::AdmissionLease,
  pub(super) tags: Option<HashMap<String, String>>,
  pub(super) effective_buffering: buffering::EffectiveBuffering,
  pub(super) request_method: Method,
  pub(super) request_uri: http::Uri,
  pub(super) client_asn: Option<u32>,
  pub(super) response_waf_enabled: bool,
  pub(super) response_body_need: BodyNeed,
  pub(super) response_waf_body_compression_transform: bool,
  pub(super) request_waf: crate::waf::RequestWafDecision,
  pub(super) captured_body: Option<body::CapturedBody>,
  pub(super) outbound: Request<ProxyBody>,
  pub(super) upstream: &'state UpstreamConfig,
  pub(super) upstream_index: usize,
  pub(super) selected_pool_name: Option<String>,
  pub(super) pool_retry_cookie: Option<http::HeaderValue>,
  pub(super) sticky_cookie: Option<http::HeaderValue>,
  pub(super) pool_selection: Option<crate::pools::PoolSelection>,
  pub(super) timeouts: EffectiveTimeouts,
  pub(super) grpc_timeout_caps: semantics::GrpcTimeoutCaps,
  pub(super) upstream_version: HttpVersion,
  pub(super) grpc_web_mode: Option<grpc_web::GrpcWebMode>,
  pub(super) native_grpc_request: bool,
  pub(super) request_headers: HeaderMap,
  pub(super) stale_on_error: Option<crate::cache::CacheEntry>,
  pub(super) revalidation_entry: Option<crate::cache::CacheEntry>,
  pub(super) cache_store_allowed: bool,
  pub(super) cache_fill_guard: Option<crate::cache::CacheFillGuard>,
}

pub(super) async fn run<B>(context: InitialContext<'_, '_, '_, '_, '_, B>) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<super::body::BoxError> + Send + Sync + Unpin + 'static,
{
  let InitialContext {
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
    connection_limit_context,
    drain,
    access_log,
    request_connection_permit,
    trace_context,
    route_circuit_breaker_lease,
    mut tags,
    client_body_timeout,
    upload_bandwidth_limited,
    max_request_body_bytes,
    verified_early_data,
  } = context;
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let client_asn = state.client_identity.asn.lookup(client_addr.ip());
  let request_waf_enabled = resolved.execution_plan.waf.request.enabled();
  let response_waf_enabled = resolved.execution_plan.waf.response.enabled();
  let request_body_need = resolved.execution_plan.waf.request.body_need();
  let response_body_need = resolved.execution_plan.waf.response.body_need();
  let effective_buffering = buffering::EffectiveBuffering::new(&state.config, resolved.route);
  if state.request_path_features.rate_limits {
    let rate_limit_context = RateLimitContext::route(
      client_addr.ip(),
      &resolved.route.name,
      request_uri.path(),
      request.headers(),
    )
    .with_tls_fingerprint(tls.fingerprint.as_deref())
    .with_client_asn(client_asn)
    .with_tcp_max_hop(tcp_max_hop);
    if let Some(status) = state
      .limits
      .check_route_rate_limits_async(rate_limit_context, &state.config.rate_limits)
      .await
    {
      return route_security.text(status, "rate limit exceeded");
    }
  }
  let mut evaluated_person_proof = None;
  if request_waf_enabled
    || response_waf_enabled
    || resolved.execution_plan.waf.stream_enabled
    || (state.request_path_features.dynamic_policy
      && state
        .dynamic_policy
        .needs_person_proof_clearance_for_request(DynamicPolicyRequest {
          client_ip: client_addr.ip(),
          route_name: &resolved.route.name,
          method: &request_method,
          path: request_uri.path(),
          headers: Some(request.headers()),
          tls_fingerprint: tls.fingerprint.as_deref(),
          client_asn,
          tcp_max_hop,
          person_proof_clearance_hash: None,
        }))
  {
    access_log.ensure_request_ids();
    evaluated_person_proof = Some(
      state
        .waf
        .evaluate_person_proof_request_async(WafRequestInput {
          request_id: access_log.request_id(),
          transaction_id: access_log.transaction_id(),
          received_at_unix_ms: access_log.request_received_at_unix_ms,
          method: &request_method,
          uri: &request_uri,
          version: request_version,
          headers: request.headers(),
          body: None,
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
        })
        .await,
    );
  }
  let person_proof_clearance_hash = evaluated_person_proof
    .as_ref()
    .and_then(|status| status.clearance_hash());
  let mut person_proof_snapshot = evaluated_person_proof
    .as_ref()
    .map(crate::waf::EvaluatedPersonProofRequest::sanitized);
  access_log.set_person_proof_snapshot(person_proof_snapshot.as_ref());
  let dynamic_policy = if state.request_path_features.dynamic_policy {
    state
      .dynamic_policy
      .evaluate_async(
        DynamicPolicyRequest {
          client_ip: client_addr.ip(),
          route_name: &resolved.route.name,
          method: &request_method,
          path: request_uri.path(),
          headers: Some(request.headers()),
          tls_fingerprint: tls.fingerprint.as_deref(),
          client_asn,
          tcp_max_hop,
          person_proof_clearance_hash,
        },
        &state.limits,
      )
      .await
  } else {
    Default::default()
  };
  access_log.dynamic_policy = dynamic_policy.context;
  let mut dynamic_challenge_response_mutations = Vec::new();
  let mut dynamic_person_proof_mutation_added = false;
  if let Some(terminal) = dynamic_policy.terminal {
    match terminal {
      DynamicPolicyTerminal::Text { status, body } => {
        return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
          text_response(status, &body),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ));
      }
      DynamicPolicyTerminal::SilentClose => {
        return silent_close_response();
      }
      DynamicPolicyTerminal::Challenge { status } => {
        let person_proof_api_path = state.request_path_features.person_proof_api
          && state.waf.has_person_proof_api_path(request_uri.path());
        if !person_proof_api_path {
          access_log.ensure_request_ids();
          let decision = match state
            .waf
            .evaluate_dynamic_person_proof_challenge_with_status_async(
              WafRequestInput {
                request_id: access_log.request_id(),
                transaction_id: access_log.transaction_id(),
                received_at_unix_ms: access_log.request_received_at_unix_ms,
                method: &request_method,
                uri: &request_uri,
                version: request_version,
                headers: request.headers(),
                body: None,
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
              },
              status,
              &mut evaluated_person_proof,
            )
            .await
          {
            Ok(decision) => decision,
            Err(error) => {
              warn!(error = %error, "failed to evaluate dynamic Person proof challenge");
              return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
                text_response(StatusCode::FORBIDDEN, "person proof challenge failed"),
                state.as_ref(),
                evaluated_person_proof.as_ref(),
                dynamic_person_proof_mutation_added,
                &dynamic_challenge_response_mutations,
              ));
            }
          };
          person_proof_snapshot = evaluated_person_proof
            .as_ref()
            .map(crate::waf::EvaluatedPersonProofRequest::sanitized);
          access_log.set_person_proof_snapshot(person_proof_snapshot.as_ref());
          if let Some(terminal) = decision.terminal {
            return route_security.waf_http_terminal(terminal, &decision.response_header_mutations);
          }
          dynamic_person_proof_mutation_added = !decision.response_header_mutations.is_empty();
          dynamic_challenge_response_mutations.extend(decision.response_header_mutations);
        }
      }
    }
  }
  person_proof_snapshot = evaluated_person_proof
    .as_ref()
    .map(crate::waf::EvaluatedPersonProofRequest::sanitized);
  access_log.set_person_proof_snapshot(person_proof_snapshot.as_ref());
  let person_proof_api_path = state.request_path_features.person_proof_api
    && state.waf.has_person_proof_api_path(request_uri.path());
  if person_proof_api_path {
    access_log.ensure_request_ids();
    let response = handle_person_proof_api(
      request,
      state.as_ref(),
      request_method,
      request_uri,
      (!upload_bandwidth_limited).then_some(client_body_timeout),
      request_version,
      client_addr,
      host,
      downstream_scheme,
      &resolved.route.name,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      tags_ref(&tags),
      &access_log.dynamic_policy,
      access_log.request_id().to_string(),
      access_log.transaction_id().to_string(),
      access_log.request_received_at_unix_ms,
    )
    .await;
    return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
      response,
      state.as_ref(),
      evaluated_person_proof.as_ref(),
      dynamic_person_proof_mutation_added,
      &dynamic_challenge_response_mutations,
    ));
  }
  match route_actions::resolved_redirect_response(
    &resolved,
    downstream_scheme,
    host,
    downstream_port,
    &request_uri,
  ) {
    Ok(Some(response)) => {
      return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
        response,
        state.as_ref(),
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
        &dynamic_challenge_response_mutations,
      ));
    }
    Ok(None) => {}
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to build route redirect response");
      return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
        text_response(StatusCode::BAD_REQUEST, "invalid route redirect"),
        state.as_ref(),
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
        &dynamic_challenge_response_mutations,
      ));
    }
  }
  let mut request = request.map(|body| body.map_err(Into::into).boxed());
  if resolved.execution_plan.features.external_auth
    && let Some(provider) = resolved.route.external_auth.as_deref()
  {
    match state
      .external_auth
      .authorize_http(
        provider,
        &mut request,
        client_addr.ip(),
        host,
        downstream_scheme,
        &resolved.route.name,
        usize::try_from(max_request_body_bytes).unwrap_or(usize::MAX),
        (!upload_bandwidth_limited).then_some(client_body_timeout),
      )
      .await
    {
      ExternalAuthOutcome::Allowed => {}
      ExternalAuthOutcome::Denied(terminal) => {
        return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
          external_auth_response(terminal),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ));
      }
    }
  }
  // CT routes remain behind the same dynamic-policy and external-auth gates as
  // upstream routes. Dispatch only after both gates have accepted the request.
  if let Some(log_name) = resolved.route.ct_log.as_deref() {
    if !ct::surface_allows(
      resolved.route.ct_surface,
      request.method(),
      request.uri().path(),
    ) {
      return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
        text_response(
          StatusCode::NOT_FOUND,
          "CT endpoint not available on this route",
        ),
        state.as_ref(),
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
        &dynamic_challenge_response_mutations,
      ));
    }
    let (parts, request_body) = request.into_parts();
    let maximum = usize::try_from(max_request_body_bytes).unwrap_or(usize::MAX);
    let request_body = if upload_bandwidth_limited {
      request_body
    } else {
      body::with_read_timeout(
        Limited::new(request_body, maximum),
        client_body_timeout,
        BodyTimeoutKind::DownstreamRequestRead,
      )
    };
    let collected = match request_body.collect().await {
      Ok(collected) => collected.to_bytes(),
      Err(error) if body::error_is_body_length_limit(&error) => {
        return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
          text_response(StatusCode::PAYLOAD_TOO_LARGE, "CT request body too large"),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ));
      }
      Err(error) if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) => {
        return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
          text_response(StatusCode::REQUEST_TIMEOUT, "CT request body timed out"),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ));
      }
      Err(_) => {
        return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
          text_response(StatusCode::BAD_REQUEST, "invalid CT request body"),
          state.as_ref(),
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ));
      }
    };
    let ct_response = state
      .certificate_transparency
      .handle(
        log_name,
        &parts.method,
        parts.uri.path(),
        parts.uri.query(),
        &collected,
        &state.control_http,
      )
      .await;
    let mut response = Response::new(
      Full::new(ct_response.body)
        .map_err(|never| -> body::BoxError { match never {} })
        .boxed(),
    );
    *response.status_mut() = ct_response.status;
    if let Ok(content_type) = http::HeaderValue::from_str(ct_response.content_type) {
      response
        .headers_mut()
        .insert(http::header::CONTENT_TYPE, content_type);
    }
    response.headers_mut().insert(
      http::header::CACHE_CONTROL,
      if ct_response.immutable {
        http::HeaderValue::from_static("public, max-age=31536000, immutable")
      } else {
        http::HeaderValue::from_static("no-store")
      },
    );
    return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
      response,
      state.as_ref(),
      evaluated_person_proof.as_ref(),
      dynamic_person_proof_mutation_added,
      &dynamic_challenge_response_mutations,
    ));
  }
  let waf_body_compression_transform =
    crate::waf::route_http_body_compression_transform_enabled(&state.config, resolved.route);
  let request_waf_body_compression_transform =
    waf_body_compression_transform && request_body_need != BodyNeed::None;
  let response_waf_body_compression_transform =
    waf_body_compression_transform && response_body_need != BodyNeed::None;
  let request = request.map(|request_body| {
    if upload_bandwidth_limited {
      request_body
    } else {
      body::with_read_timeout(
        Limited::new(request_body, max_request_body_bytes as usize).boxed(),
        client_body_timeout,
        BodyTimeoutKind::DownstreamRequestRead,
      )
    }
  });
  let request_inspection_lease =
    if request_method != Method::CONNECT && request_body_need != BodyNeed::None {
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
  let request_decompression_lease = if request_waf_body_compression_transform {
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
  let (request, captured_body) =
    if request_method != Method::CONNECT && request_body_need != BodyNeed::None {
      match capture_request_body_for_waf(
        request,
        request_body_need,
        state.config.waf.limits.max_body_inspection_bytes,
        request_waf_body_compression_transform,
        &state.config.waf.http_body_compression,
        &state.waf_body_coding,
      )
      .await
      {
        Ok(result) => result,
        Err(error) => {
          warn!(error = %error, "failed to read request body for WAF inspection");
          let (status, message) = request_body_capture_error_response(&error);
          return route_security.apply(with_pending_dynamic_person_proof_response_mutations(
            text_response(status, message),
            state.as_ref(),
            evaluated_person_proof.as_ref(),
            dynamic_person_proof_mutation_added,
            &dynamic_challenge_response_mutations,
          ));
        }
      }
    } else {
      (request, None)
    };
  let request_body = captured_body.as_ref().map(waf_body_input);

  let mut request_waf = if request_waf_enabled {
    access_log.ensure_request_ids();
    state
      .waf
      .evaluate_request_with_person_proof_async(
        WafRequestInput {
          request_id: access_log.request_id(),
          transaction_id: access_log.transaction_id(),
          received_at_unix_ms: access_log.request_received_at_unix_ms,
          method: &request_method,
          uri: &request_uri,
          version: request_version,
          headers: request.headers(),
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
        },
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
      )
      .await
  } else {
    if !dynamic_person_proof_mutation_added
      && let Some(evaluated) = evaluated_person_proof.as_ref()
      && let Ok(Some(mutation)) = state
        .waf
        .person_proof_clearance_response_mutation(evaluated)
    {
      dynamic_challenge_response_mutations.push(mutation);
    }
    Default::default()
  };
  request_waf
    .response_header_mutations
    .extend(dynamic_challenge_response_mutations);
  drop(request_decompression_lease);
  drop(request_inspection_lease);

  if !request_waf.tags.is_empty() {
    let tags = tags.get_or_insert_with(HashMap::new);
    for (key, value) in &request_waf.tags {
      tags.insert(key.clone(), value.clone());
    }
  }
  access_log.set_tags(&tags);

  if let Some(terminal) = request_waf.terminal {
    return route_security.waf_http_terminal(terminal, &request_waf.response_header_mutations);
  }

  if let Some(static_root) = resolved.route.static_root.as_deref() {
    if request_waf.upstream_override.is_some() || request_waf.upstream_pool_override.is_some() {
      warn!(
        route = %resolved.route.name,
        "WAF selected an upstream target for a static route"
      );
      return route_security.text(
        StatusCode::BAD_GATEWAY,
        "WAF selected an upstream target for a static route",
      );
    }
    access_log.set_upstream("static", "file");
    let response = static_files::serve(
      &request,
      &resolved.route.name,
      resolved.route.effective_path_prefix(),
      static_root,
      &resolved.route.static_files,
      &state.static_files,
      state.config.proxy.static_files.inline_max_bytes,
    )
    .await;
    let response = static_files::finalize_response(
      response,
      state.as_ref(),
      resolved.route,
      &request_waf,
      response_waf_enabled,
      response_body_need,
      &request_method,
      &request_uri,
      request_version,
      request.headers(),
      client_addr,
      host,
      tcp_max_hop,
      tls.as_ref(),
      protocol,
      transport_network,
      transport_metadata,
      downstream_scheme,
      listener_bind,
      request_body,
      tags_ref(&tags),
      access_log,
    )
    .await;
    return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
  }

  if request_method == Method::CONNECT {
    let response = handle_connect_request(
      request,
      state,
      &resolved,
      client_addr,
      host,
      &request_waf,
      request_version,
      connection_limit_context,
      request_connection_permit,
      drain,
      access_log,
      trace_context,
    )
    .await;
    return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
  }

  if is_upgrade_request(&request) {
    let stream_waf = if resolved.execution_plan.waf.stream_enabled {
      access_log.ensure_request_ids();
      StreamWafRequestContext::from_seed(
        state.as_ref(),
        StreamWafRequestSeed {
          request_id: access_log.request_id().to_string(),
          transaction_id: access_log.transaction_id().to_string(),
          received_at_unix_ms: access_log.request_received_at_unix_ms,
          method: request_method.clone(),
          uri: request_uri.clone(),
          version: request_version,
          headers: request.headers().clone(),
          peer_addr: client_addr,
          downstream_host: host.to_string(),
          downstream_scheme,
          route_name: resolved.route.name.clone(),
          tcp_max_hop,
          tls: tls.clone(),
          protocol,
          transport_network,
          tcp_mss: transport_metadata.tcp_mss,
          tcp_rtt_ms: transport_metadata.tcp_rtt_ms,
          udp_datagram_size: transport_metadata.udp_datagram_size,
          udp_connection_id: transport_metadata.udp_connection_id.map(str::to_string),
          tags: tags.clone().unwrap_or_default(),
          dynamic_policy: access_log.dynamic_policy.clone(),
          person_proof: access_log.person_proof_snapshot().cloned(),
        },
      )
      .await
    } else {
      None
    };
    if let Some(response) = handle_upgrade_request(
      request,
      state,
      &resolved,
      forwarded_client_addr,
      client_addr,
      host,
      downstream_scheme,
      downstream_port,
      &request_waf,
      stream_waf,
      connection_limit_context,
      request_connection_permit,
      drain,
      access_log,
      trace_context,
    )
    .await
    {
      return with_circuit_breaker_request_lease(response, route_circuit_breaker_lease);
    }
    return route_security.text(
      StatusCode::NOT_IMPLEMENTED,
      "unsupported HTTP upgrade request",
    );
  }

  upstream::run(UpstreamContext {
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
  })
  .await
}
