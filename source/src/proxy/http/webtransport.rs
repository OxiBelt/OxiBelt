//! WebTransport preparation for HTTP proxy routes.
//! Session setup validates route and upstream capabilities before handing off to HTTP/3.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use http::uri::Authority;
use http::{Request, Response, StatusCode};
use tracing::warn;

use crate::bandwidth::RouteBandwidthLimiter;
use crate::config::{HttpVersion, UpstreamConfig};
use crate::dynamic_policy::{DynamicPolicyContext, DynamicPolicyRequest, DynamicPolicyTerminal};
use crate::external_auth::ExternalAuthOutcome;
use crate::pools::PoolSelection;
use crate::proxy::stream_waf::{StreamWafRequestContext, StreamWafRequestSeed};
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::state::AppSnapshot;
use crate::telemetry::TraceContext;
use crate::waf::{
  WafProtocol, WafRequestInput, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
  apply_header_mutations,
};

use super::body::ProxyBody;
use super::headers::{
  add_forwarded_headers, extract_downstream_port, extract_host, strip_hop_by_hop_headers,
  validate_authority_host_consistency,
};
use super::response::{
  silent_close_response, text_response, waf_http_terminal_response_with_route_security,
  with_route_security_headers,
};
use super::route_actions::{self, RouteActionRenderContext};
use super::uri::validate_downstream_path;
use super::version::select_route_upstream_http_version;
use super::{EffectiveTimeouts, tags_ref};

mod response_bandwidth;
pub(crate) use response_bandwidth::shape_webtransport_response;
use response_bandwidth::with_webtransport_bandwidth_context;

pub(crate) struct PreparedWebTransport {
  pub(crate) downstream_http2: bool,
  pub(crate) status_headers: crate::config::StatusHeadersConfig,
  pub(crate) bandwidth: Arc<RouteBandwidthLimiter>,
  pub(crate) client_addr: std::net::SocketAddr,
  pub(crate) route_name: String,
  pub(crate) client_certificate_forwarding: bool,
  pub(crate) trace_context: Option<TraceContext>,
  pub(crate) target_url: url::Url,
  pub(crate) headers: http::HeaderMap,
  pub(crate) protocols: Vec<String>,
  pub(crate) upstream: UpstreamConfig,
  pub(crate) upstream_version: HttpVersion,
  pub(crate) timeouts: EffectiveTimeouts,
  pub(crate) stream_waf: Option<StreamWafRequestContext>,
  _pool_selection: Option<PoolSelection>,
}

pub(crate) async fn prepare_webtransport(
  request: &Request<()>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  transport_metadata: WafTransportMetadataInput<'_>,
  tls: &WafTlsMetadata,
  state: &AppSnapshot,
) -> Result<PreparedWebTransport, Box<Response<ProxyBody>>> {
  let sanitized_request = (!state.client_certificate_forwarding_headers.is_empty()).then(|| {
    let mut sanitized = request.clone();
    super::client_certificate::strip_reserved(sanitized.headers_mut(), state);
    sanitized
  });
  let request = sanitized_request.as_ref().unwrap_or(request);
  let mut response_bandwidth: Option<Arc<RouteBandwidthLimiter>> = None;
  let mut certificate_forwarding_enabled = false;
  let mut status_headers = state.config.proxy.status_headers.clone();
  macro_rules! preparation_error {
    ($response:expr) => {{
      let response = match response_bandwidth.as_ref() {
        Some(bandwidth) => with_webtransport_bandwidth_context($response, bandwidth.clone()),
        None => $response,
      };
      let mut response = response;
      super::client_certificate::finalize_response(
        &mut response,
        certificate_forwarding_enabled,
        state,
      );
      response.extensions_mut().insert(status_headers.clone());
      Box::new(super::status_headers::finalize(response, &status_headers))
    }};
  }
  if validate_authority_host_consistency(request).is_err() {
    warn!("rejected ambiguous downstream WebTransport host metadata");
    return Err(preparation_error!(text_response(
      StatusCode::BAD_REQUEST,
      "ambiguous host header",
    )));
  }

  let host = extract_host(request).unwrap_or_default();
  let downstream_port = extract_downstream_port(request, "https");
  let path = request.uri().path().to_string();
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream WebTransport path");
    return Err(preparation_error!(text_response(
      StatusCode::BAD_REQUEST,
      "invalid request path",
    )));
  }
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_headers = request.headers().clone();
  let trace_context = if state.request_path_features.telemetry {
    state.telemetry.context_from_headers(&request_headers)
  } else {
    None
  };
  let received_at_unix_ms = crate::waf::current_unix_ms();
  let mut tags: Option<HashMap<String, String>> = None;
  let client_addr = match state.resolve_client_addr(
    &request_headers,
    peer_addr,
    &host,
    tls.sni.as_deref().filter(|_| tls.enabled),
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return Err(preparation_error!(text_response(
        StatusCode::BAD_REQUEST,
        "untrusted forwarded client IP metadata",
      )));
    }
  };
  let forwarded_client_addr = super::select_forwarded_client_addr(
    peer_addr,
    client_addr,
    state.config.proxy.forwarded_headers.client_ip_source,
  );
  let Some(resolved) = state.route_table.resolve_normalized_host_with_context(
    &host,
    RouteMatchContext {
      path: &path,
      method: Some(&request_method),
      headers: Some(&request_headers),
      query: request_uri.query(),
      source_ip: Some(client_addr.ip()),
      protocol: Some(RouteRequestProtocol::Webtransport),
      tls: Some(tls),
    },
    &state.upstreams,
  ) else {
    return Err(preparation_error!(text_response(
      StatusCode::NOT_FOUND,
      "no matching route",
    )));
  };
  status_headers = state
    .config
    .proxy
    .status_headers
    .for_route(Some(resolved.route));
  response_bandwidth = Some(resolved.bandwidth.clone());
  certificate_forwarding_enabled = resolved.route.client_certificate_forwarding.is_some();
  if !webtransport_origin_is_allowed(request, &resolved.route.name, state) {
    return Err(preparation_error!(with_route_security_headers(
      text_response(StatusCode::FORBIDDEN, "WebTransport Origin is not allowed"),
      &state.config.security,
      resolved.route,
    )));
  }
  let certificate_forwarding =
    super::client_certificate::PreparedCertificateForwarding::prepare(request, resolved.route)
      .map_err(|status| {
        preparation_error!(text_response(
          status,
          "client certificate forwarding failed"
        ))
      })?;
  if let Some(response) =
    super::early_data::reject_if_disallowed(request, &state.config, resolved.route)
  {
    return Err(preparation_error!(with_route_security_headers(
      response,
      &state.config.security,
      resolved.route,
    )));
  }
  match route_actions::direct_response(resolved.route) {
    Ok(Some(response)) => {
      return Err(preparation_error!(with_route_security_headers(
        response,
        &state.config.security,
        resolved.route,
      )));
    }
    Ok(None) => {}
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to build route direct response");
      return Err(preparation_error!(with_route_security_headers(
        text_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid direct response"),
        &state.config.security,
        resolved.route,
      )));
    }
  }
  let client_asn = state.client_identity.asn.lookup(client_addr.ip());

  let mut evaluated_person_proof = None;
  if resolved.execution_plan.waf.request.enabled()
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
    let request_id = crate::waf::new_access_log_id();
    let transaction_id = crate::waf::new_access_log_id();
    evaluated_person_proof = Some(
      state
        .waf
        .evaluate_person_proof_request_async(WafRequestInput {
          request_id: &request_id,
          transaction_id: &transaction_id,
          received_at_unix_ms,
          method: &request_method,
          uri: &request_uri,
          version: request.version(),
          headers: request.headers(),
          body: None,
          peer_addr: client_addr,
          client_asn,
          web_bot_auth: request
            .extensions()
            .get::<crate::web_bot_auth::WebBotAuthResult>(),
          downstream_host: &host,
          downstream_scheme: "https",
          route_name: &resolved.route.name,
          tcp_max_hop,
          tls,
          protocol: WafProtocol::Webtransport,
          transport_network: if request.version() == http::Version::HTTP_2 {
            WafTransportNetwork::Tcp
          } else {
            WafTransportNetwork::Udp
          },
          transport_metadata,
          tags: tags_ref(&tags),
          dynamic_policy: &DynamicPolicyContext::default(),
        })
        .await,
    );
  }
  let person_proof_clearance_hash = evaluated_person_proof
    .as_ref()
    .and_then(|status| status.clearance_hash());
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
  let dynamic_policy_context = dynamic_policy.context;
  let mut dynamic_challenge_response_mutations = Vec::new();
  let mut dynamic_person_proof_mutation_added = false;
  if let Some(terminal) = dynamic_policy.terminal {
    match terminal {
      DynamicPolicyTerminal::Text { status, body } => {
        return Err(preparation_error!(with_route_security_headers(
          super::with_pending_dynamic_person_proof_response_mutations(
            text_response(status, &body),
            state,
            evaluated_person_proof.as_ref(),
            dynamic_person_proof_mutation_added,
            &dynamic_challenge_response_mutations,
          ),
          &state.config.security,
          resolved.route,
        )));
      }
      DynamicPolicyTerminal::SilentClose => {
        return Err(preparation_error!(silent_close_response()));
      }
      DynamicPolicyTerminal::Challenge { status } => {
        let person_proof_api_path = state.request_path_features.person_proof_api
          && state.waf.has_person_proof_api_path(request_uri.path());
        if !person_proof_api_path {
          let request_id = crate::waf::new_access_log_id();
          let transaction_id = crate::waf::new_access_log_id();
          let decision = match state
            .waf
            .evaluate_dynamic_person_proof_challenge_with_status_async(
              WafRequestInput {
                request_id: &request_id,
                transaction_id: &transaction_id,
                received_at_unix_ms,
                method: &request_method,
                uri: &request_uri,
                version: request.version(),
                headers: request.headers(),
                body: None,
                peer_addr: client_addr,
                client_asn,
                web_bot_auth: request
                  .extensions()
                  .get::<crate::web_bot_auth::WebBotAuthResult>(),
                downstream_host: &host,
                downstream_scheme: "https",
                route_name: &resolved.route.name,
                tcp_max_hop,
                tls,
                protocol: WafProtocol::Webtransport,
                transport_network: if request.version() == http::Version::HTTP_2 {
                  WafTransportNetwork::Tcp
                } else {
                  WafTransportNetwork::Udp
                },
                transport_metadata,
                tags: tags_ref(&tags),
                dynamic_policy: &dynamic_policy_context,
              },
              status,
              &mut evaluated_person_proof,
            )
            .await
          {
            Ok(decision) => decision,
            Err(error) => {
              warn!(error = %error, "failed to evaluate dynamic Person proof challenge");
              return Err(preparation_error!(with_route_security_headers(
                super::with_pending_dynamic_person_proof_response_mutations(
                  text_response(StatusCode::FORBIDDEN, "person proof challenge failed"),
                  state,
                  evaluated_person_proof.as_ref(),
                  dynamic_person_proof_mutation_added,
                  &dynamic_challenge_response_mutations,
                ),
                &state.config.security,
                resolved.route,
              )));
            }
          };
          if let Some(terminal) = decision.terminal {
            return Err(preparation_error!(
              waf_http_terminal_response_with_route_security(
                terminal,
                &decision.response_header_mutations,
                &state.config.security,
                resolved.route,
              )
            ));
          }
          dynamic_person_proof_mutation_added = !decision.response_header_mutations.is_empty();
          dynamic_challenge_response_mutations.extend(decision.response_header_mutations);
        }
      }
    }
  }

  let person_proof_snapshot = evaluated_person_proof
    .as_ref()
    .map(crate::waf::EvaluatedPersonProofRequest::sanitized);

  match route_actions::redirect_response(
    resolved.route,
    RouteActionRenderContext {
      route_prefix: resolved.route.effective_path_prefix(),
      path_captures: &resolved.path_captures,
      downstream_scheme: "https",
      downstream_host: &host,
      downstream_uri: &request_uri,
    },
    downstream_port,
  ) {
    Ok(Some(response)) => {
      return Err(preparation_error!(with_route_security_headers(
        super::with_pending_dynamic_person_proof_response_mutations(
          response,
          state,
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ),
        &state.config.security,
        resolved.route,
      )));
    }
    Ok(None) => {}
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to build route redirect response");
      return Err(preparation_error!(with_route_security_headers(
        super::with_pending_dynamic_person_proof_response_mutations(
          text_response(StatusCode::BAD_REQUEST, "invalid route redirect"),
          state,
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ),
        &state.config.security,
        resolved.route,
      )));
    }
  }

  let mut auth_request = request.clone();
  if resolved.execution_plan.features.external_auth
    && let Some(provider) = resolved.route.external_auth.as_deref()
  {
    match state
      .external_auth
      .authorize(
        provider,
        &mut auth_request,
        client_addr.ip(),
        &host,
        "https",
        &resolved.route.name,
      )
      .await
    {
      ExternalAuthOutcome::Allowed => {}
      ExternalAuthOutcome::Denied(terminal) => {
        return Err(preparation_error!(with_route_security_headers(
          super::with_pending_dynamic_person_proof_response_mutations(
            super::external_auth_response(terminal),
            state,
            evaluated_person_proof.as_ref(),
            dynamic_person_proof_mutation_added,
            &dynamic_challenge_response_mutations,
          ),
          &state.config.security,
          resolved.route,
        )));
      }
    }
  }
  let request_headers = auth_request.headers().clone();

  let mut request_ids = None;
  let mut request_waf = if resolved.execution_plan.waf.request.enabled() {
    let request_id = crate::waf::new_access_log_id();
    let transaction_id = crate::waf::new_access_log_id();
    let decision = state
      .waf
      .evaluate_request_with_person_proof_async(
        WafRequestInput {
          request_id: &request_id,
          transaction_id: &transaction_id,
          received_at_unix_ms,
          method: &request_method,
          uri: &request_uri,
          version: request.version(),
          headers: &request_headers,
          body: None,
          peer_addr: client_addr,
          client_asn,
          web_bot_auth: request
            .extensions()
            .get::<crate::web_bot_auth::WebBotAuthResult>(),
          downstream_host: &host,
          downstream_scheme: "https",
          route_name: &resolved.route.name,
          tcp_max_hop,
          tls,
          protocol: WafProtocol::Webtransport,
          transport_network: if request.version() == http::Version::HTTP_2 {
            WafTransportNetwork::Tcp
          } else {
            WafTransportNetwork::Udp
          },
          transport_metadata,
          tags: tags_ref(&tags),
          dynamic_policy: &dynamic_policy_context,
        },
        evaluated_person_proof.as_ref(),
        dynamic_person_proof_mutation_added,
      )
      .await;
    request_ids = Some((request_id, transaction_id));
    decision
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

  if !request_waf.tags.is_empty() {
    let tags = tags.get_or_insert_with(HashMap::new);
    for (key, value) in request_waf.tags {
      tags.insert(key, value);
    }
  }

  if let Some(terminal) = request_waf.terminal {
    return Err(preparation_error!(
      waf_http_terminal_response_with_route_security(
        terminal,
        &request_waf.response_header_mutations,
        &state.config.security,
        resolved.route,
      )
    ));
  }

  let stream_waf = if resolved.execution_plan.waf.stream_enabled {
    let (request_id, transaction_id) = request_ids.unwrap_or_else(|| {
      (
        crate::waf::new_access_log_id(),
        crate::waf::new_access_log_id(),
      )
    });
    StreamWafRequestContext::from_seed(
      state,
      StreamWafRequestSeed {
        request_id,
        transaction_id,
        received_at_unix_ms,
        method: request_method.clone(),
        uri: request_uri.clone(),
        version: request.version(),
        headers: request_headers.clone(),
        web_bot_auth: request
          .extensions()
          .get::<crate::web_bot_auth::WebBotAuthResult>()
          .cloned(),
        peer_addr,
        downstream_host: host.to_string(),
        downstream_scheme: "https",
        route_name: resolved.route.name.clone(),
        tcp_max_hop,
        tls: Arc::new(tls.clone()),
        protocol: WafProtocol::Webtransport,
        transport_network: if request.version() == http::Version::HTTP_2 {
          WafTransportNetwork::Tcp
        } else {
          WafTransportNetwork::Udp
        },
        tcp_mss: transport_metadata.tcp_mss,
        tcp_rtt_ms: transport_metadata.tcp_rtt_ms,
        udp_datagram_size: transport_metadata.udp_datagram_size,
        udp_connection_id: transport_metadata.udp_connection_id.map(str::to_string),
        proxy_protocol: transport_metadata.proxy_protocol.cloned().map(Arc::new),
        tags: tags.clone().unwrap_or_default(),
        dynamic_policy: dynamic_policy_context.clone(),
        person_proof: person_proof_snapshot.clone(),
      },
    )
    .await
  } else {
    None
  };

  let mut pool_selection = None;
  let upstream = if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    match state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
    {
      Some(upstream) => upstream,
      None => {
        warn!(upstream = upstream_name, "WAF selected an unknown upstream");
        return Err(preparation_error!(with_route_security_headers(
          text_response(StatusCode::BAD_GATEWAY, "WAF selected an unknown upstream"),
          &state.config.security,
          resolved.route,
        )));
      }
    }
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state
      .pools
      .select_with_cookie_header_async(
        pool_name,
        client_addr.ip(),
        &format!("{host}{}", request.uri()),
        request_waf.load_balancing_policy.as_deref(),
        request.headers().get(http::header::COOKIE),
      )
      .await
    {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        pool_selection = Some(selection);
        let Some(upstream) = state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
        else {
          tracing::error!(upstream = %name, "pool selected an unavailable synthetic upstream");
          return Err(preparation_error!(with_route_security_headers(
            text_response(StatusCode::BAD_GATEWAY, "selected upstream is unavailable"),
            &state.config.security,
            resolved.route,
          )));
        };
        upstream
      }
      Err(error) => {
        warn!(error = %error, pool = %pool_name, "failed to select upstream pool server");
        return Err(preparation_error!(with_route_security_headers(
          text_response(StatusCode::BAD_GATEWAY, "no available upstream pool server"),
          &state.config.security,
          resolved.route,
        )));
      }
    }
  } else if let Some(upstream) = resolved.upstream {
    upstream
  } else {
    tracing::error!(route = %resolved.route.name, "validated route has no upstream");
    return Err(preparation_error!(with_route_security_headers(
      text_response(StatusCode::BAD_GATEWAY, "route upstream is unavailable"),
      &state.config.security,
      resolved.route,
    )));
  };

  if !upstream.webtransport {
    return Err(preparation_error!(with_route_security_headers(
      text_response(
        StatusCode::BAD_GATEWAY,
        "selected upstream does not allow WebTransport",
      ),
      &state.config.security,
      resolved.route,
    )));
  }

  let upstream_version = select_route_upstream_http_version(
    resolved.route,
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
  if !matches!(upstream_version, HttpVersion::H2 | HttpVersion::H3) {
    return Err(preparation_error!(with_route_security_headers(
      text_response(
        StatusCode::BAD_GATEWAY,
        "WebTransport forwarding requires HTTP/2 or HTTP/3 upstream",
      ),
      &state.config.security,
      resolved.route,
    )));
  }
  if upstream.origin.scheme() != "https" {
    return Err(preparation_error!(with_route_security_headers(
      text_response(
        StatusCode::BAD_GATEWAY,
        "WebTransport forwarding requires https upstream origin",
      ),
      &state.config.security,
      resolved.route,
    )));
  }

  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return Err(preparation_error!(with_route_security_headers(
      text_response(StatusCode::BAD_GATEWAY, "upstream URI is not configured"),
      &state.config.security,
      resolved.route,
    )));
  };
  let target_uri = route_actions::build_upstream_uri(
    upstream_uri,
    resolved.route,
    RouteActionRenderContext {
      route_prefix: resolved.route.effective_path_prefix(),
      path_captures: &resolved.path_captures,
      downstream_scheme: "https",
      downstream_host: &host,
      downstream_uri: request.uri(),
    },
  )
  .map_err(|error| {
    warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream WebTransport URI");
    preparation_error!(with_route_security_headers(
      text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
      &state.config.security,
      resolved.route,
    ))
  })?;
  let rewrite_authority = resolved
    .route
    .actions
    .rewrite
    .as_ref()
    .is_some_and(|rewrite| rewrite.authority.is_some());
  let (target_uri, _) = preserve_webtransport_authority(
    target_uri,
    request,
    upstream.preserve_host,
    rewrite_authority,
  )
  .map_err(|error| {
    warn!(error, route = %resolved.route.name, "rejected downstream WebTransport authority");
    preparation_error!(with_route_security_headers(
      text_response(StatusCode::BAD_REQUEST, "invalid WebTransport authority"),
      &state.config.security,
      resolved.route,
    ))
  })?;
  let target_url = url::Url::parse(&target_uri.to_string()).map_err(|error| {
    warn!(error = %error, uri = %target_uri, "failed to convert WebTransport target URI");
    preparation_error!(with_route_security_headers(
      text_response(StatusCode::BAD_REQUEST, "invalid WebTransport target URI"),
      &state.config.security,
      resolved.route,
    ))
  })?;

  let mut headers = request_headers;
  strip_hop_by_hop_headers(&mut headers);
  add_forwarded_headers(
    &mut headers,
    forwarded_client_addr,
    &host,
    "https",
    downstream_port,
    state.config.proxy.forwarded_headers.mode,
    None,
  );
  apply_header_mutations(&mut headers, &request_waf.request_header_mutations);
  super::early_data::apply_verified_upstream_header(
    &mut headers,
    super::early_data::is_verified(request),
  );
  state
    .telemetry
    .inject_trace_context(&mut headers, trace_context);
  super::client_certificate::strip_reserved(&mut headers, state);
  if let Some(prepared) = certificate_forwarding {
    prepared
      .apply(&mut headers, &state.config.limits)
      .map_err(|status| {
        preparation_error!(text_response(
          status,
          "client certificate forwarding failed"
        ))
      })?;
  }

  // Extended CONNECT carries its authority in the pseudo-header derived from
  // target_url. An ordinary Host header is redundant and can contradict it.
  headers.remove(http::header::HOST);

  let protocols = parse_webtransport_protocols(&headers).map_err(|error| {
    warn!(error, "rejected invalid WebTransport protocol offer");
    preparation_error!(text_response(
      StatusCode::BAD_REQUEST,
      "invalid WebTransport protocol offer",
    ))
  })?;
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  Ok(PreparedWebTransport {
    downstream_http2: request.version() == http::Version::HTTP_2,
    status_headers,
    bandwidth: resolved.bandwidth.clone(),
    client_addr,
    route_name: resolved.route.name.clone(),
    client_certificate_forwarding: certificate_forwarding_enabled,
    trace_context,
    target_url,
    headers,
    protocols,
    upstream: upstream.clone(),
    upstream_version,
    timeouts,
    stream_waf,
    _pool_selection: pool_selection,
  })
}

/// The upstream connection still uses its configured endpoint and TLS server name.
/// This only changes the CONNECT request target when Host preservation is selected.
fn preserve_webtransport_authority(
  target_uri: http::Uri,
  request: &Request<()>,
  preserve_host: bool,
  rewrite_authority: bool,
) -> Result<(http::Uri, Option<Authority>), &'static str> {
  if !preserve_host || rewrite_authority {
    return Ok((target_uri, None));
  }
  let authority = if let Some(authority) = request.uri().authority() {
    authority.clone()
  } else {
    let host = request
      .headers()
      .get(http::header::HOST)
      .ok_or("missing authority")?
      .to_str()
      .map_err(|_| "invalid Host header")?;
    Authority::from_str(host).map_err(|_| "invalid Host authority")?
  };
  let parsed =
    url::Url::parse(&format!("https://{authority}/")).map_err(|_| "invalid authority URL")?;
  if authority.as_str().ends_with(':')
    || parsed.host_str().is_none()
    || !parsed.username().is_empty()
    || parsed.password().is_some()
    || parsed.port() == Some(0)
  {
    return Err("invalid authority host or port");
  }
  let mut parts = target_uri.into_parts();
  parts.authority = Some(authority.clone());
  let target_uri = http::Uri::from_parts(parts).map_err(|_| "invalid target authority")?;
  Ok((target_uri, Some(authority)))
}

/// A WebTransport Origin is a serialized origin, never a URL with credentials,
/// path, query, or fragment. Both H2 and H3 use the same route CORS policy.
pub(crate) fn webtransport_origin_is_allowed(
  request: &Request<()>,
  route_name: &str,
  state: &AppSnapshot,
) -> bool {
  let mut origins = request.headers().get_all(http::header::ORIGIN).iter();
  let Some(origin) = origins.next() else {
    return true;
  };
  if origins.next().is_some() {
    return false;
  }
  let Ok(origin) = origin.to_str() else {
    return false;
  };
  let Ok(origin_url) = url::Url::parse(origin) else {
    return false;
  };
  if !matches!(origin_url.scheme(), "http" | "https")
    || !origin_url.username().is_empty()
    || origin_url.password().is_some()
    || origin_url.path() != "/"
    || origin_url.query().is_some()
    || origin_url.fragment().is_some()
  {
    return false;
  }
  if origin != origin_url.origin().ascii_serialization() {
    return false;
  }
  let Some(authority) = request.uri().authority() else {
    return false;
  };
  let Ok(request_url) = url::Url::parse(&format!("https://{authority}")) else {
    return false;
  };
  if origin_url.origin() == request_url.origin() {
    return true;
  }
  state
    .config
    .routes
    .iter()
    .find(|route| route.name == route_name)
    .and_then(|route| route.actions.cors.as_ref())
    .is_some_and(|cors| super::cors_origin_allowed(cors, origin))
}

pub(crate) fn parse_webtransport_protocols(
  headers: &http::HeaderMap,
) -> Result<Vec<String>, &'static str> {
  let mut values = Vec::new();
  for value in headers.get_all("wt-available-protocols") {
    if values.len().saturating_add(value.len()).saturating_add(2) > 16 * 1024 {
      return Err("WebTransport protocol offer exceeds 16 KiB");
    }
    if !values.is_empty() {
      values.extend_from_slice(b", ");
    }
    values.extend_from_slice(value.as_bytes());
  }
  if values.is_empty() {
    return Ok(Vec::new());
  }
  let list = sfv::Parser::new(&values)
    .with_version(sfv::Version::Rfc8941)
    .parse::<sfv::List>()
    .map_err(|_| "invalid WebTransport protocol list")?;
  list
    .iter()
    .map(|entry| match entry {
      sfv::ListEntry::Item(item) => item
        .bare_item
        .as_string()
        .map(|value| value.as_str().to_string())
        .ok_or("WebTransport protocol is not a string"),
      sfv::ListEntry::InnerList(_) => Err("WebTransport protocol is an inner list"),
    })
    .collect()
}

#[cfg(test)]
mod authority_tests {
  use super::*;

  #[test]
  fn preserved_authority_keeps_downstream_port_without_changing_path_or_query() {
    let request = Request::builder()
      .uri("https://web-platform.test:11000/connect?token=7")
      .body(())
      .unwrap();
    let target: http::Uri = "https://127.0.0.1:11000/base/connect?token=7"
      .parse()
      .unwrap();
    let (target, authority) = preserve_webtransport_authority(target, &request, true, false)
      .expect("valid downstream authority");
    assert_eq!(
      target.to_string(),
      "https://web-platform.test:11000/base/connect?token=7"
    );
    assert_eq!(authority.unwrap().as_str(), "web-platform.test:11000");
  }

  #[test]
  fn explicit_rewrite_authority_takes_precedence() {
    let request = Request::builder()
      .uri("https://web-platform.test:11000/connect")
      .body(())
      .unwrap();
    let target: http::Uri = "https://rewrite.example:9443/connect".parse().unwrap();
    let (target, authority) =
      preserve_webtransport_authority(target, &request, true, true).unwrap();
    assert_eq!(target.to_string(), "https://rewrite.example:9443/connect");
    assert!(authority.is_none());
  }

  #[test]
  fn preserved_target_canonicalizes_default_https_port() {
    let request = Request::builder()
      .uri("https://EXAMPLE.test:443/connect")
      .body(())
      .unwrap();
    let target: http::Uri = "https://127.0.0.1:11000/connect".parse().unwrap();
    let (target, _) = preserve_webtransport_authority(target, &request, true, false).unwrap();
    let target_url = url::Url::parse(&target.to_string()).unwrap();
    assert_eq!(target_url.as_str(), "https://example.test/connect");
  }

  #[test]
  fn rejects_invalid_preserved_authority() {
    let request = Request::builder()
      .uri("/connect")
      .header(http::header::HOST, "user@web-platform.test:11000")
      .body(())
      .unwrap();
    let target: http::Uri = "https://127.0.0.1:11000/connect".parse().unwrap();
    assert!(preserve_webtransport_authority(target, &request, true, false).is_err());

    let request = Request::builder()
      .uri("/connect")
      .header(http::header::HOST, "example.test:")
      .body(())
      .unwrap();
    let target: http::Uri = "https://127.0.0.1:11000/connect".parse().unwrap();
    assert!(preserve_webtransport_authority(target, &request, true, false).is_err());
  }

  #[test]
  fn offered_protocols_decode_escaped_strings_and_reject_malformed_lists() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
      "wt-available-protocols",
      http::HeaderValue::from_static(r#""a\"b", "c\\d""#),
    );
    assert_eq!(
      parse_webtransport_protocols(&headers).unwrap(),
      vec!["a\"b", "c\\d"]
    );
    headers.insert(
      "wt-available-protocols",
      http::HeaderValue::from_static("token"),
    );
    assert!(parse_webtransport_protocols(&headers).is_err());
  }
}
