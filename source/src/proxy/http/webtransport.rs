//! WebTransport preparation for HTTP proxy routes.
//! Session setup validates route and upstream capabilities before handing off to HTTP/3.

use std::collections::HashMap;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use tracing::warn;

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
  add_forwarded_headers, extract_downstream_port, extract_host, set_effective_host_header,
  strip_hop_by_hop_headers, validate_authority_host_consistency,
};
use super::response::{text_response, waf_terminal_response};
use super::route_actions::{self, RouteActionRenderContext};
use super::uri::validate_downstream_path;
use super::version::select_upstream_http_version;
use super::{EffectiveTimeouts, tags_ref};

pub(crate) struct PreparedWebTransport {
  pub(crate) client_addr: std::net::SocketAddr,
  pub(crate) route_name: String,
  pub(crate) trace_context: Option<TraceContext>,
  pub(crate) target_url: url::Url,
  pub(crate) headers: http::HeaderMap,
  pub(crate) protocols: Vec<String>,
  pub(crate) upstream: UpstreamConfig,
  pub(crate) timeouts: EffectiveTimeouts,
  pub(crate) stream_waf: Option<StreamWafRequestContext>,
  _pool_selection: Option<PoolSelection>,
}

pub(crate) async fn prepare_webtransport(
  request: &Request<()>,
  peer_addr: std::net::SocketAddr,
  transport_metadata: WafTransportMetadataInput<'_>,
  tls: &WafTlsMetadata,
  state: &AppSnapshot,
) -> Result<PreparedWebTransport, Box<Response<ProxyBody>>> {
  if validate_authority_host_consistency(request).is_err() {
    warn!("rejected ambiguous downstream WebTransport host metadata");
    return Err(Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "ambiguous host header",
    )));
  }

  let host = extract_host(request).unwrap_or_default();
  let downstream_port = extract_downstream_port(request, "https");
  let path = request.uri().path().to_string();
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream WebTransport path");
    return Err(Box::new(text_response(
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
  let client_addr = match crate::identity::resolve_client_addr(
    &request_headers,
    peer_addr,
    &state.config.proxy.real_ip,
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return Err(Box::new(text_response(
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
    return Err(Box::new(text_response(
      StatusCode::NOT_FOUND,
      "no matching route",
    )));
  };
  let client_asn = state.client_identity.asn.lookup(client_addr.ip());

  let mut evaluated_person_proof = None;
  if state.request_path_features.dynamic_policy
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
        tcp_max_hop: None,
        person_proof_clearance_hash: None,
      })
  {
    let request_id = crate::waf::new_access_log_id();
    let transaction_id = crate::waf::new_access_log_id();
    evaluated_person_proof = Some(state.waf.evaluate_person_proof_request(WafRequestInput {
      request_id: &request_id,
      transaction_id: &transaction_id,
      received_at_unix_ms,
      method: &request_method,
      uri: &request_uri,
      version: http::Version::HTTP_3,
      headers: request.headers(),
      body: None,
      peer_addr: client_addr,
      client_asn,
      downstream_host: &host,
      downstream_scheme: "https",
      route_name: &resolved.route.name,
      tcp_max_hop: None,
      tls,
      protocol: WafProtocol::Webtransport,
      transport_network: WafTransportNetwork::Udp,
      transport_metadata,
      tags: tags_ref(&tags),
      dynamic_policy: &DynamicPolicyContext::default(),
    }));
  }
  let person_proof_clearance_hash = evaluated_person_proof
    .as_ref()
    .and_then(|status| status.clearance_hash());
  let dynamic_policy = if state.request_path_features.dynamic_policy {
    state.dynamic_policy.evaluate(
      DynamicPolicyRequest {
        client_ip: client_addr.ip(),
        route_name: &resolved.route.name,
        method: &request_method,
        path: request_uri.path(),
        headers: Some(request.headers()),
        tls_fingerprint: tls.fingerprint.as_deref(),
        client_asn,
        tcp_max_hop: None,
        person_proof_clearance_hash,
      },
      &state.limits,
    )
  } else {
    Default::default()
  };
  let dynamic_policy_context = dynamic_policy.context;
  let mut dynamic_challenge_response_mutations = Vec::new();
  let mut dynamic_person_proof_mutation_added = false;
  if let Some(terminal) = dynamic_policy.terminal {
    match terminal {
      DynamicPolicyTerminal::Text { status, body } => {
        return Err(Box::new(
          super::with_pending_dynamic_person_proof_response_mutations(
            text_response(status, &body),
            state,
            evaluated_person_proof.as_ref(),
            dynamic_person_proof_mutation_added,
            &dynamic_challenge_response_mutations,
          ),
        ));
      }
      DynamicPolicyTerminal::Challenge { status } => {
        let person_proof_api_path = state.request_path_features.person_proof_api
          && state.waf.has_person_proof_api_path(request_uri.path());
        if !person_proof_api_path {
          let request_id = crate::waf::new_access_log_id();
          let transaction_id = crate::waf::new_access_log_id();
          let decision = match state
            .waf
            .evaluate_dynamic_person_proof_challenge_with_status(
              WafRequestInput {
                request_id: &request_id,
                transaction_id: &transaction_id,
                received_at_unix_ms,
                method: &request_method,
                uri: &request_uri,
                version: http::Version::HTTP_3,
                headers: request.headers(),
                body: None,
                peer_addr: client_addr,
                client_asn,
                downstream_host: &host,
                downstream_scheme: "https",
                route_name: &resolved.route.name,
                tcp_max_hop: None,
                tls,
                protocol: WafProtocol::Webtransport,
                transport_network: WafTransportNetwork::Udp,
                transport_metadata,
                tags: tags_ref(&tags),
                dynamic_policy: &dynamic_policy_context,
              },
              status,
              &mut evaluated_person_proof,
            ) {
            Ok(decision) => decision,
            Err(error) => {
              warn!(error = %error, "failed to evaluate dynamic Person proof challenge");
              return Err(Box::new(
                super::with_pending_dynamic_person_proof_response_mutations(
                  text_response(StatusCode::FORBIDDEN, "person proof challenge failed"),
                  state,
                  evaluated_person_proof.as_ref(),
                  dynamic_person_proof_mutation_added,
                  &dynamic_challenge_response_mutations,
                ),
              ));
            }
          };
          if let Some(terminal) = decision.terminal {
            return Err(Box::new(waf_terminal_response(
              terminal,
              &decision.response_header_mutations,
            )));
          }
          dynamic_person_proof_mutation_added = !decision.response_header_mutations.is_empty();
          dynamic_challenge_response_mutations.extend(decision.response_header_mutations);
        }
      }
    }
  }

  match route_actions::redirect_response(
    resolved.route,
    RouteActionRenderContext {
      route_prefix: resolved.route.effective_path_prefix(),
      path_captures: &resolved.path_captures,
      downstream_scheme: "https",
      downstream_host: &host,
      downstream_uri: &request_uri,
    },
  ) {
    Ok(Some(response)) => {
      return Err(Box::new(
        super::with_pending_dynamic_person_proof_response_mutations(
          response,
          state,
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ),
      ));
    }
    Ok(None) => {}
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to build route redirect response");
      return Err(Box::new(
        super::with_pending_dynamic_person_proof_response_mutations(
          text_response(StatusCode::BAD_REQUEST, "invalid route redirect"),
          state,
          evaluated_person_proof.as_ref(),
          dynamic_person_proof_mutation_added,
          &dynamic_challenge_response_mutations,
        ),
      ));
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
        return Err(Box::new(
          super::with_pending_dynamic_person_proof_response_mutations(
            super::external_auth_response(terminal),
            state,
            evaluated_person_proof.as_ref(),
            dynamic_person_proof_mutation_added,
            &dynamic_challenge_response_mutations,
          ),
        ));
      }
    }
  }
  let request_headers = auth_request.headers().clone();

  let mut request_ids = None;
  let mut request_waf = if resolved.execution_plan.waf.request.enabled() {
    let request_id = crate::waf::new_access_log_id();
    let transaction_id = crate::waf::new_access_log_id();
    let decision = state.waf.evaluate_request_with_person_proof(
      WafRequestInput {
        request_id: &request_id,
        transaction_id: &transaction_id,
        received_at_unix_ms,
        method: &request_method,
        uri: &request_uri,
        version: http::Version::HTTP_3,
        headers: &request_headers,
        body: None,
        peer_addr: client_addr,
        client_asn,
        downstream_host: &host,
        downstream_scheme: "https",
        route_name: &resolved.route.name,
        tcp_max_hop: None,
        tls,
        protocol: WafProtocol::Webtransport,
        transport_network: WafTransportNetwork::Udp,
        transport_metadata,
        tags: tags_ref(&tags),
        dynamic_policy: &dynamic_policy_context,
      },
      evaluated_person_proof.as_ref(),
      dynamic_person_proof_mutation_added,
    );
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
    return Err(Box::new(waf_terminal_response(
      terminal,
      &request_waf.response_header_mutations,
    )));
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
        version: http::Version::HTTP_3,
        headers: request_headers.clone(),
        peer_addr,
        downstream_host: host.to_string(),
        downstream_scheme: "https",
        route_name: resolved.route.name.clone(),
        tcp_max_hop: None,
        tls: Arc::new(tls.clone()),
        protocol: WafProtocol::Webtransport,
        transport_network: WafTransportNetwork::Udp,
        tcp_mss: transport_metadata.tcp_mss,
        tcp_rtt_ms: transport_metadata.tcp_rtt_ms,
        udp_datagram_size: transport_metadata.udp_datagram_size,
        udp_connection_id: transport_metadata.udp_connection_id.map(str::to_string),
        tags: tags.clone().unwrap_or_default(),
        dynamic_policy: dynamic_policy_context.clone(),
      },
    )
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
        return Err(Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "WAF selected an unknown upstream",
        )));
      }
    }
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select_with_cookie_header(
      pool_name,
      client_addr.ip(),
      &format!("{host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
      request.headers().get(http::header::COOKIE),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(error) => {
        warn!(error = %error, pool = %pool_name, "failed to select upstream pool server");
        return Err(Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "no available upstream pool server",
        )));
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
  };

  if !upstream.webtransport {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebTransport",
    )));
  }

  let upstream_version = select_upstream_http_version(
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
  if upstream_version != HttpVersion::H3 {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "WebTransport forwarding requires HTTP/3 upstream",
    )));
  }
  if upstream.origin.scheme() != "https" {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "WebTransport forwarding requires https upstream origin",
    )));
  }

  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "upstream URI is not configured",
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
    Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid upstream URI rewrite",
    ))
  })?;
  let target_url = url::Url::parse(&target_uri.to_string()).map_err(|error| {
    warn!(error = %error, uri = %target_uri, "failed to convert WebTransport target URI");
    Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid WebTransport target URI",
    ))
  })?;

  let mut headers = request_headers;
  strip_hop_by_hop_headers(&mut headers);
  if upstream.preserve_host {
    set_effective_host_header(&mut headers, &host);
  } else {
    headers.remove(http::header::HOST);
  }
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
  state
    .telemetry
    .inject_trace_context(&mut headers, trace_context);

  let protocols = parse_webtransport_protocols(&headers);
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  Ok(PreparedWebTransport {
    client_addr,
    route_name: resolved.route.name.clone(),
    trace_context,
    target_url,
    headers,
    protocols,
    upstream: upstream.clone(),
    timeouts,
    stream_waf,
    _pool_selection: pool_selection,
  })
}

pub(crate) fn parse_webtransport_protocols(headers: &http::HeaderMap) -> Vec<String> {
  headers
    .get("wt-available-protocols")
    .and_then(|value| value.to_str().ok())
    .map(|value| {
      value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_matches('"').to_string())
        .collect()
    })
    .unwrap_or_default()
}
