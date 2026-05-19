use std::collections::HashMap;
use std::sync::Arc;

use http::{Request, Response, StatusCode};
use tracing::warn;

use crate::config::{HttpVersion, UpstreamConfig};
use crate::dynamic_policy::DynamicPolicyRequest;
use crate::external_auth::ExternalAuthOutcome;
use crate::pools::PoolSelection;
use crate::proxy::stream_waf::{StreamWafRequestContext, StreamWafRequestSeed};
use crate::state::AppSnapshot;
use crate::telemetry::TraceContext;
use crate::waf::{
  WafProtocol, WafRequestInput, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
  apply_header_mutations,
};

use super::body::ProxyBody;
use super::headers::{
  add_forwarded_headers, extract_host, set_effective_host_header, strip_hop_by_hop_headers,
  validate_authority_host_consistency,
};
use super::response::{text_response, waf_terminal_response};
use super::uri::{rewrite_uri, validate_downstream_path};
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
  let trace_context = state.telemetry.context_from_headers(&request_headers);
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
  let Some(resolved) = state
    .route_table
    .resolve_normalized_host(&host, &path, &state.upstreams)
  else {
    return Err(Box::new(text_response(
      StatusCode::NOT_FOUND,
      "no matching route",
    )));
  };

  let dynamic_policy = if state.dynamic_policy.enabled() {
    state.dynamic_policy.evaluate(
      DynamicPolicyRequest {
        client_ip: client_addr.ip(),
        route_name: &resolved.route.name,
        method: &request_method,
        path: request_uri.path(),
      },
      &state.limits,
    )
  } else {
    Default::default()
  };
  if let Some(terminal) = dynamic_policy.terminal {
    return Err(Box::new(text_response(terminal.status, &terminal.body)));
  }
  let dynamic_policy_context = dynamic_policy.context;

  let mut auth_request = request.clone();
  if let Some(provider) = resolved.route.external_auth.as_deref() {
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
        return Err(Box::new(super::external_auth_response(terminal)));
      }
    }
  }
  let request_headers = auth_request.headers().clone();

  let mut request_ids = None;
  let request_waf = if state.waf.enabled() {
    let request_id = crate::waf::new_access_log_id();
    let transaction_id = crate::waf::new_access_log_id();
    let decision = state.waf.evaluate_request(WafRequestInput {
      request_id: &request_id,
      transaction_id: &transaction_id,
      received_at_unix_ms,
      method: &request_method,
      uri: &request_uri,
      version: http::Version::HTTP_3,
      headers: &request_headers,
      body: None,
      peer_addr,
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
    });
    request_ids = Some((request_id, transaction_id));
    decision
  } else {
    Default::default()
  };

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

  let stream_waf = if state.waf.requires_stream_inspection(&resolved.route.name) {
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
        downstream_host: host.clone(),
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
  let target_uri = rewrite_uri(
    upstream_uri,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
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
    client_addr,
    &host,
    "https",
    state.config.proxy.forwarded_headers.mode,
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

fn parse_webtransport_protocols(headers: &http::HeaderMap) -> Vec<String> {
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
