use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;

use ::http::{StatusCode, Uri, Version};

use super::{ParsedPlainRequest, TimedStaticResponsePlan};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::proxy::http::static_files::{self, StaticResponsePlan};
use crate::state::AppSnapshot;
use crate::waf::{
  HeaderMutation, RequestWafDecision, WafProtocol, WafRequestInput, WafResponseInput,
  WafTerminalResponse, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
  apply_header_mutations,
};

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_static_waf(
  request: &ParsedPlainRequest,
  request_uri: &Uri,
  snapshot: &AppSnapshot,
  client_addr: SocketAddr,
  transport_metadata: WafTransportMetadataInput<'_>,
  host: &str,
  route_name: &str,
  response_send_timeout: Duration,
  mut plan: StaticResponsePlan,
) -> TimedStaticResponsePlan {
  let tls = WafTlsMetadata::default();
  let dynamic_policy = DynamicPolicyContext::default();
  let request_waf_enabled = snapshot.waf.has_request_rules(route_name);
  let response_waf_enabled = snapshot.waf.has_response_rules(route_name);
  let mut tags = None;
  let request_id =
    (request_waf_enabled || response_waf_enabled).then(crate::waf::new_access_log_id);
  let transaction_id =
    (request_waf_enabled || response_waf_enabled).then(crate::waf::new_access_log_id);
  let request_received_at_unix_ms =
    (request_waf_enabled || response_waf_enabled).then(crate::waf::current_unix_ms);
  let mut request_waf = if request_waf_enabled {
    snapshot.waf.evaluate_request(WafRequestInput {
      request_id: request_id.as_deref().unwrap_or_default(),
      transaction_id: transaction_id.as_deref().unwrap_or_default(),
      received_at_unix_ms: request_received_at_unix_ms.unwrap_or_default(),
      method: &request.method,
      uri: request_uri,
      version: Version::HTTP_11,
      headers: &request.headers,
      body: None,
      peer_addr: client_addr,
      downstream_host: host,
      downstream_scheme: "http",
      route_name,
      tcp_max_hop: None,
      tls: &tls,
      protocol: WafProtocol::Http,
      transport_network: WafTransportNetwork::Tcp,
      transport_metadata,
      tags: &EMPTY_TAGS,
      dynamic_policy: &dynamic_policy,
    })
  } else {
    RequestWafDecision::default()
  };
  if !request_waf.tags.is_empty() {
    let active_tags = tags.get_or_insert_with(HashMap::new);
    for (key, value) in &request_waf.tags {
      active_tags.insert(key.clone(), value.clone());
    }
  }
  if let Some(terminal) = request_waf.terminal.take() {
    return TimedStaticResponsePlan {
      response: static_waf_terminal_plan(terminal, &request_waf.response_header_mutations),
      response_send_timeout,
    };
  }
  if request_waf.upstream_override.is_some() || request_waf.upstream_pool_override.is_some() {
    return TimedStaticResponsePlan {
      response: static_files::text_plan(
        StatusCode::BAD_GATEWAY,
        "WAF selected an upstream target for a static route",
      ),
      response_send_timeout,
    };
  }

  apply_header_mutations(&mut plan.headers, &request_waf.response_header_mutations);
  if response_waf_enabled {
    let response_id = crate::waf::new_access_log_id();
    let request_input = WafRequestInput {
      request_id: request_id.as_deref().unwrap_or_default(),
      transaction_id: transaction_id.as_deref().unwrap_or_default(),
      received_at_unix_ms: request_received_at_unix_ms.unwrap_or_default(),
      method: &request.method,
      uri: request_uri,
      version: Version::HTTP_11,
      headers: &request.headers,
      body: None,
      peer_addr: client_addr,
      downstream_host: host,
      downstream_scheme: "http",
      route_name,
      tcp_max_hop: None,
      tls: &tls,
      protocol: WafProtocol::Http,
      transport_network: WafTransportNetwork::Tcp,
      transport_metadata,
      tags: tags.as_ref().unwrap_or(&EMPTY_TAGS),
      dynamic_policy: &dynamic_policy,
    };
    let response_waf = snapshot.waf.evaluate_response(WafResponseInput {
      request: request_input,
      response_id: &response_id,
      received_at_unix_ms: crate::waf::current_unix_ms(),
      version: Version::HTTP_11,
      status: plan.status,
      headers: &plan.headers,
      body: None,
      upstream_name: "static",
      upstream_pool: None,
      upstream_scheme: "file",
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error: None,
    });
    for access_log in &response_waf.access_logs {
      snapshot.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return TimedStaticResponsePlan {
        response: static_waf_terminal_plan(terminal, &mutations),
        response_send_timeout,
      };
    }
    apply_header_mutations(&mut plan.headers, &response_waf.response_header_mutations);
  }

  TimedStaticResponsePlan {
    response: plan,
    response_send_timeout,
  }
}

fn static_waf_terminal_plan(
  terminal: WafTerminalResponse,
  mutations: &[HeaderMutation],
) -> StaticResponsePlan {
  let mut plan = static_files::text_plan(terminal.status, terminal.body);
  apply_header_mutations(&mut plan.headers, &terminal.headers);
  apply_header_mutations(&mut plan.headers, mutations);
  plan
}
