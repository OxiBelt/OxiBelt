//! WAF integration for static responses in the plain HTTP path.
//! Static shortcuts still consult WAF plans before serving local content.

use std::net::SocketAddr;
use std::time::Duration;

use ::http::{StatusCode, Version};

use super::{
  TimedStaticResponsePlan, parse::ParsedPlainRequest, static_access_log::StaticFastPathContext,
};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::proxy::http::static_files::{self, StaticResponsePlan};
use crate::routes::RouteWafExecutionPlan;
use crate::state::AppSnapshot;
use crate::waf::{
  HeaderMutation, RequestWafDecision, WafHttpTerminal, WafProtocol, WafRequestInput,
  WafResponseInput, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
  apply_header_mutations,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_static_waf(
  request: &ParsedPlainRequest,
  snapshot: &AppSnapshot,
  route_waf: RouteWafExecutionPlan,
  client_addr: SocketAddr,
  transport_metadata: WafTransportMetadataInput<'_>,
  mut access_log: StaticFastPathContext,
  response_send_timeout: Duration,
  mut plan: StaticResponsePlan,
) -> TimedStaticResponsePlan {
  let tls = WafTlsMetadata::default();
  let dynamic_policy = DynamicPolicyContext::default();
  let request_waf_enabled = route_waf.request.enabled();
  let response_waf_enabled = route_waf.response.enabled();
  let evaluated_person_proof = if request_waf_enabled || response_waf_enabled {
    access_log.ensure_request_ids();
    Some(
      snapshot
        .waf
        .evaluate_person_proof_request_async(WafRequestInput {
          request_id: access_log.request_id(),
          transaction_id: access_log.transaction_id(),
          received_at_unix_ms: access_log.request_received_at_unix_ms,
          method: &request.method,
          uri: &access_log.request_uri,
          version: Version::HTTP_11,
          headers: &request.headers,
          body: None,
          peer_addr: client_addr,
          client_asn: snapshot.client_identity.asn.lookup(client_addr.ip()),
          downstream_host: &access_log.downstream_host,
          downstream_scheme: "http",
          route_name: &access_log.route_name,
          tcp_max_hop: None,
          tls: &tls,
          protocol: WafProtocol::Http,
          transport_network: WafTransportNetwork::Tcp,
          transport_metadata,
          tags: access_log.tags(),
          dynamic_policy: &dynamic_policy,
        })
        .await,
    )
  } else {
    None
  };
  let person_proof_snapshot = evaluated_person_proof
    .as_ref()
    .map(crate::waf::EvaluatedPersonProofRequest::sanitized);
  access_log.set_person_proof_snapshot(person_proof_snapshot.as_ref());
  let mut request_waf = if request_waf_enabled {
    snapshot
      .waf
      .evaluate_request_with_person_proof_async(
        WafRequestInput {
          request_id: access_log.request_id(),
          transaction_id: access_log.transaction_id(),
          received_at_unix_ms: access_log.request_received_at_unix_ms,
          method: &request.method,
          uri: &access_log.request_uri,
          version: Version::HTTP_11,
          headers: &request.headers,
          body: None,
          peer_addr: client_addr,
          client_asn: snapshot.client_identity.asn.lookup(client_addr.ip()),
          downstream_host: &access_log.downstream_host,
          downstream_scheme: "http",
          route_name: &access_log.route_name,
          tcp_max_hop: None,
          tls: &tls,
          protocol: WafProtocol::Http,
          transport_network: WafTransportNetwork::Tcp,
          transport_metadata,
          tags: access_log.tags(),
          dynamic_policy: &dynamic_policy,
        },
        evaluated_person_proof.as_ref(),
        false,
      )
      .await
  } else {
    RequestWafDecision::default()
  };
  access_log.add_tags(&request_waf.tags);
  if let Some(terminal) = request_waf.terminal.take() {
    return TimedStaticResponsePlan {
      silent_close: terminal.is_silent_close(),
      response: static_waf_terminal_plan(terminal, &request_waf.response_header_mutations),
      response_send_timeout,
      access_log: Some(access_log),
    };
  }
  if request_waf.upstream_override.is_some() || request_waf.upstream_pool_override.is_some() {
    return TimedStaticResponsePlan {
      response: static_files::text_plan(
        StatusCode::BAD_GATEWAY,
        "WAF selected an upstream target for a static route",
      ),
      response_send_timeout,
      access_log: Some(access_log),
      silent_close: false,
    };
  }

  apply_header_mutations(&mut plan.headers, &request_waf.response_header_mutations);
  if response_waf_enabled {
    access_log.ensure_response_ids();
    let request_input = WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: &request.method,
      uri: &access_log.request_uri,
      version: Version::HTTP_11,
      headers: &request.headers,
      body: None,
      peer_addr: client_addr,
      client_asn: snapshot.client_identity.asn.lookup(client_addr.ip()),
      downstream_host: &access_log.downstream_host,
      downstream_scheme: "http",
      route_name: &access_log.route_name,
      tcp_max_hop: None,
      tls: &tls,
      protocol: WafProtocol::Http,
      transport_network: WafTransportNetwork::Tcp,
      transport_metadata,
      tags: access_log.tags(),
      dynamic_policy: &dynamic_policy,
    };
    let person_proof = access_log
      .person_proof_snapshot()
      .expect("static response WAF should have a request-scoped Person proof snapshot");
    let response_waf = snapshot.waf.evaluate_response_with_person_proof_snapshot(
      WafResponseInput {
        request: request_input,
        response_id: access_log.response_id(),
        received_at_unix_ms: access_log.response_received_at_unix_ms,
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
      },
      person_proof,
    );
    for access_log in &response_waf.access_logs {
      snapshot.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return TimedStaticResponsePlan {
        silent_close: terminal.is_silent_close(),
        response: static_waf_terminal_plan(terminal, &mutations),
        response_send_timeout,
        access_log: Some(access_log),
      };
    }
    apply_header_mutations(&mut plan.headers, &response_waf.response_header_mutations);
  }

  TimedStaticResponsePlan {
    response: plan,
    response_send_timeout,
    access_log: Some(access_log),
    silent_close: false,
  }
}

fn static_waf_terminal_plan(
  terminal: WafHttpTerminal,
  mutations: &[HeaderMutation],
) -> StaticResponsePlan {
  let Some(terminal) = terminal.into_response() else {
    return static_files::text_plan(StatusCode::NO_CONTENT, "");
  };
  let mut plan = static_files::text_plan(terminal.status, terminal.body);
  apply_header_mutations(&mut plan.headers, &terminal.headers);
  apply_header_mutations(&mut plan.headers, mutations);
  plan
}
