use std::collections::HashMap;
use std::sync::LazyLock;

use http::{HeaderMap, Request, Response};

use crate::proxy::http::SystemAccessLogContext;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::waf_http_terminal_response;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::{
  RequestWafDecision, WafProtocol, WafRequestInput, WafTlsMetadata, WafTransportMetadataInput,
  WafTransportNetwork,
};

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

fn tags_ref(tags: &Option<HashMap<String, String>>) -> &HashMap<String, String> {
  tags.as_ref().unwrap_or(&EMPTY_TAGS)
}

#[derive(Debug)]
pub(crate) struct PlainFastPathWaf {
  pub(crate) request: RequestWafDecision,
  pub(crate) request_headers: Option<HeaderMap>,
  pub(crate) tags: Option<HashMap<String, String>>,
}

impl PlainFastPathWaf {
  pub(crate) fn disabled() -> Self {
    Self {
      request: RequestWafDecision::default(),
      request_headers: None,
      tags: None,
    }
  }
}

pub(crate) fn plain_fast_path_waf_required(resolved: &ResolvedRoute<'_>) -> bool {
  resolved.execution_plan.waf.request.enabled() || resolved.execution_plan.waf.response.enabled()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_plain_fast_path_waf<B>(
  request: &Request<B>,
  state: &AppSnapshot,
  resolved: &ResolvedRoute<'_>,
  client_addr: std::net::SocketAddr,
  host: &str,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  downstream_scheme: &'static str,
  access_log: &mut SystemAccessLogContext<'_>,
) -> Result<PlainFastPathWaf, Box<Response<ProxyBody>>> {
  let response_waf_enabled = resolved.execution_plan.waf.response.enabled();
  let request_headers = if response_waf_enabled {
    Some(request.headers().clone())
  } else {
    None
  };
  let mut tags = None;
  let mut request_waf = if resolved.execution_plan.waf.request.enabled() {
    access_log.ensure_request_ids();
    state.waf.evaluate_request(WafRequestInput {
      request_id: access_log.request_id(),
      transaction_id: access_log.transaction_id(),
      received_at_unix_ms: access_log.request_received_at_unix_ms,
      method: request.method(),
      uri: request.uri(),
      version: request.version(),
      headers: request.headers(),
      body: None,
      peer_addr: client_addr,
      client_asn: state.client_identity.asn.lookup(client_addr.ip()),
      downstream_host: host,
      downstream_scheme,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      tags: tags_ref(&tags),
      dynamic_policy: &access_log.dynamic_policy,
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
  access_log.set_tags(&tags);

  if let Some(terminal) = request_waf.terminal.take() {
    return Err(Box::new(waf_http_terminal_response(
      terminal,
      &request_waf.response_header_mutations,
    )));
  }

  Ok(PlainFastPathWaf {
    request: request_waf,
    request_headers,
    tags,
  })
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use http::StatusCode;
  use pretty_assertions::assert_eq;

  use super::*;
  use crate::config::Config;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  #[tokio::test]
  async fn response_waf_requires_plain_fast_path_waf_prepare() {
    let temp_dir = common::TempDir::new("plain-fast-path-response-waf-required");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-response-waf-required");
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path).replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      ),
      r#"

[waf]
enabled = true

[[waf.rules]]
name = "response-mark"
phase = "response"
priority = 10
when = "Response.Http.Status == 200"

[[waf.rules.actions]]
type = "set_response_header"
name = "x-fast-path-response-waf"
value = "yes"
"#
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");
    let resolved = state
      .route_table
      .resolve("example.com", "/", &state.upstreams)
      .expect("route should resolve");

    assert!(plain_fast_path_waf_required(&resolved));

    let request = Request::builder()
      .uri("https://example.com/")
      .body(())
      .expect("request should build");
    let mut access_log = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      Some(Arc::new(WafTlsMetadata::default())),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
      true,
    );
    let prepared = prepare_plain_fast_path_waf(
      &request,
      &state,
      &resolved,
      "127.0.0.1:12345".parse().unwrap(),
      "example.com",
      None,
      &WafTlsMetadata::default(),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      &mut access_log,
    )
    .expect("response WAF should prepare without evaluating request WAF");

    assert!(
      prepared.request_headers.is_some(),
      "response WAF needs original request headers for response evaluation"
    );
  }

  #[tokio::test]
  async fn prepare_handles_terminal_and_request_mutations() {
    let temp_dir = common::TempDir::new("plain-fast-path-waf-prepare");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-waf-prepare");
    let raw = format!(
      "{}{}",
      common::minimal_config_toml(&cert_path, &key_path).replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      ),
      r#"

[waf]
enabled = true

[[waf.rules]]
name = "block"
phase = "request"
priority = 10
when = "Request.Http.Path == '/blocked'"

[[waf.rules.actions]]
type = "reject"
status = 451
body = "blocked by fast path waf"

[[waf.rules]]
name = "mark"
phase = "request"
priority = 20
when = "Request.Http.Path == '/ok'"

[[waf.rules.actions]]
type = "set_request_header"
name = "x-fast-path-waf"
value = "yes"
"#
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");
    let resolved = state
      .route_table
      .resolve("example.com", "/", &state.upstreams)
      .expect("route should resolve");
    let peer_addr = "127.0.0.1:12345".parse().unwrap();
    let tls = Arc::new(WafTlsMetadata::default());

    let blocked = Request::builder()
      .uri("https://example.com/blocked")
      .body(())
      .expect("request should build");
    let mut access_log = SystemAccessLogContext::new(
      &blocked,
      peer_addr,
      None,
      Some(tls.clone()),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
      true,
    );
    let response = prepare_plain_fast_path_waf(
      &blocked,
      &state,
      &resolved,
      peer_addr,
      "example.com",
      None,
      tls.as_ref(),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      &mut access_log,
    )
    .expect_err("terminal WAF decision should return a response");
    assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);

    let marked = Request::builder()
      .uri("https://example.com/ok")
      .body(())
      .expect("request should build");
    let mut access_log = SystemAccessLogContext::new(
      &marked,
      peer_addr,
      None,
      Some(tls.clone()),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
      true,
    );
    let prepared = prepare_plain_fast_path_waf(
      &marked,
      &state,
      &resolved,
      peer_addr,
      "example.com",
      None,
      tls.as_ref(),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      &mut access_log,
    )
    .expect("header mutation should stay on the fast path");
    assert!(
      prepared.request_headers.is_none(),
      "request headers should not be cloned without response WAF rules"
    );
    assert!(
      prepared
        .request
        .request_header_mutations
        .iter()
        .any(|mutation| matches!(
          mutation,
          crate::waf::HeaderMutation::Set { name, value }
            if name.as_str() == "x-fast-path-waf" && value == "yes"
        ))
    );
  }
}
