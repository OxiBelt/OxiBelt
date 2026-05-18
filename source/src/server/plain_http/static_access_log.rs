use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::LazyLock;

use ::http::{Uri, Version};

use super::{TimedStaticResponsePlan, parse::ParsedPlainRequest};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::state::AppSnapshot;
use crate::waf::{
  WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata, WafTransportMetadataInput,
  WafTransportNetwork,
};

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

pub(super) struct StaticFastPathContext {
  request_id: Option<String>,
  response_id: Option<String>,
  transaction_id: Option<String>,
  pub(super) request_received_at_unix_ms: u64,
  pub(super) response_received_at_unix_ms: u64,
  pub(super) request_uri: Uri,
  pub(super) client_addr: SocketAddr,
  pub(super) downstream_host: String,
  pub(super) route_name: String,
  tags: Option<HashMap<String, String>>,
}

impl StaticFastPathContext {
  pub(super) fn new(
    request_uri: Uri,
    peer_addr: SocketAddr,
    downstream_host: String,
    route_name: String,
  ) -> Self {
    Self {
      request_id: None,
      response_id: None,
      transaction_id: None,
      request_received_at_unix_ms: 0,
      response_received_at_unix_ms: 0,
      request_uri,
      client_addr: peer_addr,
      downstream_host,
      route_name,
      tags: None,
    }
  }

  fn ensure_request_id(&mut self) {
    if self.request_received_at_unix_ms == 0 {
      self.request_received_at_unix_ms = crate::waf::current_unix_ms();
    }
    if self.request_id.is_none() {
      self.request_id = Some(crate::waf::new_access_log_id());
    }
  }

  pub(super) fn ensure_request_ids(&mut self) {
    self.ensure_request_id();
    if self.transaction_id.is_none() {
      self.transaction_id = Some(crate::waf::new_access_log_id());
    }
  }

  pub(super) fn ensure_response_ids(&mut self) {
    self.ensure_request_ids();
    if self.response_id.is_none() {
      self.response_id = Some(crate::waf::new_access_log_id());
    }
    if self.response_received_at_unix_ms == 0 {
      self.response_received_at_unix_ms = crate::waf::current_unix_ms();
    }
  }

  pub(super) fn add_tags(&mut self, tags: &[(String, String)]) {
    if tags.is_empty() {
      return;
    }
    let active_tags = self.tags.get_or_insert_with(HashMap::new);
    for (key, value) in tags {
      active_tags.insert(key.clone(), value.clone());
    }
  }

  pub(super) fn request_id(&self) -> &str {
    self
      .request_id
      .as_deref()
      .expect("static fast-path request id should be generated before use")
  }

  pub(super) fn response_id(&self) -> &str {
    self
      .response_id
      .as_deref()
      .expect("static fast-path response id should be generated before use")
  }

  pub(super) fn transaction_id(&self) -> &str {
    self
      .transaction_id
      .as_deref()
      .expect("static fast-path transaction id should be generated before use")
  }

  pub(super) fn tags(&self) -> &HashMap<String, String> {
    self.tags.as_ref().unwrap_or(&EMPTY_TAGS)
  }
}

pub(super) fn emit_system_access_log(
  request: &ParsedPlainRequest,
  snapshot: &AppSnapshot,
  transport_metadata: WafTransportMetadataInput<'_>,
  plan: &mut TimedStaticResponsePlan,
) {
  if !snapshot.system_access_log.enabled() {
    return;
  }
  let Some(access_log) = plan.access_log.as_mut() else {
    return;
  };
  access_log.ensure_response_ids();

  let tls = WafTlsMetadata::default();
  let dynamic_policy = DynamicPolicyContext::default();
  snapshot.system_access_log.emit(
    &snapshot.waf,
    WafResponseInput {
      request: WafRequestInput {
        request_id: access_log.request_id(),
        transaction_id: access_log.transaction_id(),
        received_at_unix_ms: access_log.request_received_at_unix_ms,
        method: &request.method,
        uri: &access_log.request_uri,
        version: Version::HTTP_11,
        headers: &request.headers,
        body: None,
        peer_addr: access_log.client_addr,
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
      response_id: access_log.response_id(),
      received_at_unix_ms: access_log.response_received_at_unix_ms,
      version: Version::HTTP_11,
      status: plan.response.status,
      headers: &plan.response.headers,
      body: None,
      upstream_name: "static",
      upstream_pool: None,
      upstream_scheme: "file",
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error: None,
    },
  );
}
