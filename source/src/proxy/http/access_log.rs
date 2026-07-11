//! HTTP access-log projection.
//! Request and response metadata is captured without retaining full body contents.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

use http::{HeaderMap, Method, Request, Response, Uri, Version};

use crate::dynamic_policy::DynamicPolicyContext;
use crate::waf::{
  PersonProofRequestSnapshot, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, WafUpstreamError,
};

use super::body::ProxyBody;
static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);
static DEFAULT_METHOD: LazyLock<Method> = LazyLock::new(|| Method::GET);

struct SystemAccessLogRequest {
  method: Method,
  uri: Uri,
  version: Version,
  headers: HeaderMap,
}

pub(crate) struct SystemAccessLogContext<'a> {
  request_id: Option<String>,
  response_id: Option<String>,
  transaction_id: Option<String>,
  request: Option<SystemAccessLogRequest>,
  metadata_enabled: bool,
  method: Option<Method>,
  version: Version,
  pub(super) request_received_at_unix_ms: u64,
  pub(super) response_received_at_unix_ms: u64,
  pub(super) client_addr: std::net::SocketAddr,
  pub(super) downstream_host: String,
  pub(super) downstream_scheme: &'static str,
  pub(super) route_name: String,
  pub(super) tcp_max_hop: Option<u8>,
  pub(super) tls: Option<Arc<WafTlsMetadata>>,
  pub(super) protocol: WafProtocol,
  pub(super) transport_network: WafTransportNetwork,
  pub(super) transport_metadata: WafTransportMetadataInput<'a>,
  pub(super) tags: Option<HashMap<String, String>>,
  person_proof: Option<PersonProofRequestSnapshot>,
  pub(super) dynamic_policy: DynamicPolicyContext,
  pub(super) upstream_name: String,
  pub(super) upstream_pool: Option<String>,
  pub(super) upstream_scheme: String,
  pub(super) upstream_connect_time_ms: Option<u64>,
  pub(super) upstream_first_byte_time_ms: Option<u64>,
  upstream_error_code: Option<String>,
  upstream_error_message: Option<String>,
}

impl<'a> SystemAccessLogContext<'a> {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new<B>(
    request: &Request<B>,
    peer_addr: std::net::SocketAddr,
    tcp_max_hop: Option<u8>,
    tls: Option<Arc<WafTlsMetadata>>,
    protocol: WafProtocol,
    transport_network: WafTransportNetwork,
    transport_metadata: WafTransportMetadataInput<'a>,
    downstream_scheme: &'static str,
    metadata_enabled: bool,
    capture_request: bool,
  ) -> Self {
    let request_snapshot = capture_request.then(|| SystemAccessLogRequest {
      method: request.method().clone(),
      uri: request.uri().clone(),
      version: request.version(),
      headers: request.headers().clone(),
    });

    Self {
      request_id: None,
      response_id: None,
      transaction_id: None,
      request: request_snapshot,
      metadata_enabled,
      method: metadata_enabled.then(|| request.method().clone()),
      version: request.version(),
      request_received_at_unix_ms: 0,
      response_received_at_unix_ms: 0,
      client_addr: peer_addr,
      downstream_host: String::new(),
      downstream_scheme,
      route_name: String::new(),
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      tags: None,
      person_proof: None,
      dynamic_policy: DynamicPolicyContext::default(),
      upstream_name: String::new(),
      upstream_pool: None,
      upstream_scheme: String::new(),
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error_code: None,
      upstream_error_message: None,
    }
  }

  pub(super) fn ensure_request_id(&mut self) {
    self.ensure_request_received_at();
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
  }

  pub(super) fn set_downstream_host(&mut self, host: &str) {
    if self.request.is_none() {
      return;
    }
    self.downstream_host.clear();
    self.downstream_host.push_str(host);
  }

  pub(super) fn set_route_name(&mut self, route_name: &str) {
    if !self.metadata_enabled {
      return;
    }
    self.route_name.clear();
    self.route_name.push_str(route_name);
  }

  pub(super) fn set_tags(&mut self, tags: &Option<HashMap<String, String>>) {
    if self.request.is_none() {
      return;
    }
    self.tags = tags.clone();
  }

  pub(super) fn set_person_proof_snapshot(
    &mut self,
    person_proof: Option<&PersonProofRequestSnapshot>,
  ) {
    self.person_proof = person_proof.cloned();
  }

  pub(super) fn person_proof_snapshot(&self) -> Option<&PersonProofRequestSnapshot> {
    self.person_proof.as_ref()
  }

  pub(super) fn set_upstream(&mut self, upstream_name: &str, upstream_scheme: &str) {
    if !self.metadata_enabled {
      return;
    }
    self.upstream_name.clear();
    self.upstream_name.push_str(upstream_name);
    self.upstream_scheme.clear();
    self.upstream_scheme.push_str(upstream_scheme);
  }

  pub(super) fn set_upstream_pool(&mut self, upstream_pool: &str) {
    if !self.metadata_enabled {
      return;
    }
    self.upstream_pool = Some(upstream_pool.to_string());
  }

  pub(super) fn set_upstream_first_byte_time_ms(&mut self, elapsed_ms: u64) {
    self.upstream_first_byte_time_ms = Some(elapsed_ms);
  }

  pub(super) fn request_id(&self) -> &str {
    self
      .request_id
      .as_deref()
      .expect("request id should be generated before use")
  }

  pub(super) fn response_id(&self) -> &str {
    self
      .response_id
      .as_deref()
      .expect("response id should be generated before use")
  }

  pub(super) fn transaction_id(&self) -> &str {
    self
      .transaction_id
      .as_deref()
      .expect("transaction id should be generated before use")
  }

  pub(super) fn response_input<'b>(
    &'b mut self,
    response: &'b Response<ProxyBody>,
  ) -> Option<WafResponseInput<'b>> {
    self.request.as_ref()?;
    self.tls.as_ref()?;
    self.ensure_response_ids();
    if self.response_received_at_unix_ms == 0 {
      self.response_received_at_unix_ms = crate::waf::current_unix_ms();
    }
    let request = self.request.as_ref()?;
    let tls = self.tls.as_deref()?;
    let upstream_error = self
      .upstream_error_code
      .as_deref()
      .zip(self.upstream_error_message.as_deref())
      .map(|(code, message)| WafUpstreamError { code, message });
    Some(WafResponseInput {
      request: WafRequestInput {
        request_id: self.request_id(),
        transaction_id: self.transaction_id(),
        received_at_unix_ms: self.request_received_at_unix_ms,
        method: &request.method,
        uri: &request.uri,
        version: request.version,
        headers: &request.headers,
        body: None,
        peer_addr: self.client_addr,
        client_asn: None,
        downstream_host: &self.downstream_host,
        downstream_scheme: self.downstream_scheme,
        route_name: &self.route_name,
        tcp_max_hop: self.tcp_max_hop,
        tls,
        protocol: self.protocol,
        transport_network: self.transport_network,
        transport_metadata: self.transport_metadata,
        tags: self.tags(),
        dynamic_policy: &self.dynamic_policy,
      },
      response_id: self.response_id(),
      received_at_unix_ms: self.response_received_at_unix_ms,
      version: response.version(),
      status: response.status(),
      headers: response.headers(),
      body: None,
      upstream_name: &self.upstream_name,
      upstream_pool: self.upstream_pool.as_deref(),
      upstream_scheme: &self.upstream_scheme,
      upstream_connect_time_ms: self.upstream_connect_time_ms,
      upstream_first_byte_time_ms: self.upstream_first_byte_time_ms,
      upstream_error,
    })
  }

  pub(super) fn record_upstream_error(&mut self, code: &str, message: &str) {
    if !self.metadata_enabled {
      return;
    }
    self.upstream_error_code = Some(code.to_string());
    self.upstream_error_message = Some(message.to_string());
  }

  pub(super) fn method(&self) -> &Method {
    self.method.as_ref().unwrap_or(&DEFAULT_METHOD)
  }

  pub(super) fn protocol_label(&self) -> &'static str {
    match (self.protocol, self.version) {
      (WafProtocol::Websocket, _) => "websocket",
      (WafProtocol::Webtransport, _) => "webtransport",
      (_, Version::HTTP_3) => "h3",
      (_, Version::HTTP_2) => "h2",
      (_, Version::HTTP_11) => "h1",
      (_, Version::HTTP_10) => "h1",
      _ => "http",
    }
  }

  pub(super) fn route_name_for_metrics(&self) -> &str {
    if self.route_name.is_empty() {
      "unmatched"
    } else {
      &self.route_name
    }
  }

  pub(super) fn upstream_name_for_metrics(&self) -> &str {
    if self.upstream_name.is_empty() {
      "none"
    } else {
      &self.upstream_name
    }
  }

  pub(super) fn upstream_protocol_for_metrics(&self) -> &str {
    if self.upstream_scheme.is_empty() {
      "none"
    } else {
      &self.upstream_scheme
    }
  }

  pub(super) fn upstream_outcome_for_metrics(&self) -> &str {
    self.upstream_error_code.as_deref().unwrap_or("success")
  }

  pub(super) fn upstream_duration_ms_for_metrics(&self) -> Option<u64> {
    self.upstream_first_byte_time_ms
  }

  pub(super) fn tags(&self) -> &HashMap<String, String> {
    self.tags.as_ref().unwrap_or(&EMPTY_TAGS)
  }

  fn ensure_request_received_at(&mut self) {
    if self.request_received_at_unix_ms == 0 {
      self.request_received_at_unix_ms = crate::waf::current_unix_ms();
    }
  }
}

#[cfg(test)]
mod tests {
  use http::Request;

  use super::*;

  #[test]
  fn ids_are_lazy_until_requested() {
    let request = Request::builder()
      .uri("https://example.com/path")
      .body(())
      .expect("request should build");
    let mut context = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      Some(Arc::new(WafTlsMetadata::default())),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
      false,
    );

    assert!(context.request_id.is_none());
    assert!(context.response_id.is_none());
    assert!(context.transaction_id.is_none());
    assert_eq!(context.request_received_at_unix_ms, 0);
    assert!(context.request.is_none());
    assert!(context.downstream_host.is_empty());
    assert!(context.tags().is_empty());

    context.ensure_request_id();
    assert!(context.request_id.is_some());
    assert!(context.response_id.is_none());
    assert!(context.transaction_id.is_none());
    assert_ne!(context.request_received_at_unix_ms, 0);

    context.ensure_response_ids();
    assert!(context.request_id.is_some());
    assert!(context.response_id.is_some());
    assert!(context.transaction_id.is_some());
  }

  #[test]
  fn request_snapshot_is_optional() {
    let request = Request::builder()
      .uri("https://example.com/path")
      .header("x-test", "1")
      .body(())
      .expect("request should build");
    let context = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      Some(Arc::new(WafTlsMetadata::default())),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      true,
      true,
    );

    let snapshot = context.request.as_ref().expect("snapshot should exist");
    assert_eq!(snapshot.uri, "https://example.com/path");
    assert_eq!(snapshot.headers["x-test"], "1");
  }

  #[test]
  fn host_and_tags_are_lazy() {
    let request = Request::builder()
      .uri("https://example.com/path")
      .header("host", "example.com")
      .body(())
      .expect("request should build");
    let mut context = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      None,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
      false,
    );

    assert!(context.downstream_host.is_empty());
    assert!(context.tags().is_empty());

    context.set_downstream_host("example.com");
    context.set_tags(&Some(HashMap::from([(
      "role".to_string(),
      "api".to_string(),
    )])));

    assert!(context.downstream_host.is_empty());
    assert!(context.tags().is_empty());
  }

  #[test]
  fn metadata_is_lazy_until_needed() {
    let request = Request::builder()
      .uri("https://example.com/path")
      .body(())
      .expect("request should build");
    let mut context = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      None,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
      false,
    );

    context.set_route_name("app");
    context.set_upstream("backend", "http");
    context.set_upstream_pool("pool");
    context.record_upstream_error("connect_error", "upstream request failed");

    assert!(context.method.is_none());
    assert_eq!(context.route_name_for_metrics(), "unmatched");
    assert_eq!(context.upstream_name_for_metrics(), "none");
    assert_eq!(context.upstream_protocol_for_metrics(), "none");
    assert_eq!(context.upstream_outcome_for_metrics(), "success");
    assert!(context.upstream_pool.is_none());

    let mut context = SystemAccessLogContext::new(
      &request,
      "127.0.0.1:12345".parse().unwrap(),
      None,
      None,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      true,
      false,
    );
    context.set_route_name("app");
    context.set_upstream("backend", "http");

    assert_eq!(context.method().as_str(), "GET");
    assert_eq!(context.route_name_for_metrics(), "app");
    assert_eq!(context.upstream_name_for_metrics(), "backend");
    assert_eq!(context.upstream_protocol_for_metrics(), "http");
  }
}
