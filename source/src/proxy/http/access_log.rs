use std::sync::Arc;

use http::{HeaderMap, Method, Request, Response, Uri, Version};

use crate::dynamic_policy::DynamicPolicyContext;
use crate::waf::{
  WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata, WafTransportMetadataInput,
  WafTransportNetwork, WafUpstreamError,
};

use super::body::ProxyBody;
use super::headers::extract_host;

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
  pub(super) request_received_at_unix_ms: u64,
  pub(super) response_received_at_unix_ms: u64,
  pub(super) client_addr: std::net::SocketAddr,
  pub(super) downstream_host: String,
  pub(super) downstream_scheme: &'static str,
  pub(super) route_name: String,
  pub(super) tcp_max_hop: Option<u8>,
  pub(super) tls: Arc<WafTlsMetadata>,
  pub(super) protocol: WafProtocol,
  pub(super) transport_network: WafTransportNetwork,
  pub(super) transport_metadata: WafTransportMetadataInput<'a>,
  pub(super) tags: std::collections::HashMap<String, String>,
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
  pub(super) fn new<B>(
    request: &Request<B>,
    peer_addr: std::net::SocketAddr,
    tcp_max_hop: Option<u8>,
    tls: Arc<WafTlsMetadata>,
    protocol: WafProtocol,
    transport_network: WafTransportNetwork,
    transport_metadata: WafTransportMetadataInput<'a>,
    downstream_scheme: &'static str,
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
      request_received_at_unix_ms: crate::waf::current_unix_ms(),
      response_received_at_unix_ms: 0,
      client_addr: peer_addr,
      downstream_host: extract_host(request).unwrap_or_default(),
      downstream_scheme,
      route_name: String::new(),
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      tags: std::collections::HashMap::new(),
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
    self.ensure_response_ids();
    if self.response_received_at_unix_ms == 0 {
      self.response_received_at_unix_ms = crate::waf::current_unix_ms();
    }
    let request = self.request.as_ref()?;
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
        downstream_host: &self.downstream_host,
        downstream_scheme: self.downstream_scheme,
        route_name: &self.route_name,
        tcp_max_hop: self.tcp_max_hop,
        tls: self.tls.as_ref(),
        protocol: self.protocol,
        transport_network: self.transport_network,
        transport_metadata: self.transport_metadata,
        tags: &self.tags,
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
    self.upstream_error_code = Some(code.to_string());
    self.upstream_error_message = Some(message.to_string());
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
      Arc::new(WafTlsMetadata::default()),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      false,
    );

    assert!(context.request_id.is_none());
    assert!(context.response_id.is_none());
    assert!(context.transaction_id.is_none());
    assert!(context.request.is_none());

    context.ensure_request_id();
    assert!(context.request_id.is_some());
    assert!(context.response_id.is_none());
    assert!(context.transaction_id.is_none());

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
      Arc::new(WafTlsMetadata::default()),
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      WafTransportMetadataInput::default(),
      "https",
      true,
    );

    let snapshot = context.request.as_ref().expect("snapshot should exist");
    assert_eq!(snapshot.uri, "https://example.com/path");
    assert_eq!(snapshot.headers["x-test"], "1");
  }
}
