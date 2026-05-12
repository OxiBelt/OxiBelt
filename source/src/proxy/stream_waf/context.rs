use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{HeaderMap, Method, Uri, Version};

use crate::dynamic_policy::DynamicPolicyContext;
use crate::state::AppSnapshot;
use crate::waf::{
  WafBodyInput, WafProtocol, WafRequestInput, WafStreamDecision, WafStreamDirection,
  WafStreamInput, WafStreamProtocol, WafStreamUnit, WafTlsMetadata, WafTransportMetadataInput,
  WafTransportNetwork, WafWebSocketStreamMetadata, WafWebTransportStreamMetadata,
};

#[derive(Clone)]
pub(crate) struct StreamWafRequestContext {
  request_id: String,
  transaction_id: String,
  received_at_unix_ms: u64,
  method: Method,
  uri: Uri,
  version: Version,
  headers: HeaderMap,
  peer_addr: SocketAddr,
  downstream_host: String,
  downstream_scheme: &'static str,
  route_name: String,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  tcp_mss: Option<u32>,
  tcp_rtt_ms: Option<u64>,
  udp_datagram_size: Option<usize>,
  udp_connection_id: Option<String>,
  tags: HashMap<String, String>,
  dynamic_policy: DynamicPolicyContext,
  max_payload_bytes: usize,
}

pub(crate) struct StreamWafRequestSeed {
  pub(crate) request_id: String,
  pub(crate) transaction_id: String,
  pub(crate) received_at_unix_ms: u64,
  pub(crate) method: Method,
  pub(crate) uri: Uri,
  pub(crate) version: Version,
  pub(crate) headers: HeaderMap,
  pub(crate) peer_addr: SocketAddr,
  pub(crate) downstream_host: String,
  pub(crate) downstream_scheme: &'static str,
  pub(crate) route_name: String,
  pub(crate) tcp_max_hop: Option<u8>,
  pub(crate) tls: Arc<WafTlsMetadata>,
  pub(crate) protocol: WafProtocol,
  pub(crate) transport_network: WafTransportNetwork,
  pub(crate) tcp_mss: Option<u32>,
  pub(crate) tcp_rtt_ms: Option<u64>,
  pub(crate) udp_datagram_size: Option<usize>,
  pub(crate) udp_connection_id: Option<String>,
  pub(crate) tags: HashMap<String, String>,
  pub(crate) dynamic_policy: DynamicPolicyContext,
}

impl StreamWafRequestContext {
  pub(crate) fn from_seed(state: &AppSnapshot, seed: StreamWafRequestSeed) -> Option<Self> {
    if !state.waf.requires_stream_inspection(&seed.route_name) {
      return None;
    }

    Some(Self {
      request_id: seed.request_id,
      transaction_id: seed.transaction_id,
      received_at_unix_ms: seed.received_at_unix_ms,
      method: seed.method,
      uri: seed.uri,
      version: seed.version,
      headers: seed.headers,
      peer_addr: seed.peer_addr,
      downstream_host: seed.downstream_host,
      downstream_scheme: seed.downstream_scheme,
      route_name: seed.route_name,
      tcp_max_hop: seed.tcp_max_hop,
      tls: seed.tls,
      protocol: seed.protocol,
      transport_network: seed.transport_network,
      tcp_mss: seed.tcp_mss,
      tcp_rtt_ms: seed.tcp_rtt_ms,
      udp_datagram_size: seed.udp_datagram_size,
      udp_connection_id: seed.udp_connection_id,
      tags: seed.tags,
      dynamic_policy: seed.dynamic_policy,
      max_payload_bytes: state.config.waf.limits.max_body_inspection_bytes,
    })
  }

  pub(crate) fn max_payload_bytes(&self) -> usize {
    self.max_payload_bytes
  }

  fn request_input(&self) -> WafRequestInput<'_> {
    WafRequestInput {
      request_id: &self.request_id,
      transaction_id: &self.transaction_id,
      received_at_unix_ms: self.received_at_unix_ms,
      method: &self.method,
      uri: &self.uri,
      version: self.version,
      headers: &self.headers,
      body: None,
      peer_addr: self.peer_addr,
      downstream_host: &self.downstream_host,
      downstream_scheme: self.downstream_scheme,
      route_name: &self.route_name,
      tcp_max_hop: self.tcp_max_hop,
      tls: self.tls.as_ref(),
      protocol: self.protocol,
      transport_network: self.transport_network,
      transport_metadata: WafTransportMetadataInput {
        tcp_mss: self.tcp_mss,
        tcp_rtt_ms: self.tcp_rtt_ms,
        udp_datagram_size: self.udp_datagram_size,
        udp_connection_id: self.udp_connection_id.as_deref(),
      },
      tags: &self.tags,
      dynamic_policy: &self.dynamic_policy,
    }
  }

  pub(crate) fn evaluate_websocket(
    &self,
    state: &AppSnapshot,
    direction: WafStreamDirection,
    unit: WafStreamUnit,
    payload: &[u8],
    is_truncated: bool,
    websocket: WafWebSocketStreamMetadata<'_>,
  ) -> WafStreamDecision {
    state.waf.evaluate_stream(WafStreamInput {
      request: self.request_input(),
      protocol: WafStreamProtocol::Websocket,
      direction,
      unit,
      payload: WafBodyInput {
        bytes: payload,
        is_truncated,
      },
      websocket: Some(websocket),
      webtransport: None,
    })
  }

  pub(crate) fn evaluate_webtransport(
    &self,
    state: &AppSnapshot,
    direction: WafStreamDirection,
    payload: &[u8],
    is_truncated: bool,
    metadata: WafWebTransportStreamMetadata,
  ) -> WafStreamDecision {
    state.waf.evaluate_stream(WafStreamInput {
      request: self.request_input(),
      protocol: WafStreamProtocol::Webtransport,
      direction,
      unit: if metadata.datagram_size.is_some() {
        WafStreamUnit::WebtransportDatagram
      } else {
        WafStreamUnit::WebtransportStreamChunk
      },
      payload: WafBodyInput {
        bytes: payload,
        is_truncated,
      },
      websocket: None,
      webtransport: Some(metadata),
    })
  }
}
