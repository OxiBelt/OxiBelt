use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{HeaderMap, Method, Uri, Version};

use crate::dynamic_policy::DynamicPolicyContext;
use crate::state::AppSnapshot;
use crate::waf::{
  PersonProofRequestSnapshot, WafBodyInput, WafProtocol, WafRequestInput, WafStreamDecision,
  WafStreamDirection, WafStreamInput, WafStreamProtocol, WafStreamUnit, WafTlsMetadata,
  WafTransportMetadataInput, WafTransportNetwork, WafWebSocketStreamMetadata,
  WafWebTransportStreamMetadata,
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
  person_proof: PersonProofRequestSnapshot,
  upstream_certificate: Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
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
  pub(crate) person_proof: Option<PersonProofRequestSnapshot>,
}

impl StreamWafRequestContext {
  pub(crate) async fn from_seed(state: &AppSnapshot, seed: StreamWafRequestSeed) -> Option<Self> {
    if !state.waf.requires_stream_inspection(&seed.route_name) {
      return None;
    }

    // Resolve any missing state before payload frames are retained by the
    // WebSocket or WebTransport relay.  Normal HTTP paths supply a snapshot;
    // this fallback covers isolated stream entry points.
    let person_proof = match seed.person_proof.clone() {
      Some(person_proof) => person_proof,
      None => state
        .waf
        .evaluate_person_proof_request_async(WafRequestInput {
          request_id: &seed.request_id,
          transaction_id: &seed.transaction_id,
          received_at_unix_ms: seed.received_at_unix_ms,
          method: &seed.method,
          uri: &seed.uri,
          version: seed.version,
          headers: &seed.headers,
          body: None,
          peer_addr: seed.peer_addr,
          client_asn: None,
          downstream_host: &seed.downstream_host,
          downstream_scheme: seed.downstream_scheme,
          route_name: &seed.route_name,
          tcp_max_hop: seed.tcp_max_hop,
          tls: seed.tls.as_ref(),
          protocol: seed.protocol,
          transport_network: seed.transport_network,
          transport_metadata: WafTransportMetadataInput {
            tcp_mss: seed.tcp_mss,
            tcp_rtt_ms: seed.tcp_rtt_ms,
            udp_datagram_size: seed.udp_datagram_size,
            udp_connection_id: seed.udp_connection_id.as_deref(),
          },
          tags: &seed.tags,
          dynamic_policy: &seed.dynamic_policy,
        })
        .await
        .sanitized(),
    };

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
      person_proof,
      upstream_certificate: None,
      max_payload_bytes: state.config.waf.limits.max_body_inspection_bytes,
    })
  }

  pub(crate) fn with_upstream_certificate(
    mut self,
    upstream_certificate: Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
  ) -> Self {
    self.upstream_certificate = upstream_certificate;
    self
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
      client_asn: None,
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
    state.waf.evaluate_stream_with_person_proof_snapshot(
      stream_input(
        self.request_input(),
        WafStreamProtocol::Websocket,
        direction,
        unit,
        WafBodyInput {
          bytes: payload,
          is_truncated,
        },
        Some(websocket),
        None,
        self.upstream_certificate.as_deref(),
      ),
      &self.person_proof,
    )
  }

  pub(crate) fn evaluate_webtransport(
    &self,
    state: &AppSnapshot,
    direction: WafStreamDirection,
    payload: &[u8],
    is_truncated: bool,
    metadata: WafWebTransportStreamMetadata,
  ) -> WafStreamDecision {
    state.waf.evaluate_stream_with_person_proof_snapshot(
      stream_input(
        self.request_input(),
        WafStreamProtocol::Webtransport,
        direction,
        if metadata.datagram_size.is_some() {
          WafStreamUnit::WebtransportDatagram
        } else {
          WafStreamUnit::WebtransportStreamChunk
        },
        WafBodyInput {
          bytes: payload,
          is_truncated,
        },
        None,
        Some(metadata),
        self.upstream_certificate.as_deref(),
      ),
      &self.person_proof,
    )
  }
}

#[allow(clippy::too_many_arguments)]
fn stream_input<'a>(
  request: WafRequestInput<'a>,
  protocol: WafStreamProtocol,
  direction: WafStreamDirection,
  unit: WafStreamUnit,
  payload: WafBodyInput<'a>,
  websocket: Option<WafWebSocketStreamMetadata<'a>>,
  webtransport: Option<WafWebTransportStreamMetadata>,
  upstream_certificate: Option<&'a crate::waf::metadata::WafCertificateMetadata>,
) -> WafStreamInput<'a> {
  WafStreamInput {
    request,
    protocol,
    direction,
    unit,
    payload,
    websocket,
    webtransport,
    upstream_certificate,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn request_input<'a>(
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    tls: &'a WafTlsMetadata,
    tags: &'a HashMap<String, String>,
    dynamic_policy: &'a DynamicPolicyContext,
  ) -> WafRequestInput<'a> {
    WafRequestInput {
      request_id: "request",
      transaction_id: "transaction",
      received_at_unix_ms: 0,
      method,
      uri,
      version: Version::HTTP_3,
      headers,
      body: None,
      peer_addr: "127.0.0.1:443".parse().unwrap(),
      client_asn: None,
      downstream_host: "example.test",
      downstream_scheme: "https",
      route_name: "stream",
      tcp_max_hop: None,
      tls,
      protocol: WafProtocol::Webtransport,
      transport_network: WafTransportNetwork::Udp,
      transport_metadata: WafTransportMetadataInput::default(),
      tags,
      dynamic_policy,
    }
  }

  #[test]
  fn stream_input_propagates_upstream_certificate_for_both_directions() {
    let tls = WafTlsMetadata::default();
    let tags = HashMap::new();
    let dynamic_policy = DynamicPolicyContext::default();
    let certificate = crate::waf::metadata::WafCertificateMetadata::default();
    let method = Method::GET;
    let uri = "https://example.test/stream".parse().unwrap();
    let headers = HeaderMap::new();
    let payload = b"stream";

    let downstream = stream_input(
      request_input(&method, &uri, &headers, &tls, &tags, &dynamic_policy),
      WafStreamProtocol::Websocket,
      WafStreamDirection::DownstreamToUpstream,
      WafStreamUnit::WebsocketFrame,
      WafBodyInput {
        bytes: payload,
        is_truncated: false,
      },
      None,
      None,
      Some(&certificate),
    );
    let upstream = stream_input(
      request_input(&method, &uri, &headers, &tls, &tags, &dynamic_policy),
      WafStreamProtocol::Webtransport,
      WafStreamDirection::UpstreamToDownstream,
      WafStreamUnit::WebtransportStreamChunk,
      WafBodyInput {
        bytes: payload,
        is_truncated: false,
      },
      None,
      None,
      Some(&certificate),
    );

    assert!(std::ptr::eq(
      downstream
        .upstream_certificate
        .expect("downstream certificate"),
      &certificate,
    ));
    assert!(std::ptr::eq(
      upstream.upstream_certificate.expect("upstream certificate"),
      &certificate,
    ));
  }

  #[test]
  fn stream_input_omits_certificate_without_upstream_identity() {
    let tls = WafTlsMetadata::default();
    let tags = HashMap::new();
    let dynamic_policy = DynamicPolicyContext::default();
    let method = Method::GET;
    let uri = "https://example.test/stream".parse().unwrap();
    let headers = HeaderMap::new();
    let input = stream_input(
      request_input(&method, &uri, &headers, &tls, &tags, &dynamic_policy),
      WafStreamProtocol::Webtransport,
      WafStreamDirection::UpstreamToDownstream,
      WafStreamUnit::WebtransportDatagram,
      WafBodyInput {
        bytes: b"datagram",
        is_truncated: false,
      },
      None,
      None,
      None,
    );

    assert!(input.upstream_certificate.is_none());
  }
}
