//! Runtime request, response, stream, decision, terminal, and mutation types.

use super::*;

#[derive(Debug, Clone, Copy)]
pub struct WafRequestInput<'a> {
  pub request_id: &'a str,
  pub transaction_id: &'a str,
  pub received_at_unix_ms: u64,
  pub method: &'a Method,
  pub uri: &'a Uri,
  pub version: Version,
  pub headers: &'a HeaderMap,
  pub body: Option<WafBodyInput<'a>>,
  pub peer_addr: std::net::SocketAddr,
  pub client_asn: Option<u32>,
  pub downstream_host: &'a str,
  pub downstream_scheme: &'a str,
  pub route_name: &'a str,
  pub tcp_max_hop: Option<u8>,
  pub tls: &'a WafTlsMetadata,
  pub protocol: WafProtocol,
  pub transport_network: WafTransportNetwork,
  pub transport_metadata: WafTransportMetadataInput<'a>,
  pub tags: &'a HashMap<String, String>,
  pub dynamic_policy: &'a DynamicPolicyContext,
}

#[derive(Debug, Clone, Copy)]
pub struct WafBodyInput<'a> {
  pub bytes: &'a [u8],
  pub is_truncated: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct WafResponseInput<'a> {
  pub request: WafRequestInput<'a>,
  pub response_id: &'a str,
  pub received_at_unix_ms: u64,
  pub version: Version,
  pub status: StatusCode,
  pub headers: &'a HeaderMap,
  pub body: Option<WafBodyInput<'a>>,
  pub upstream_name: &'a str,
  pub upstream_pool: Option<&'a str>,
  pub upstream_scheme: &'a str,
  pub upstream_connect_time_ms: Option<u64>,
  pub upstream_first_byte_time_ms: Option<u64>,
  pub upstream_error: Option<WafUpstreamError<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct WafStreamInput<'a> {
  pub request: WafRequestInput<'a>,
  pub protocol: WafStreamProtocol,
  pub direction: WafStreamDirection,
  pub unit: WafStreamUnit,
  pub payload: WafBodyInput<'a>,
  pub websocket: Option<WafWebSocketStreamMetadata<'a>>,
  pub webtransport: Option<WafWebTransportStreamMetadata>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafStreamProtocol {
  Websocket,
  Webtransport,
}

impl WafStreamProtocol {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Websocket => "websocket",
      Self::Webtransport => "webtransport",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafStreamDirection {
  DownstreamToUpstream,
  UpstreamToDownstream,
}

impl WafStreamDirection {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::DownstreamToUpstream => "downstream_to_upstream",
      Self::UpstreamToDownstream => "upstream_to_downstream",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafStreamUnit {
  WebsocketFrame,
  WebsocketMessage,
  WebtransportStreamChunk,
  WebtransportDatagram,
}

impl WafStreamUnit {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::WebsocketFrame => "websocket_frame",
      Self::WebsocketMessage => "websocket_message",
      Self::WebtransportStreamChunk => "webtransport_stream_chunk",
      Self::WebtransportDatagram => "webtransport_datagram",
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct WafWebSocketStreamMetadata<'a> {
  pub opcode: &'a str,
  pub fin: bool,
  pub is_control: bool,
  pub message_opcode: Option<&'a str>,
  pub frame_payload_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct WafWebTransportStreamMetadata {
  pub stream_kind: Option<WafWebTransportStreamKind>,
  pub stream_id: Option<u64>,
  pub datagram_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WafWebTransportStreamKind {
  Bidi,
  Uni,
}

impl WafWebTransportStreamKind {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Bidi => "bidi",
      Self::Uni => "uni",
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub struct WafUpstreamError<'a> {
  pub code: &'a str,
  pub message: &'a str,
}

#[derive(Debug, Default)]
pub struct RequestWafDecision {
  pub terminal: Option<WafHttpTerminal>,
  pub request_header_mutations: Vec<HeaderMutation>,
  pub response_header_mutations: Vec<HeaderMutation>,
  pub tags: Vec<(String, String)>,
  pub upstream_override: Option<String>,
  pub upstream_pool_override: Option<String>,
  pub load_balancing_policy: Option<String>,
}

#[derive(Debug, Default)]
pub struct ResponseWafDecision {
  pub terminal: Option<WafHttpTerminal>,
  pub response_header_mutations: Vec<HeaderMutation>,
  pub access_logs: Vec<AccessLogRecord>,
}

#[derive(Debug, Clone, Default)]
pub struct WafStreamDecision {
  pub close: Option<WafStreamClose>,
  pub silent_close: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WafStreamClose {
  pub websocket_code: u16,
  pub webtransport_code: u32,
  pub reason: String,
}

impl Default for WafStreamClose {
  fn default() -> Self {
    Self {
      websocket_code: default_websocket_close_code(),
      webtransport_code: default_webtransport_close_code(),
      reason: default_stream_close_reason(),
    }
  }
}

pub(super) fn record_request_tag(
  decision: &mut RequestWafDecision,
  active_tags: &mut HashMap<String, String>,
  key: String,
  value: String,
) {
  active_tags.insert(key.clone(), value.clone());
  decision.tags.push((key, value));
}

pub(super) fn person_proof_rate_limited_decision() -> RequestWafDecision {
  RequestWafDecision {
    terminal: Some(WafHttpTerminal::response(
      StatusCode::TOO_MANY_REQUESTS,
      "person proof token capacity exhausted".to_string(),
    )),
    ..RequestWafDecision::default()
  }
}

pub(super) fn apply_crs_request_decision(crs: CrsDecision, decision: &mut RequestWafDecision) {
  if decision.terminal.is_none() {
    decision.terminal = crs.terminal.map(Into::into);
  }
}

pub(super) fn apply_crs_response_decision(crs: CrsDecision, decision: &mut ResponseWafDecision) {
  if decision.terminal.is_none() {
    decision.terminal = crs.terminal.map(Into::into);
  }
}

#[derive(Debug)]
pub struct WafTerminalResponse {
  pub status: StatusCode,
  pub body: String,
  pub headers: Vec<HeaderMutation>,
}

impl WafTerminalResponse {
  pub(super) fn new(status: StatusCode, body: String) -> Self {
    Self {
      status,
      body,
      headers: Vec::new(),
    }
  }
}

#[derive(Debug)]
pub enum WafHttpTerminal {
  Response(WafTerminalResponse),
  SilentClose,
}

impl WafHttpTerminal {
  pub(super) fn response(status: StatusCode, body: String) -> Self {
    Self::Response(WafTerminalResponse::new(status, body))
  }

  pub fn is_silent_close(&self) -> bool {
    matches!(self, Self::SilentClose)
  }

  pub fn into_response(self) -> Option<WafTerminalResponse> {
    match self {
      Self::Response(response) => Some(response),
      Self::SilentClose => None,
    }
  }
}

impl Deref for WafHttpTerminal {
  type Target = WafTerminalResponse;

  fn deref(&self) -> &Self::Target {
    match self {
      Self::Response(response) => response,
      Self::SilentClose => panic!("silent_close WAF terminal has no HTTP response"),
    }
  }
}

impl From<WafTerminalResponse> for WafHttpTerminal {
  fn from(response: WafTerminalResponse) -> Self {
    Self::Response(response)
  }
}

#[derive(Debug, Clone)]
pub enum HeaderMutation {
  Set {
    name: HeaderName,
    value: HeaderValue,
  },
  Append {
    name: HeaderName,
    value: HeaderValue,
  },
  Remove {
    name: HeaderName,
  },
}
