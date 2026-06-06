//! Devtools fixture construction for repeatable OxiRule analysis.
//! Fixtures isolate sample data from live proxy traffic.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

use anyhow::{Context, bail};
use base64::Engine;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};

use crate::config::Config;
use crate::dynamic_policy::DynamicPolicyContext;

use super::super::{
  WafBodyInput, WafPhase, WafProtocol, WafRequestInput, WafResponseInput, WafStreamDirection,
  WafStreamInput, WafStreamProtocol, WafStreamUnit, WafTlsMetadata, WafTransportMetadataInput,
  WafTransportNetwork, WafUpstreamError, WafWebSocketStreamMetadata, WafWebTransportStreamKind,
  WafWebTransportStreamMetadata, current_unix_ms, new_access_log_id,
};
use super::types::{
  HeaderInput, OxiRuleFixture, OxiRuleRequestFixture, OxiRuleResponseFixture, OxiRuleStreamFixture,
  OxiRuleUpstreamErrorFixture, OxiRuleWebSocketFixture, default_method, default_status,
  default_stream_direction, default_stream_protocol, default_stream_unit, default_uri,
  default_ws_opcode,
};

pub(super) struct BuiltFixture {
  phase: WafPhase,
  route_name: String,
  request_id: String,
  transaction_id: String,
  response_id: String,
  method: Method,
  uri: Uri,
  request_version: Version,
  request_headers: HeaderMap,
  request_body: Option<Vec<u8>>,
  request_body_truncated: bool,
  peer_addr: SocketAddr,
  downstream_host: String,
  downstream_scheme: String,
  tcp_max_hop: Option<u8>,
  tls: WafTlsMetadata,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  tcp_mss: Option<u32>,
  tcp_rtt_ms: Option<u64>,
  udp_datagram_size: Option<usize>,
  udp_connection_id: Option<String>,
  tags: HashMap<String, String>,
  dynamic_policy: DynamicPolicyContext,
  response_version: Version,
  response_status: StatusCode,
  response_headers: HeaderMap,
  response_body: Option<Vec<u8>>,
  response_body_truncated: bool,
  upstream_name: String,
  upstream_pool: Option<String>,
  upstream_scheme: String,
  upstream_connect_time_ms: Option<u64>,
  upstream_first_byte_time_ms: Option<u64>,
  upstream_error: Option<OxiRuleUpstreamErrorFixture>,
  stream_protocol: WafStreamProtocol,
  stream_direction: WafStreamDirection,
  stream_unit: WafStreamUnit,
  stream_payload: Vec<u8>,
  stream_payload_truncated: bool,
  websocket_opcode: String,
  websocket_fin: bool,
  websocket_is_control: bool,
  websocket_message_opcode: Option<String>,
  websocket_frame_payload_size: usize,
  webtransport_stream_kind: Option<WafWebTransportStreamKind>,
  webtransport_stream_id: Option<u64>,
  webtransport_datagram_size: Option<usize>,
}

impl BuiltFixture {
  pub(super) fn new(
    config: &Config,
    fallback_route: &str,
    fixture: OxiRuleFixture,
  ) -> anyhow::Result<Self> {
    let phase = fixture.phase.unwrap_or_else(|| {
      if fixture.stream.is_some() {
        WafPhase::Stream
      } else if fixture.response.is_some() {
        WafPhase::Response
      } else {
        WafPhase::Request
      }
    });
    let route_name = fixture
      .route
      .or_else(|| config.routes.first().map(|route| route.name.clone()))
      .unwrap_or_else(|| fallback_route.to_string());
    let method = Method::from_bytes(fixture.request.method.as_bytes())
      .with_context(|| format!("invalid request method {}", fixture.request.method))?;
    let uri = fixture
      .request
      .uri
      .parse::<Uri>()
      .with_context(|| format!("invalid request URI {}", fixture.request.uri))?;
    let request_headers = header_map(&fixture.request.headers)?;
    let downstream_host = fixture
      .request
      .downstream_host
      .clone()
      .or_else(|| {
        request_headers
          .get(http::header::HOST)
          .and_then(|value| value.to_str().ok())
          .map(str::to_string)
      })
      .or_else(|| uri.host().map(str::to_string))
      .unwrap_or_else(|| "example.com".to_string());
    let response = fixture.response.unwrap_or_default();
    let stream = fixture.stream.unwrap_or_else(default_stream_fixture);
    let websocket = stream.websocket.unwrap_or_else(default_websocket_fixture);
    let webtransport = stream.webtransport.unwrap_or_default();
    let response_status = StatusCode::from_u16(response.status)
      .with_context(|| format!("invalid response status {}", response.status))?;
    let stream_payload =
      decode_body(stream.payload.as_deref(), stream.payload_base64.as_deref())?.unwrap_or_default();
    let stream_payload_len = stream_payload.len();
    Ok(Self {
      phase,
      route_name,
      request_id: new_access_log_id(),
      transaction_id: new_access_log_id(),
      response_id: response.response_id,
      method,
      uri,
      request_version: parse_version(&fixture.request.version)?,
      request_headers,
      request_body: decode_body(
        fixture.request.body.as_deref(),
        fixture.request.body_base64.as_deref(),
      )?,
      request_body_truncated: fixture.request.body_truncated,
      peer_addr: fixture
        .request
        .peer_addr
        .parse()
        .with_context(|| format!("invalid peer_addr {}", fixture.request.peer_addr))?,
      downstream_host,
      downstream_scheme: fixture.request.downstream_scheme,
      tcp_max_hop: fixture.request.tcp_max_hop,
      tls: WafTlsMetadata {
        enabled: fixture.request.tls.enabled,
        version: fixture.request.tls.version,
        cipher_suite: fixture.request.tls.cipher_suite,
        sni: fixture.request.tls.sni,
        alpn: fixture.request.tls.alpn,
        fingerprint: fixture.request.tls.fingerprint,
        fingerprint_scheme: fixture.request.tls.fingerprint_scheme,
        client_certificate: None,
      },
      protocol: parse_protocol(&fixture.request.protocol)?,
      transport_network: parse_transport_network(&fixture.request.transport_network)?,
      tcp_mss: fixture.request.transport.tcp_mss,
      tcp_rtt_ms: fixture.request.transport.tcp_rtt_ms,
      udp_datagram_size: fixture.request.transport.udp_datagram_size,
      udp_connection_id: fixture.request.transport.udp_connection_id,
      tags: fixture.request.tags,
      dynamic_policy: DynamicPolicyContext {
        matched: fixture.request.dynamic_policy.matched,
        action: fixture.request.dynamic_policy.action,
        name: fixture.request.dynamic_policy.name,
        reason: fixture.request.dynamic_policy.reason,
        code: fixture.request.dynamic_policy.code,
        mode: fixture.request.dynamic_policy.mode,
        source: fixture.request.dynamic_policy.source,
      },
      response_version: parse_version(&response.version)?,
      response_status,
      response_headers: header_map(&response.headers)?,
      response_body: decode_body(response.body.as_deref(), response.body_base64.as_deref())?,
      response_body_truncated: response.body_truncated,
      upstream_name: response.upstream_name,
      upstream_pool: response.upstream_pool,
      upstream_scheme: response.upstream_scheme,
      upstream_connect_time_ms: response.upstream_connect_time_ms,
      upstream_first_byte_time_ms: response.upstream_first_byte_time_ms,
      upstream_error: response.upstream_error,
      stream_protocol: parse_stream_protocol(&stream.protocol)?,
      stream_direction: parse_stream_direction(&stream.direction)?,
      stream_unit: parse_stream_unit(&stream.unit)?,
      stream_payload,
      stream_payload_truncated: stream.payload_truncated,
      websocket_frame_payload_size: websocket.frame_payload_size.unwrap_or(stream_payload_len),
      websocket_opcode: websocket.opcode,
      websocket_fin: websocket.fin,
      websocket_is_control: websocket.is_control,
      websocket_message_opcode: websocket.message_opcode,
      webtransport_stream_kind: parse_optional_webtransport_kind(
        webtransport.stream_kind.as_deref(),
      )?,
      webtransport_stream_id: webtransport.stream_id,
      webtransport_datagram_size: webtransport.datagram_size,
    })
  }

  pub(super) fn phase(&self) -> WafPhase {
    self.phase
  }

  pub(super) fn route_name(&self) -> &str {
    &self.route_name
  }

  pub(super) fn request_input(&self) -> WafRequestInput<'_> {
    WafRequestInput {
      request_id: &self.request_id,
      transaction_id: &self.transaction_id,
      received_at_unix_ms: current_unix_ms(),
      method: &self.method,
      uri: &self.uri,
      version: self.request_version,
      headers: &self.request_headers,
      body: self.request_body.as_ref().map(|bytes| WafBodyInput {
        bytes,
        is_truncated: self.request_body_truncated,
      }),
      peer_addr: self.peer_addr,
      client_asn: None,
      downstream_host: &self.downstream_host,
      downstream_scheme: &self.downstream_scheme,
      route_name: &self.route_name,
      tcp_max_hop: self.tcp_max_hop,
      tls: &self.tls,
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

  pub(super) fn response_input(&self) -> WafResponseInput<'_> {
    WafResponseInput {
      request: self.request_input(),
      response_id: &self.response_id,
      received_at_unix_ms: current_unix_ms(),
      version: self.response_version,
      status: self.response_status,
      headers: &self.response_headers,
      body: self.response_body.as_ref().map(|bytes| WafBodyInput {
        bytes,
        is_truncated: self.response_body_truncated,
      }),
      upstream_name: &self.upstream_name,
      upstream_pool: self.upstream_pool.as_deref(),
      upstream_scheme: &self.upstream_scheme,
      upstream_connect_time_ms: self.upstream_connect_time_ms,
      upstream_first_byte_time_ms: self.upstream_first_byte_time_ms,
      upstream_error: self.upstream_error.as_ref().map(|error| WafUpstreamError {
        code: &error.code,
        message: &error.message,
      }),
    }
  }

  pub(super) fn stream_input(&self) -> WafStreamInput<'_> {
    WafStreamInput {
      request: self.request_input(),
      protocol: self.stream_protocol,
      direction: self.stream_direction,
      unit: self.stream_unit,
      payload: WafBodyInput {
        bytes: &self.stream_payload,
        is_truncated: self.stream_payload_truncated,
      },
      websocket: Some(WafWebSocketStreamMetadata {
        opcode: &self.websocket_opcode,
        fin: self.websocket_fin,
        is_control: self.websocket_is_control,
        message_opcode: self.websocket_message_opcode.as_deref(),
        frame_payload_size: self.websocket_frame_payload_size,
      }),
      webtransport: Some(WafWebTransportStreamMetadata {
        stream_kind: self.webtransport_stream_kind,
        stream_id: self.webtransport_stream_id,
        datagram_size: self.webtransport_datagram_size,
      }),
    }
  }
}

pub(super) fn fixture_from_access_log_value(value: serde_json::Value) -> OxiRuleFixture {
  let method = json_string(&value, "method").unwrap_or_else(default_method);
  let path = json_string(&value, "path").unwrap_or_else(default_uri);
  let status = value
    .get("status")
    .and_then(serde_json::Value::as_u64)
    .and_then(|status| u16::try_from(status).ok())
    .unwrap_or(default_status());
  OxiRuleFixture {
    phase: Some(WafPhase::Response),
    route: json_string(&value, "route"),
    request: OxiRuleRequestFixture {
      method,
      uri: path,
      ..OxiRuleRequestFixture::default()
    },
    response: Some(OxiRuleResponseFixture {
      status,
      ..OxiRuleResponseFixture::default()
    }),
    stream: None,
  }
}

fn header_map(input: &BTreeMap<String, HeaderInput>) -> anyhow::Result<HeaderMap> {
  let mut headers = HeaderMap::new();
  for (name, value) in input {
    let name = HeaderName::from_bytes(name.as_bytes())
      .with_context(|| format!("invalid header name {name}"))?;
    match value {
      HeaderInput::One(value) => {
        headers.append(name, header_value(value)?);
      }
      HeaderInput::Many(values) => {
        for value in values {
          headers.append(name.clone(), header_value(value)?);
        }
      }
    }
  }
  Ok(headers)
}

fn header_value(value: &str) -> anyhow::Result<HeaderValue> {
  HeaderValue::from_str(value).with_context(|| format!("invalid header value {value:?}"))
}

pub(super) fn header_value_to_string(value: &HeaderValue) -> String {
  value.to_str().unwrap_or("<non-utf8>").to_string()
}

fn decode_body(text: Option<&str>, base64_text: Option<&str>) -> anyhow::Result<Option<Vec<u8>>> {
  if text.is_some() && base64_text.is_some() {
    bail!("body and body_base64 are mutually exclusive");
  }
  if let Some(text) = text {
    return Ok(Some(text.as_bytes().to_vec()));
  }
  if let Some(base64_text) = base64_text {
    return Ok(Some(
      base64::engine::general_purpose::STANDARD
        .decode(base64_text)
        .context("failed to decode base64 body")?,
    ));
  }
  Ok(None)
}

fn parse_version(value: &str) -> anyhow::Result<Version> {
  match value.to_ascii_lowercase().as_str() {
    "http/0.9" | "http0.9" | "0.9" => Ok(Version::HTTP_09),
    "http/1.0" | "http1.0" | "1.0" => Ok(Version::HTTP_10),
    "http/1.1" | "http1.1" | "1.1" => Ok(Version::HTTP_11),
    "http/2" | "http2" | "h2" | "2" => Ok(Version::HTTP_2),
    "http/3" | "http3" | "h3" | "3" => Ok(Version::HTTP_3),
    _ => bail!("unsupported HTTP version {value}"),
  }
}

fn parse_protocol(value: &str) -> anyhow::Result<WafProtocol> {
  match value {
    "http" => Ok(WafProtocol::Http),
    "websocket" => Ok(WafProtocol::Websocket),
    "webrtc" => Ok(WafProtocol::Webrtc),
    "webtransport" => Ok(WafProtocol::Webtransport),
    _ => bail!("unsupported WAF protocol {value}"),
  }
}

fn parse_transport_network(value: &str) -> anyhow::Result<WafTransportNetwork> {
  match value {
    "tcp" => Ok(WafTransportNetwork::Tcp),
    "udp" => Ok(WafTransportNetwork::Udp),
    _ => bail!("unsupported transport network {value}"),
  }
}

fn parse_stream_protocol(value: &str) -> anyhow::Result<WafStreamProtocol> {
  match value {
    "websocket" => Ok(WafStreamProtocol::Websocket),
    "webtransport" => Ok(WafStreamProtocol::Webtransport),
    _ => bail!("unsupported stream protocol {value}"),
  }
}

fn parse_stream_direction(value: &str) -> anyhow::Result<WafStreamDirection> {
  match value {
    "downstream_to_upstream" => Ok(WafStreamDirection::DownstreamToUpstream),
    "upstream_to_downstream" => Ok(WafStreamDirection::UpstreamToDownstream),
    _ => bail!("unsupported stream direction {value}"),
  }
}

fn parse_stream_unit(value: &str) -> anyhow::Result<WafStreamUnit> {
  match value {
    "websocket_frame" => Ok(WafStreamUnit::WebsocketFrame),
    "websocket_message" => Ok(WafStreamUnit::WebsocketMessage),
    "webtransport_stream_chunk" => Ok(WafStreamUnit::WebtransportStreamChunk),
    "webtransport_datagram" => Ok(WafStreamUnit::WebtransportDatagram),
    _ => bail!("unsupported stream unit {value}"),
  }
}

fn parse_optional_webtransport_kind(
  value: Option<&str>,
) -> anyhow::Result<Option<WafWebTransportStreamKind>> {
  match value {
    None => Ok(None),
    Some("bidi") => Ok(Some(WafWebTransportStreamKind::Bidi)),
    Some("uni") => Ok(Some(WafWebTransportStreamKind::Uni)),
    Some(other) => bail!("unsupported WebTransport stream kind {other}"),
  }
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
  value
    .get(key)
    .and_then(serde_json::Value::as_str)
    .map(str::to_string)
}

fn default_stream_fixture() -> OxiRuleStreamFixture {
  OxiRuleStreamFixture {
    protocol: default_stream_protocol(),
    direction: default_stream_direction(),
    unit: default_stream_unit(),
    payload: Some(String::new()),
    payload_base64: None,
    payload_truncated: false,
    websocket: Some(default_websocket_fixture()),
    webtransport: None,
  }
}

fn default_websocket_fixture() -> OxiRuleWebSocketFixture {
  OxiRuleWebSocketFixture {
    opcode: default_ws_opcode(),
    fin: true,
    is_control: false,
    message_opcode: None,
    frame_payload_size: None,
  }
}
