use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use bytes::BytesMut;
use h3::ext::Protocol;
use http::header::{CONNECTION, HOST, TE, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request};
use md5::{Digest, Md5};
use url::Url;

mod admin;
mod parsers;

pub use admin::{
  exercise_admin_json_mutations, exercise_admin_mutation_envelope, exercise_cluster_rollout_state,
};
pub use parsers::{
  exercise_cache_metadata_key, exercise_http_body_coding, exercise_native_config,
  exercise_oxirule_expression, exercise_tls_certificate_metadata,
};

use crate::config::{
  ForwardedHeaderMode, HttpVersion, SniForwardClientHelloParseMethod, TurnAuthConfig, TurnAuthMode,
  TurnStaticCredentialConfig,
};
use crate::proxy::http::headers::{
  add_forwarded_headers, extract_downstream_port, extract_host, is_upgrade_request,
  set_effective_host_header, strip_hop_by_hop_headers, validate_authority_host_consistency,
};
use crate::proxy::http::uri::{UpstreamUriParts, rewrite_uri, validate_downstream_path};
use crate::proxy::http::version::select_upstream_http_version;
use crate::turn::protocol::{
  ALLOCATE_REQUEST, ATTR_DATA, ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME,
  CHANNEL_BIND_REQUEST, CREATE_PERMISSION_REQUEST, DATA_INDICATION, SEND_INDICATION, attr_string,
  encode_channel_data, encode_message, encode_success, parse_channel_data, parse_stun,
  verify_fingerprint, verify_message_integrity, with_message_integrity,
};

const MAX_RAW_BYTES: usize = 4096;
const MAX_TOKEN_BYTES: usize = 64;
const TURN_REALM: &str = "fuzz.example.test";
const TURN_USER: &str = "fuzz-user";
const TURN_PASSWORD: &str = "fuzz-password";

pub fn exercise_tls_client_hello(data: &[u8]) {
  let data = bounded(data);
  let _ = crate::sni_forward::client_hello::tls_record_client_hello_sni(
    data,
    &[SniForwardClientHelloParseMethod::SingleRecord],
  );
  let _ = crate::sni_forward::client_hello::tls_record_client_hello_sni(
    data,
    &[
      SniForwardClientHelloParseMethod::SingleRecord,
      SniForwardClientHelloParseMethod::TlsRecordReassembly,
    ],
  );
  let _ = crate::sni_forward::client_hello::raw_client_hello_sni(data);
}

pub fn exercise_syscall_boundaries(data: &[u8]) {
  let data = bounded(data);
  let mut input = FuzzInput::new(data);
  let port = input.u16();
  let address = if input.bool() {
    SocketAddr::from((
      Ipv4Addr::new(input.byte(), input.byte(), input.byte(), input.byte()),
      port,
    ))
  } else {
    let mut octets = [0_u8; 16];
    for octet in &mut octets {
      *octet = input.byte();
    }
    SocketAddr::from((Ipv6Addr::from(octets), port))
  };
  crate::stream::fuzz_socket_address_boundary(address, input.usize(33).saturating_add(1));
  crate::hardening::fuzz_syscall_boundary(input.byte());
  crate::tcp_hop::fuzz_syscall_boundary(input.bool());
  let _ = i64::try_from(input.u64());
}

pub fn exercise_http_semantics(data: &[u8]) {
  let data = bounded(data);
  let mut input = FuzzInput::new(data);
  let mut headers = header_map(&mut input);
  let uri = input.http_uri();
  let method = input.http_method();

  if let Ok(request) = Request::builder().method(method).uri(uri.as_str()).body(()) {
    let _ = extract_host(&request);
    let _ = extract_downstream_port(&request, input.scheme());
    let _ = validate_authority_host_consistency(&request);
    let _ = is_upgrade_request(&request);
    let _ = validate_downstream_path(request.uri().path());

    if let Ok(origin) = UpstreamUriParts::from_url(&input.upstream_origin()) {
      let _ = rewrite_uri(
        &origin,
        input.route_prefix(),
        input.replacement_prefix(),
        request.uri(),
      );
    }
  }

  strip_hop_by_hop_headers(&mut headers);
  set_effective_host_header(&mut headers, input.host().as_str());
  add_forwarded_headers(
    &mut headers,
    SocketAddr::from((Ipv4Addr::new(203, 0, 113, input.byte()), 5443)),
    input.host().as_str(),
    "https",
    input.u16(),
    if input.bool() {
      ForwardedHeaderMode::Append
    } else {
      ForwardedHeaderMode::Overwrite
    },
    None,
  );

  let _ = select_upstream_http_version(input.bool(), input.http_version(), input.http_version());
}

pub fn exercise_compio_h1_response(
  response: &[u8],
  fragment_sizes: &[u8],
  limit_selectors: [u8; 9],
) {
  use crate::proxy::http::fast_path::direct_h1::response_protocol::{
    ResponseProtocolEngine, ResponseProtocolLimits, ResponseState,
  };

  const MAX_RESPONSE_BYTES: usize = 128 * 1024;
  let response = &response[..response.len().min(MAX_RESPONSE_BYTES)];
  let limits = ResponseProtocolLimits::from_selectors(limit_selectors);
  let expected_metadata_bound = limits
    .max_response_head_bytes
    .max(limits.max_chunk_size_line_bytes.saturating_add(2))
    .max(limits.max_trailer_block_bytes);
  let Ok(mut engine) = ResponseProtocolEngine::new(Method::GET, limits) else {
    panic!("normalized fuzz limits must validate");
  };
  assert_eq!(
    engine.max_buffered_metadata_bytes(),
    expected_metadata_bound
  );

  let mut input = BytesMut::new();
  let mut offset = 0usize;
  let mut fragment_index = 0usize;
  let mut completed = false;
  while offset < response.len() && !completed {
    let selected = fragment_sizes
      .get(fragment_index % fragment_sizes.len().max(1))
      .copied()
      .unwrap_or(1);
    fragment_index = fragment_index.saturating_add(1);
    let fragment_len = usize::from(selected).saturating_add(1);
    let end = offset.saturating_add(fragment_len).min(response.len());
    input.extend_from_slice(&response[offset..end]);
    offset = end;
    completed = drain_compio_response_events(&mut engine, &mut input, false);
  }
  if !completed {
    let _ = drain_compio_response_events(&mut engine, &mut input, true);
  }

  if engine.state() == ResponseState::FailedNonReusable {
    let Err(first) = engine.decode(&mut input, true) else {
      panic!("failed parser must preserve its terminal error");
    };
    let Err(repeated) = engine.decode(&mut input, true) else {
      panic!("failed parser must remain failed");
    };
    assert_eq!(first, repeated);
  }
}

fn drain_compio_response_events(
  engine: &mut crate::proxy::http::fast_path::direct_h1::response_protocol::ResponseProtocolEngine,
  input: &mut BytesMut,
  eof: bool,
) -> bool {
  use crate::proxy::http::fast_path::direct_h1::response_protocol::{ResponseEvent, ResponseStep};

  loop {
    match engine.decode(input, eof) {
      Ok(ResponseStep::Event(ResponseEvent::Complete)) => return true,
      Ok(ResponseStep::Event(_)) => {}
      Ok(ResponseStep::NeedInput) => {
        assert!(
          engine.buffered_metadata_bytes(input) <= engine.max_buffered_metadata_bytes(),
          "incremental response metadata exceeded the validated engine bound"
        );
        return false;
      }
      Err(_) => return false,
    }
  }
}

pub fn exercise_http3_webtransport(data: &[u8]) {
  let data = bounded(data);
  let mut input = FuzzInput::new(data);
  let mut headers = header_map(&mut input);
  let protocol_value_len = input.usize(MAX_TOKEN_BYTES + 1);
  let protocol_value = input.bytes(protocol_value_len);
  insert_header_bytes(
    &mut headers,
    HeaderName::from_static("wt-available-protocols"),
    protocol_value.as_slice(),
  );
  let _ = crate::proxy::http::webtransport::parse_webtransport_protocols(&headers);

  if let Ok(mut request) = Request::builder()
    .method(input.http_method())
    .uri(input.http_uri())
    .body(())
  {
    if input.bool() {
      request.extensions_mut().insert(Protocol::WEB_TRANSPORT);
    }
    let _ = crate::proxy::http3::is_webtransport_request(&request);
    let _ =
      crate::proxy::http3::rejects_unsafe_early_data(&request, input.zero_rtt_mode(), input.bool());
  }
}

pub fn exercise_websocket_frame(data: &[u8]) {
  let data = bounded(data);
  let mut input = FuzzInput::new(data);
  let limit = input.usize(2048).saturating_add(1);
  let generated = websocket_frame(&mut input);
  let generated_sequence = (0..input.usize(8).saturating_add(1))
    .flat_map(|_| websocket_frame(&mut input))
    .collect::<Vec<_>>();
  let runtime = websocket_runtime();
  runtime.block_on(async {
    crate::proxy::stream_waf::fuzz_websocket_frame(data, limit).await;
    crate::proxy::stream_waf::fuzz_websocket_frame(&generated, limit).await;
    crate::proxy::stream_waf::fuzz_websocket_frame(&generated_sequence, limit).await;
  });
}

pub fn exercise_webrtc_turn(data: &[u8]) {
  let data = bounded(data);
  let mut input = FuzzInput::new(data);
  let auth = turn_auth(input.turn_auth_mode(), input.u16().max(1) as u64);
  exercise_turn_packet(data, &auth);

  let transaction_id = input.transaction_id();
  let mut attrs = vec![
    (ATTR_USERNAME, TURN_USER.as_bytes().to_vec()),
    (ATTR_REALM, TURN_REALM.as_bytes().to_vec()),
  ];
  if let Some(nonce) = crate::turn::fuzzing::create_nonce(&auth, TURN_REALM) {
    attrs.push((ATTR_NONCE, nonce.into_bytes()));
  }
  if input.bool() {
    let data_len = input.usize(128);
    attrs.push((ATTR_DATA, input.bytes(data_len)));
  }
  let message_type = input.turn_message_type();
  let key = turn_long_term_key();
  let message = with_message_integrity(encode_message(message_type, transaction_id, &attrs), &key);
  exercise_turn_packet(&message, &auth);

  let bad_integrity = encode_message(
    message_type,
    transaction_id,
    &[
      (ATTR_USERNAME, TURN_USER.as_bytes().to_vec()),
      (ATTR_REALM, TURN_REALM.as_bytes().to_vec()),
      (ATTR_MESSAGE_INTEGRITY, input.bytes(20)),
    ],
  );
  exercise_turn_packet(&bad_integrity, &auth);

  let payload_len = input.usize(256);
  let payload = input.bytes(payload_len);
  let channel = 0x4000 | (input.u16() & 0x3fff);
  let channel_data = encode_channel_data(channel, &payload);
  let _ = parse_channel_data(&channel_data);
}

fn exercise_turn_packet(packet: &[u8], auth: &TurnAuthConfig) {
  if let Ok(message) = parse_stun(packet) {
    crate::turn::fuzzing::exercise_auth(auth, TURN_REALM, &message);
    let _ = verify_fingerprint(&message);
    let _ = verify_message_integrity(&message, &turn_long_term_key());
    let _ = attr_string(&message, ATTR_USERNAME);
    let _ = attr_string(&message, ATTR_REALM);
    let _ = attr_string(&message, ATTR_NONCE);
    let _ = encode_success(message.message_type, message.transaction_id, &[]);
  }
  let _ = parse_channel_data(packet);
}

fn bounded(data: &[u8]) -> &[u8] {
  &data[..data.len().min(MAX_RAW_BYTES)]
}

fn header_map(input: &mut FuzzInput<'_>) -> HeaderMap {
  let mut headers = HeaderMap::new();
  for name in [
    HOST,
    CONNECTION,
    UPGRADE,
    TE,
    HeaderName::from_static("x-forwarded-for"),
    HeaderName::from_static("x-forwarded-host"),
    HeaderName::from_static("x-hop"),
  ] {
    let value_len = input.usize(MAX_TOKEN_BYTES + 1);
    let value = input.bytes(value_len);
    insert_header_bytes(&mut headers, name, &value);
  }
  headers
}

fn insert_header_bytes(headers: &mut HeaderMap, name: HeaderName, value: &[u8]) {
  if let Ok(value) = HeaderValue::from_bytes(value) {
    headers.insert(name, value);
  }
}

#[allow(
  clippy::expect_used,
  reason = "the fuzz-only runtime cannot continue if its local executor cannot initialize"
)]
fn websocket_runtime() -> &'static tokio::runtime::Runtime {
  static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
  RUNTIME.get_or_init(|| {
    tokio::runtime::Builder::new_current_thread()
      .enable_io()
      .enable_time()
      .build()
      .expect("fuzzing runtime should build")
  })
}

fn websocket_frame(input: &mut FuzzInput<'_>) -> Vec<u8> {
  let payload_len = input.usize(256);
  let payload = input.bytes(payload_len);
  let opcode = match input.byte() % 6 {
    0 => 0x1,
    1 => 0x2,
    2 => 0x0,
    3 => 0x8,
    4 => 0x9,
    _ => 0xa,
  };
  let mut out = Vec::with_capacity(payload.len() + 16);
  let fin = if input.bool() { 0x80 } else { 0x00 };
  out.push(fin | opcode);
  if payload.len() < 126 {
    out.push(0x80 | payload.len() as u8);
  } else {
    out.push(0x80 | 126);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  }
  let mask = [input.byte(), input.byte(), input.byte(), input.byte()];
  out.extend_from_slice(&mask);
  out.extend(
    payload
      .iter()
      .enumerate()
      .map(|(index, byte)| byte ^ mask[index % mask.len()]),
  );
  out
}

fn turn_auth(mode: TurnAuthMode, nonce_ttl_seconds: u64) -> TurnAuthConfig {
  TurnAuthConfig {
    mode,
    static_credentials: vec![TurnStaticCredentialConfig {
      username: TURN_USER.to_string(),
      password: Some(TURN_PASSWORD.to_string()),
      password_env: None,
    }],
    rest_shared_secret: Some("fuzz-rest-secret".to_string()),
    rest_shared_secret_env: None,
    nonce_ttl_seconds,
  }
}

fn turn_long_term_key() -> [u8; 16] {
  let value = format!("{TURN_USER}:{TURN_REALM}:{TURN_PASSWORD}");
  let mut digest = Md5::new();
  digest.update(value.as_bytes());
  digest.finalize().into()
}

struct FuzzInput<'a> {
  data: &'a [u8],
  offset: usize,
}

impl<'a> FuzzInput<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self { data, offset: 0 }
  }

  fn byte(&mut self) -> u8 {
    if self.data.is_empty() {
      return 0;
    }
    let byte = self.data[self.offset % self.data.len()];
    self.offset = self.offset.wrapping_add(1);
    byte
  }

  fn bool(&mut self) -> bool {
    self.byte() & 1 == 1
  }

  fn u16(&mut self) -> u16 {
    u16::from_be_bytes([self.byte(), self.byte()])
  }

  fn u64(&mut self) -> u64 {
    u64::from_be_bytes([
      self.byte(),
      self.byte(),
      self.byte(),
      self.byte(),
      self.byte(),
      self.byte(),
      self.byte(),
      self.byte(),
    ])
  }

  fn usize(&mut self, modulo: usize) -> usize {
    if modulo == 0 {
      0
    } else {
      ((self.u16() as usize) ^ (self.byte() as usize)) % modulo
    }
  }

  fn bytes(&mut self, len: usize) -> Vec<u8> {
    (0..len).map(|_| self.byte()).collect()
  }

  fn token(&mut self, max: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_";
    let len = self.usize(max + 1);
    (0..len)
      .map(|_| ALPHABET[self.usize(ALPHABET.len())] as char)
      .collect()
  }

  fn host(&mut self) -> String {
    match self.byte() % 5 {
      0 => "example.test".to_string(),
      1 => "Example.Test:8443".to_string(),
      2 => "bad host".to_string(),
      3 => String::new(),
      _ => format!("{}.example.test", self.token(16)),
    }
  }

  fn http_uri(&mut self) -> String {
    match self.byte() % 8 {
      0 => "/".to_string(),
      1 => format!("/app/{}?q={}", self.token(16), self.token(16)),
      2 => "/safe/../admin".to_string(),
      3 => "/safe/%2e%2e/admin".to_string(),
      4 => format!("https://{}:8443/app/{}", self.host(), self.token(16)),
      5 => format!("http://absolute.example/{}", self.token(16)),
      6 => "*".to_string(),
      _ => self.token(32),
    }
  }

  #[allow(
    clippy::expect_used,
    reason = "the fuzz harness selects only fixed syntactically valid URL literals"
  )]
  fn upstream_origin(&mut self) -> Url {
    Url::parse(match self.byte() % 4 {
      0 => "https://upstream.internal/base",
      1 => "http://backend.internal/",
      2 => "https://backend.internal:8443/root/",
      _ => "https://backend.internal",
    })
    .expect("static URL should parse")
  }

  fn route_prefix(&mut self) -> &'static str {
    match self.byte() % 4 {
      0 => "/",
      1 => "/app",
      2 => "/safe",
      _ => "/api",
    }
  }

  fn replacement_prefix(&mut self) -> Option<&'static str> {
    match self.byte() % 4 {
      0 => None,
      1 => Some("/"),
      2 => Some("/edge"),
      _ => Some("/internal/v1"),
    }
  }

  fn scheme(&mut self) -> &'static str {
    if self.bool() { "https" } else { "http" }
  }

  fn http_method(&mut self) -> Method {
    match self.byte() % 6 {
      0 => Method::GET,
      1 => Method::POST,
      2 => Method::CONNECT,
      3 => Method::HEAD,
      4 => Method::PUT,
      _ => Method::OPTIONS,
    }
  }

  fn http_version(&mut self) -> HttpVersion {
    match self.byte() % 3 {
      0 => HttpVersion::H1,
      1 => HttpVersion::H2,
      _ => HttpVersion::H3,
    }
  }

  fn zero_rtt_mode(&mut self) -> crate::config::QuicZeroRttMode {
    if self.bool() {
      crate::config::QuicZeroRttMode::SafeMethods
    } else {
      crate::config::QuicZeroRttMode::Off
    }
  }

  fn turn_auth_mode(&mut self) -> TurnAuthMode {
    match self.byte() % 3 {
      0 => TurnAuthMode::PassThrough,
      1 => TurnAuthMode::Validate,
      _ => TurnAuthMode::Enforce,
    }
  }

  fn turn_message_type(&mut self) -> u16 {
    match self.byte() % 5 {
      0 => ALLOCATE_REQUEST,
      1 => CREATE_PERMISSION_REQUEST,
      2 => CHANNEL_BIND_REQUEST,
      3 => SEND_INDICATION,
      _ => DATA_INDICATION,
    }
  }

  fn transaction_id(&mut self) -> [u8; 12] {
    let mut transaction_id = [0u8; 12];
    for byte in &mut transaction_id {
      *byte = self.byte();
    }
    transaction_id
  }
}
