//! Fixed, in-memory request-evaluation fixture for the security fuzz target.

use std::collections::HashMap;
use std::sync::OnceLock;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, Version};

use super::*;

const ATTACK: &str = "oxibelt_fuzz_attack";
const MAX_BODY_BYTES: usize = 8 * 1024;

pub(super) fn evaluate(
  path: &str,
  body: &[u8],
  header_value: &str,
  transform: u8,
  protocol: u8,
  body_coding: u8,
) {
  let Some(original_uri) = request_uri(path) else {
    return;
  };
  let path_or_header_is_malicious =
    original_uri.path().contains(ATTACK) || header_value.contains(ATTACK);
  let (path, body, header_value, meaning_preserving) =
    transform_request(path, body, header_value, transform);
  let decoded_body = match decode_body_for_inspection(&body, body_coding) {
    Ok(decoded) => decoded,
    Err(status) => {
      assert!(
        status.is_client_error() || status.is_server_error(),
        "production body-decoding failure did not classify as a rejecting response"
      );
      return;
    }
  };
  // Classify attacker-supplied compressed profiles from the same decoded
  // representation that the WAF evaluates. Compression metadata and trailing
  // bytes are not request-body semantics.
  let semantic_malicious = path_or_header_is_malicious
    || std::str::from_utf8(&decoded_body).is_ok_and(|value| value.contains(ATTACK));
  let mut headers = HeaderMap::new();
  if let Ok(value) = HeaderValue::from_str(&header_value) {
    headers.insert("x-fuzz-input", value);
  }
  let Some(uri) = request_uri(&path) else {
    return;
  };
  let method = Method::POST;
  let tls = WafTlsMetadata::default();
  let tags = HashMap::new();
  let dynamic_policy = DynamicPolicyContext::default();
  let input = WafRequestInput {
    request_id: "fuzz-request",
    transaction_id: "fuzz-transaction",
    received_at_unix_ms: 0,
    method: &method,
    uri: &uri,
    version: match protocol % 3 {
      0 => Version::HTTP_11,
      1 => Version::HTTP_2,
      _ => Version::HTTP_3,
    },
    headers: &headers,
    body: Some(WafBodyInput {
      bytes: &decoded_body,
      is_truncated: false,
    }),
    peer_addr: std::net::SocketAddr::from(([203, 0, 113, 7], 44321)),
    client_asn: None,
    downstream_host: "fuzz.example.test",
    downstream_scheme: "https",
    route_name: "app-root",
    tcp_max_hop: None,
    tls: &tls,
    protocol: WafProtocol::Http,
    transport_network: WafTransportNetwork::Tcp,
    transport_metadata: WafTransportMetadataInput::default(),
    tags: &tags,
    dynamic_policy: &dynamic_policy,
  };
  let decision = engine().evaluate_request(input);
  if semantic_malicious && meaning_preserving {
    assert!(
      decision.terminal.is_some(),
      "a meaning-preserving malicious request became allowed"
    );
  }

  // Re-evaluating the same immutable request must yield the same allow/block
  // class. Rule hit counters are intentionally excluded from this comparison.
  let repeated = engine().evaluate_request(input);
  assert_eq!(
    decision.terminal.is_some(),
    repeated.terminal.is_some(),
    "WAF action resolution was nondeterministic"
  );
}

#[allow(
  clippy::expect_used,
  reason = "fixed compile-time fuzz configuration must be valid for this target to run"
)]
fn engine() -> &'static WafEngine {
  static ENGINE: OnceLock<WafEngine> = OnceLock::new();
  ENGINE.get_or_init(|| {
    let mut config: Config = toml::from_str(include_str!("../../config/oxibelt.toml"))
      .expect("embedded OxiBelt example configuration should parse");
    config.waf = toml::from_str(
      r#"
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[rules]]
name = "block-fuzz-security-attack"
phase = "request"
priority = 10
when = "Request.Normalized.Http.Path.contains('oxibelt_fuzz_attack') || Request.Body.contains('oxibelt_fuzz_attack') || Request.Headers.anyValueContains('oxibelt_fuzz_attack')"

[[rules.actions]]
type = "reject"
status = 403
"#,
    )
    .expect("fixed in-memory WAF fuzz rules should parse");
    WafEngine::new(&config).expect("fixed in-memory WAF fuzz rules should compile")
  })
}

fn request_uri(path: &str) -> Option<Uri> {
  let path = if path.starts_with('/') { path } else { "/" };
  path.parse().ok()
}

fn transform_request(
  path: &str,
  body: &[u8],
  header_value: &str,
  transform: u8,
) -> (String, Vec<u8>, String, bool) {
  let mut path = path.to_string();
  let mut body = body[..body.len().min(MAX_BODY_BYTES)].to_vec();
  let mut header_value = header_value.to_string();
  let meaning_preserving = transform % 5 != 4;
  match transform % 5 {
    0 => {}
    1 => {
      path = path.replace(ATTACK, "oxibelt%5ffuzz%5fattack");
    }
    2 => {
      body = String::from_utf8_lossy(&body)
        .replace(ATTACK, "oxibelt_fuzz_attack")
        .into_bytes();
    }
    3 => {
      header_value = header_value.replace(ATTACK, "oxibelt_fuzz_attack");
    }
    _ => body.reverse(),
  }
  (path, body, header_value, meaning_preserving)
}

fn decode_body_for_inspection(body: &[u8], body_coding: u8) -> Result<Vec<u8>, StatusCode> {
  let profile = body_coding % 9;
  if profile == 0 {
    return Ok(body.to_vec());
  }
  let encoding = match (profile - 1) % 4 {
    0 => WafHttpBodyEncoding::Gzip,
    1 => WafHttpBodyEncoding::Deflate,
    2 => WafHttpBodyEncoding::Br,
    _ => WafHttpBodyEncoding::Zstd,
  };
  let encoded = if profile <= 4 {
    crate::proxy::http::waf_body_coding::fuzz_encode_body(Bytes::copy_from_slice(body), encoding)?
  } else {
    Bytes::copy_from_slice(body)
  };
  crate::proxy::http::waf_body_coding::fuzz_decode_body(encoded, encoding)
    .map(|decoded| decoded.to_vec())
}
