//! RFC 7692 outbound permessage-deflate for Admin operation WebSockets.

use ::http::HeaderMap;
use flate2::{Compress, Compression, FlushCompress};
use tokio::sync::OwnedSemaphorePermit;

pub(super) const RESPONSE_EXTENSION: &str = "permessage-deflate; server_no_context_takeover";

const MAX_EXTENSION_HEADER_BYTES: usize = 4096;
const MAX_EXTENSION_HEADER_VALUES: usize = 8;

/// Caller-owned enablement, level, and admission-capacity decisions.
///
/// A negotiated compressor retains `capacity` until the upgraded socket exits.
pub(super) struct WebSocketCompressionSettings {
  pub enabled: bool,
  pub level: u8,
  pub capacity: Option<OwnedSemaphorePermit>,
}

impl WebSocketCompressionSettings {
  pub const DISABLED: Self = Self {
    enabled: false,
    level: 0,
    capacity: None,
  };

  pub fn new(enabled: bool, level: u8, capacity: Option<OwnedSemaphorePermit>) -> Option<Self> {
    if !enabled {
      return Some(Self::DISABLED);
    }
    if !(1..=9).contains(&level) {
      return None;
    }
    Some(Self {
      enabled,
      level,
      capacity,
    })
  }
}

pub(super) struct PerMessageDeflate {
  level: u8,
  _capacity: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WebSocketExtensionError {
  Malformed,
  TooLarge,
}

/// Negotiates the bounded no-context-takeover profile used by Admin events.
/// Unsupported but well-formed offers are declined; malformed permessage-
/// deflate syntax is rejected.
pub(super) fn negotiate_permessage_deflate(
  headers: &HeaderMap,
  settings: WebSocketCompressionSettings,
) -> Result<Option<PerMessageDeflate>, WebSocketExtensionError> {
  if !settings.enabled {
    return Ok(None);
  }
  let Some(capacity) = settings.capacity else {
    return Ok(None);
  };

  let values = headers.get_all("sec-websocket-extensions");
  if values.iter().count() > MAX_EXTENSION_HEADER_VALUES {
    return Err(WebSocketExtensionError::TooLarge);
  }
  let mut total_bytes = 0usize;
  let mut offers = Vec::new();
  for value in values.iter() {
    let value = value
      .to_str()
      .map_err(|_| WebSocketExtensionError::Malformed)?;
    total_bytes = total_bytes
      .checked_add(value.len())
      .ok_or(WebSocketExtensionError::TooLarge)?;
    if total_bytes > MAX_EXTENSION_HEADER_BYTES {
      return Err(WebSocketExtensionError::TooLarge);
    }
    match parse_extensions(value) {
      Ok(mut parsed) => offers.append(&mut parsed),
      // A malformed unrelated extension is not a reason to reject an otherwise
      // valid WebSocket upgrade; simply decline compression for this request.
      Err(ParseExtensionError::UnrelatedMalformed) => return Ok(None),
      Err(ParseExtensionError::PerMessageDeflateMalformed) => {
        return Err(WebSocketExtensionError::Malformed);
      }
    }
  }

  for offer in offers {
    if offer.name.eq_ignore_ascii_case("permessage-deflate") && offer.is_compatible() {
      return Ok(Some(PerMessageDeflate {
        level: settings.level,
        _capacity: capacity,
      }));
    }
  }
  Ok(None)
}

impl PerMessageDeflate {
  /// Compresses one complete WebSocket text message with raw DEFLATE and
  /// removes RFC 7692's trailing sync-flush marker.
  pub(super) fn compress(&self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut compressor = Compress::new(Compression::new(self.level.into()), false);
    let mut output = Vec::with_capacity(payload.len().saturating_add(64));
    let mut input_offset = 0usize;
    loop {
      let mut encoded = [0u8; 16 * 1024];
      let input_before = compressor.total_in();
      let output_before = compressor.total_out();
      compressor
        .compress(&payload[input_offset..], &mut encoded, FlushCompress::Sync)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
      let consumed = usize::try_from(compressor.total_in() - input_before)
        .map_err(|_| std::io::Error::other("compressed WebSocket input length overflow"))?;
      let produced = usize::try_from(compressor.total_out() - output_before)
        .map_err(|_| std::io::Error::other("compressed WebSocket output length overflow"))?;
      input_offset = input_offset
        .checked_add(consumed)
        .ok_or_else(|| std::io::Error::other("compressed WebSocket input length overflow"))?;
      output.extend_from_slice(&encoded[..produced]);
      if input_offset == payload.len() && output.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
        break;
      }
      if consumed == 0 && produced == 0 {
        return Err(std::io::Error::other(
          "raw DEFLATE compressor made no progress",
        ));
      }
    }
    if output.len() < 4 || !output.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
      return Err(std::io::Error::other(
        "raw DEFLATE compressor did not produce a sync-flush marker",
      ));
    }
    output.truncate(output.len() - 4);
    Ok(output)
  }
}

#[derive(Debug)]
struct ExtensionOffer<'a> {
  name: &'a str,
  parameters: Vec<ExtensionParameter<'a>>,
}

impl ExtensionOffer<'_> {
  fn is_compatible(&self) -> bool {
    for (index, parameter) in self.parameters.iter().enumerate() {
      if parameter
        .name
        .eq_ignore_ascii_case("server_no_context_takeover")
      {
        if parameter.value.is_some()
          || self.parameters[..index].iter().any(|previous| {
            previous
              .name
              .eq_ignore_ascii_case("server_no_context_takeover")
          })
        {
          return false;
        }
      } else if parameter
        .name
        .eq_ignore_ascii_case("client_no_context_takeover")
      {
        if parameter.value.is_some()
          || self.parameters[..index].iter().any(|previous| {
            previous
              .name
              .eq_ignore_ascii_case("client_no_context_takeover")
          })
        {
          return false;
        }
      } else {
        return false;
      }
    }
    // RFC 7692 permits a server to select server_no_context_takeover even when
    // the client did not explicitly offer it. This implementation always uses
    // a fresh compressor, so that is the only server profile it advertises.
    true
  }
}

#[derive(Debug)]
struct ExtensionParameter<'a> {
  name: &'a str,
  value: Option<&'a str>,
}

#[derive(Debug, Eq, PartialEq)]
enum ParseExtensionError {
  UnrelatedMalformed,
  PerMessageDeflateMalformed,
}

fn parse_extensions(value: &str) -> Result<Vec<ExtensionOffer<'_>>, ParseExtensionError> {
  let mut parser = ExtensionParser::new(value);
  let mut offers = Vec::new();
  loop {
    parser.skip_ows();
    if parser.is_end() {
      return if offers.is_empty() {
        Err(ParseExtensionError::UnrelatedMalformed)
      } else {
        Ok(offers)
      };
    }
    let name = match parser.token() {
      Some(name) => name,
      None => return Err(ParseExtensionError::UnrelatedMalformed),
    };
    let permessage_deflate = name.eq_ignore_ascii_case("permessage-deflate");
    let mut parameters = Vec::new();
    loop {
      parser.skip_ows();
      if parser.consume(b';') {
        parser.skip_ows();
        let Some(parameter_name) = parser.token() else {
          return Err(parser.error_for(permessage_deflate));
        };
        parser.skip_ows();
        let parameter_value = if parser.consume(b'=') {
          parser.skip_ows();
          match parser.parameter_value() {
            Some(parameter_value) => Some(parameter_value),
            None => return Err(parser.error_for(permessage_deflate)),
          }
        } else {
          None
        };
        parameters.push(ExtensionParameter {
          name: parameter_name,
          value: parameter_value,
        });
        continue;
      }
      if parser.is_end() {
        offers.push(ExtensionOffer { name, parameters });
        return Ok(offers);
      }
      if parser.consume(b',') {
        offers.push(ExtensionOffer { name, parameters });
        parser.skip_ows();
        if parser.is_end() {
          return Err(parser.error_for(permessage_deflate));
        }
        break;
      }
      return Err(parser.error_for(permessage_deflate));
    }
  }
}

struct ExtensionParser<'a> {
  value: &'a str,
  position: usize,
}

impl<'a> ExtensionParser<'a> {
  const fn new(value: &'a str) -> Self {
    Self { value, position: 0 }
  }

  fn is_end(&self) -> bool {
    self.position == self.value.len()
  }

  fn skip_ows(&mut self) {
    while matches!(self.value.as_bytes().get(self.position), Some(b' ' | b'\t')) {
      self.position += 1;
    }
  }

  fn consume(&mut self, expected: u8) -> bool {
    if self.value.as_bytes().get(self.position) == Some(&expected) {
      self.position += 1;
      true
    } else {
      false
    }
  }

  fn token(&mut self) -> Option<&'a str> {
    let start = self.position;
    while self
      .value
      .as_bytes()
      .get(self.position)
      .is_some_and(|byte| is_token_byte(*byte))
    {
      self.position += 1;
    }
    (self.position > start).then_some(&self.value[start..self.position])
  }

  fn parameter_value(&mut self) -> Option<&'a str> {
    if self.consume(b'\"') {
      let start = self.position;
      let mut escaped = false;
      while let Some(byte) = self.value.as_bytes().get(self.position) {
        self.position += 1;
        if escaped {
          if !matches!(byte, 0x20..=0x7e | b'\t') {
            return None;
          }
          escaped = false;
        } else if *byte == b'\\' {
          escaped = true;
        } else if *byte == b'\"' {
          return Some(&self.value[start..self.position - 1]);
        } else if !matches!(byte, 0x20..=0x7e | b'\t') {
          return None;
        }
      }
      None
    } else {
      self.token()
    }
  }

  fn error_for(&self, permessage_deflate: bool) -> ParseExtensionError {
    if permessage_deflate {
      ParseExtensionError::PerMessageDeflateMalformed
    } else {
      ParseExtensionError::UnrelatedMalformed
    }
  }
}

fn is_token_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric()
    || matches!(
      byte,
      b'!'
        | b'#'
        | b'$'
        | b'%'
        | b'&'
        | b'\''
        | b'*'
        | b'+'
        | b'-'
        | b'.'
        | b'^'
        | b'_'
        | b'`'
        | b'|'
        | b'~'
    )
}

#[cfg(test)]
mod tests {
  use super::*;
  use flate2::{Decompress, FlushDecompress};
  use tokio::sync::Semaphore;

  fn compression_settings() -> WebSocketCompressionSettings {
    let permit = std::sync::Arc::new(Semaphore::new(1))
      .try_acquire_owned()
      .unwrap();
    WebSocketCompressionSettings::new(true, 6, Some(permit)).unwrap()
  }

  #[test]
  fn permessage_deflate_requires_compatible_bounded_offer() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "sec-websocket-extensions",
      "x-example, permessage-deflate; server_no_context_takeover"
        .parse()
        .unwrap(),
    );
    assert!(
      negotiate_permessage_deflate(&headers, compression_settings())
        .unwrap()
        .is_some()
    );
    assert_eq!(
      RESPONSE_EXTENSION,
      "permessage-deflate; server_no_context_takeover"
    );

    for offer in [
      "permessage-deflate; server_max_window_bits=12; server_no_context_takeover",
      "permessage-deflate; server_no_context_takeover; unknown_parameter",
      "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
    ] {
      headers.insert("sec-websocket-extensions", offer.parse().unwrap());
      assert!(
        negotiate_permessage_deflate(&headers, compression_settings())
          .unwrap()
          .is_none(),
        "offer should be declined: {offer}",
      );
    }

    headers.insert(
      "sec-websocket-extensions",
      "permessage-deflate".parse().unwrap(),
    );
    assert!(
      negotiate_permessage_deflate(&headers, compression_settings())
        .unwrap()
        .is_some()
    );
  }

  #[test]
  fn permessage_deflate_rejects_relevant_malformed_syntax_but_not_disabled_mode() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "sec-websocket-extensions",
      "permessage-deflate; =server_no_context_takeover"
        .parse()
        .unwrap(),
    );
    assert_eq!(
      negotiate_permessage_deflate(&headers, compression_settings()).map(|_| ()),
      Err(WebSocketExtensionError::Malformed)
    );
    assert!(
      negotiate_permessage_deflate(&headers, WebSocketCompressionSettings::DISABLED)
        .unwrap()
        .is_none()
    );
  }

  #[test]
  fn negotiated_compression_retains_caller_capacity_until_socket_completion() {
    let capacity = std::sync::Arc::new(Semaphore::new(1));
    let permit = capacity.clone().try_acquire_owned().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
      "sec-websocket-extensions",
      "permessage-deflate".parse().unwrap(),
    );
    let compression = negotiate_permessage_deflate(
      &headers,
      WebSocketCompressionSettings::new(true, 6, Some(permit)).unwrap(),
    )
    .unwrap()
    .unwrap();
    assert!(capacity.clone().try_acquire_owned().is_err());
    drop(compression);
    assert!(capacity.try_acquire_owned().is_ok());
  }

  #[test]
  fn incompatible_offer_releases_caller_capacity_before_the_handshake() {
    let capacity = std::sync::Arc::new(Semaphore::new(1));
    let permit = capacity.clone().try_acquire_owned().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
      "sec-websocket-extensions",
      "permessage-deflate; server_max_window_bits=12"
        .parse()
        .unwrap(),
    );
    assert!(
      negotiate_permessage_deflate(
        &headers,
        WebSocketCompressionSettings::new(true, 6, Some(permit)).unwrap(),
      )
      .unwrap()
      .is_none()
    );
    assert!(capacity.try_acquire_owned().is_ok());
  }

  #[test]
  fn compressed_payloads_use_raw_deflate_sync_flush_without_the_marker() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "sec-websocket-extensions",
      "permessage-deflate".parse().unwrap(),
    );
    let compression = negotiate_permessage_deflate(&headers, compression_settings())
      .unwrap()
      .unwrap();
    let payload = br#"{"event":"operation.progress","message":"compress me"}"#;
    let mut compressed = compression.compress(payload).unwrap();
    assert!(!compressed.ends_with(&[0, 0, 0xff, 0xff]));
    compressed.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut decoded = Vec::with_capacity(payload.len());
    Decompress::new(false)
      .decompress_vec(&compressed, &mut decoded, FlushDecompress::Sync)
      .unwrap();
    assert_eq!(decoded, payload);
  }

  #[test]
  fn permessage_deflate_consumes_payloads_larger_than_its_output_chunk() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "sec-websocket-extensions",
      "permessage-deflate".parse().unwrap(),
    );
    let compression = negotiate_permessage_deflate(&headers, compression_settings())
      .unwrap()
      .unwrap();
    let mut state = 0x1234_5678_u32;
    let payload = (0..128 * 1024)
      .map(|_| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state as u8
      })
      .collect::<Vec<_>>();
    let mut compressed = compression.compress(&payload).unwrap();
    compressed.extend_from_slice(&[0, 0, 0xff, 0xff]);
    let mut decoded = Vec::with_capacity(payload.len());
    Decompress::new(false)
      .decompress_vec(&compressed, &mut decoded, FlushDecompress::Sync)
      .unwrap();
    assert_eq!(decoded, payload);
  }
}
