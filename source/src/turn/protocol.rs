//! TURN protocol parsing and packet helpers.
//! Packet data is untrusted until message integrity and allocation state agree.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, bail};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
pub const HEADER_LEN: usize = 20;

pub const BINDING_REQUEST: u16 = 0x0001;
pub const ALLOCATE_REQUEST: u16 = 0x0003;
pub const REFRESH_REQUEST: u16 = 0x0004;
pub const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub const CHANNEL_BIND_REQUEST: u16 = 0x0009;
pub const CONNECT_REQUEST: u16 = 0x000a;
pub const CONNECTION_BIND_REQUEST: u16 = 0x000b;
pub const SEND_INDICATION: u16 = 0x0016;
pub const DATA_INDICATION: u16 = 0x0017;
pub const CONNECTION_ATTEMPT_INDICATION: u16 = 0x001c;

pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000a;
pub const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001c;
pub const ATTR_PASSWORD_ALGORITHM: u16 = 0x001d;
pub const ATTR_USERHASH: u16 = 0x001e;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000c;
pub const ATTR_LIFETIME: u16 = 0x000d;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTR_EVEN_PORT: u16 = 0x0018;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_DONT_FRAGMENT: u16 = 0x001a;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_RESERVATION_TOKEN: u16 = 0x0022;
pub const ATTR_CONNECTION_ID: u16 = 0x002a;
pub const ATTR_ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
pub const ATTR_ADDRESS_ERROR_CODE: u16 = 0x8001;
pub const ATTR_PASSWORD_ALGORITHMS: u16 = 0x8002;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

pub const SOFTWARE_VALUE: &[u8] = b"OxiBelt";

pub const PASSWORD_ALGORITHM_MD5: u16 = 0x0001;
pub const PASSWORD_ALGORITHM_SHA256: u16 = 0x0002;

#[derive(Debug, Clone)]
pub struct StunMessage<'a> {
  pub message_type: u16,
  pub transaction_id: [u8; 12],
  pub attrs: Vec<StunAttribute<'a>>,
  pub raw: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct StunAttribute<'a> {
  pub kind: u16,
  pub value: &'a [u8],
  pub offset: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ChannelData<'a> {
  pub channel: u16,
  pub payload: &'a [u8],
}

pub fn is_stun_message(bytes: &[u8]) -> bool {
  bytes.len() >= HEADER_LEN
    && bytes[0] & 0b1100_0000 == 0
    && u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) == MAGIC_COOKIE
}

pub fn parse_stun(bytes: &[u8]) -> anyhow::Result<StunMessage<'_>> {
  if !is_stun_message(bytes) {
    bail!("not a STUN message");
  }
  let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
  if !len.is_multiple_of(4) || bytes.len() != HEADER_LEN + len {
    bail!("invalid STUN message length");
  }
  let raw = &bytes[..HEADER_LEN + len];
  let mut transaction_id = [0u8; 12];
  transaction_id.copy_from_slice(&raw[8..20]);
  let mut attrs = Vec::new();
  let mut offset = HEADER_LEN;
  while offset < raw.len() {
    if offset + 4 > raw.len() {
      bail!("truncated STUN attribute header");
    }
    let kind = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    let attr_len = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
    let value_start = offset + 4;
    let value_end = value_start + attr_len;
    let next = value_end
      .checked_add(padding(attr_len))
      .ok_or_else(|| anyhow::anyhow!("STUN attribute length overflow"))?;
    if next > raw.len() {
      bail!("truncated STUN attribute value");
    }
    attrs.push(StunAttribute {
      kind,
      value: &raw[value_start..value_end],
      offset,
    });
    offset = next;
  }
  if offset != raw.len() {
    bail!("invalid STUN attribute padding");
  }
  Ok(StunMessage {
    message_type: u16::from_be_bytes([raw[0], raw[1]]),
    transaction_id,
    attrs,
    raw,
  })
}

pub fn parse_channel_data(bytes: &[u8]) -> anyhow::Result<ChannelData<'_>> {
  if bytes.len() < 4 || bytes[0] & 0b1100_0000 != 0b0100_0000 {
    bail!("not TURN ChannelData");
  }
  let channel = u16::from_be_bytes([bytes[0], bytes[1]]);
  let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
  if !(0x4000..=0x4fff).contains(&channel) || bytes.len() < 4 + len {
    bail!("invalid TURN ChannelData");
  }
  Ok(ChannelData {
    channel,
    payload: &bytes[4..4 + len],
  })
}

pub fn attr_string(message: &StunMessage<'_>, kind: u16) -> Option<String> {
  semantic_attributes(message)
    .iter()
    .find(|attr| attr.kind == kind)
    .and_then(|attr| std::str::from_utf8(attr.value).ok())
    .map(ToOwned::to_owned)
}

pub fn attr_u32(message: &StunMessage<'_>, kind: u16) -> Option<u32> {
  semantic_attributes(message)
    .iter()
    .find(|attr| attr.kind == kind && attr.value.len() == 4)
    .map(|attr| u32::from_be_bytes([attr.value[0], attr.value[1], attr.value[2], attr.value[3]]))
}

pub fn attr_bytes<'a>(message: &'a StunMessage<'_>, kind: u16) -> Option<&'a [u8]> {
  semantic_attributes(message)
    .iter()
    .find(|attr| attr.kind == kind)
    .map(|attr| attr.value)
}

/// Returns comprehension-required attributes this implementation does not understand.
/// Callers can use this to send a standards-compliant 420 response without accepting an
/// extension whose meaning is security relevant.
pub fn unknown_required_attributes(message: &StunMessage<'_>) -> Vec<u16> {
  semantic_attributes(message)
    .iter()
    .filter_map(|attr| (attr.kind < 0x8000 && !known_attribute(attr.kind)).then_some(attr.kind))
    .collect()
}

/// RFC 8489 integrity attributes must be terminal (apart from FINGERPRINT), and the
/// SHA-256 integrity attribute precedes legacy SHA-1 when both are present.
pub fn validate_attribute_ordering(message: &StunMessage<'_>) -> anyhow::Result<()> {
  for singleton in [
    ATTR_USERNAME,
    ATTR_USERHASH,
    ATTR_REALM,
    ATTR_NONCE,
    ATTR_PASSWORD_ALGORITHM,
    ATTR_PASSWORD_ALGORITHMS,
  ] {
    if semantic_attributes(message)
      .iter()
      .filter(|attribute| attribute.kind == singleton)
      .nth(1)
      .is_some()
    {
      bail!("duplicate singleton STUN security attribute {singleton:#06x}");
    }
  }
  for singleton in [
    ATTR_MESSAGE_INTEGRITY_SHA256,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_FINGERPRINT,
  ] {
    if message
      .attrs
      .iter()
      .filter(|attribute| attribute.kind == singleton)
      .nth(1)
      .is_some()
    {
      bail!("duplicate singleton STUN security attribute {singleton:#06x}");
    }
  }
  let mut legacy_seen = false;
  let mut sha256_seen = false;
  for (index, attr) in message.attrs.iter().enumerate() {
    match attr.kind {
      ATTR_MESSAGE_INTEGRITY_SHA256 => {
        if legacy_seen || sha256_seen || attr.value.len() != 32 {
          bail!("invalid STUN MESSAGE-INTEGRITY-SHA256 ordering");
        }
        sha256_seen = true;
      }
      ATTR_MESSAGE_INTEGRITY => {
        if attr.value.len() != 20 || legacy_seen {
          bail!("invalid STUN MESSAGE-INTEGRITY ordering");
        }
        legacy_seen = true;
      }
      ATTR_FINGERPRINT => {
        if attr.value.len() != 4 || index + 1 != message.attrs.len() {
          bail!("STUN FINGERPRINT must be the final attribute");
        }
      }
      _ => {}
    }
  }
  Ok(())
}

/// Attributes after the first integrity attribute do not participate in STUN method semantics.
/// RFC 8489 permits a later integrity/fingerprint attribute, but requires every other later
/// attribute to be ignored.
pub fn semantic_attributes<'m, 'a>(message: &'m StunMessage<'a>) -> &'m [StunAttribute<'a>] {
  let end = message
    .attrs
    .iter()
    .position(|attribute| {
      matches!(
        attribute.kind,
        ATTR_MESSAGE_INTEGRITY | ATTR_MESSAGE_INTEGRITY_SHA256
      )
    })
    .unwrap_or(message.attrs.len());
  &message.attrs[..end]
}

pub fn attr_xor_addr(message: &StunMessage<'_>, kind: u16) -> anyhow::Result<Option<SocketAddr>> {
  let Some(attr) = semantic_attributes(message)
    .iter()
    .find(|attr| attr.kind == kind)
  else {
    return Ok(None);
  };
  decode_xor_address(attr.value, &message.transaction_id).map(Some)
}

pub fn attr_xor_addrs(message: &StunMessage<'_>, kind: u16) -> anyhow::Result<Vec<SocketAddr>> {
  semantic_attributes(message)
    .iter()
    .filter(|attr| attr.kind == kind)
    .map(|attr| decode_xor_address(attr.value, &message.transaction_id))
    .collect()
}

pub fn success_type(request_type: u16) -> u16 {
  request_type | 0x0100
}

pub fn error_type(request_type: u16) -> u16 {
  request_type | 0x0110
}

pub fn encode_message(
  message_type: u16,
  transaction_id: [u8; 12],
  attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
  let mut out = Vec::with_capacity(HEADER_LEN + attrs.len() * 12);
  out.extend_from_slice(&message_type.to_be_bytes());
  out.extend_from_slice(&0u16.to_be_bytes());
  out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
  out.extend_from_slice(&transaction_id);
  for (kind, value) in attrs {
    append_attr(&mut out, *kind, value);
  }
  let len = (out.len() - HEADER_LEN) as u16;
  out[2..4].copy_from_slice(&len.to_be_bytes());
  out
}

pub fn encode_binding_request(transaction_id: [u8; 12]) -> Vec<u8> {
  encode_message(BINDING_REQUEST, transaction_id, &[])
}

pub fn encode_error(
  request_type: u16,
  transaction_id: [u8; 12],
  code: u16,
  reason: &str,
  realm: Option<&str>,
  nonce: Option<&str>,
) -> Vec<u8> {
  let mut attrs = vec![(ATTR_ERROR_CODE, encode_error_code(code, reason))];
  if let Some(realm) = realm {
    attrs.push((ATTR_REALM, realm.as_bytes().to_vec()));
  }
  if let Some(nonce) = nonce {
    attrs.push((ATTR_NONCE, nonce.as_bytes().to_vec()));
  }
  attrs.push((ATTR_SOFTWARE, SOFTWARE_VALUE.to_vec()));
  with_fingerprint(encode_message(
    error_type(request_type),
    transaction_id,
    &attrs,
  ))
}

pub fn encode_error_code(code: u16, reason: &str) -> Vec<u8> {
  let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
  value.extend_from_slice(reason.as_bytes());
  value
}

pub fn encode_success(
  request_type: u16,
  transaction_id: [u8; 12],
  attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
  let mut attrs = attrs.to_vec();
  attrs.push((ATTR_SOFTWARE, SOFTWARE_VALUE.to_vec()));
  with_fingerprint(encode_message(
    success_type(request_type),
    transaction_id,
    &attrs,
  ))
}

pub fn encode_data_indication(transaction_id: [u8; 12], peer: SocketAddr, data: &[u8]) -> Vec<u8> {
  with_fingerprint(encode_message(
    DATA_INDICATION,
    transaction_id,
    &[
      (
        ATTR_XOR_PEER_ADDRESS,
        encode_xor_address(peer, &transaction_id),
      ),
      (ATTR_DATA, data.to_vec()),
    ],
  ))
}

pub fn encode_channel_data(channel: u16, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
  if !(0x4000..=0x4fff).contains(&channel) {
    bail!("invalid TURN channel number");
  }
  let payload_len =
    u16::try_from(payload.len()).context("TURN ChannelData payload is too large")?;
  let mut out = Vec::with_capacity(4 + payload.len() + padding(payload.len()));
  out.extend_from_slice(&channel.to_be_bytes());
  out.extend_from_slice(&payload_len.to_be_bytes());
  out.extend_from_slice(payload);
  out.resize(out.len() + padding(payload.len()), 0);
  Ok(out)
}

pub fn with_message_integrity(mut message: Vec<u8>, key: &[u8]) -> Vec<u8> {
  let final_len = (message.len() + 24 - HEADER_LEN) as u16;
  message[2..4].copy_from_slice(&final_len.to_be_bytes());
  let integrity = hmac_sha1(key, &message);
  append_attr(&mut message, ATTR_MESSAGE_INTEGRITY, &integrity);
  message
}

pub fn with_message_integrity_sha256(mut message: Vec<u8>, key: &[u8]) -> Vec<u8> {
  let final_len = (message.len() + 36 - HEADER_LEN) as u16;
  message[2..4].copy_from_slice(&final_len.to_be_bytes());
  let integrity = crate::crypto::hmac_sha256(key, &message);
  append_attr(&mut message, ATTR_MESSAGE_INTEGRITY_SHA256, &integrity);
  message
}

/// Encodes the value of a PASSWORD-ALGORITHM attribute with no algorithm parameters.
pub fn encode_password_algorithm(algorithm: u16) -> Vec<u8> {
  let mut value = Vec::with_capacity(4);
  value.extend_from_slice(&algorithm.to_be_bytes());
  value.extend_from_slice(&0u16.to_be_bytes());
  value
}

/// Encodes the value of a PASSWORD-ALGORITHMS attribute. Each advertised algorithm has no
/// algorithm-specific parameters.
pub fn encode_password_algorithms(algorithms: &[u16]) -> Vec<u8> {
  let mut value = Vec::with_capacity(algorithms.len() * 4);
  for algorithm in algorithms {
    value.extend_from_slice(&encode_password_algorithm(*algorithm));
  }
  value
}

/// Parses a no-parameter PASSWORD-ALGORITHM selection. RFC 8489 permits
/// algorithm parameters in general, but this implementation advertises none
/// and therefore rejects a selection carrying any.
pub fn password_algorithm_selection(value: &[u8]) -> Option<u16> {
  (value.len() == 4 && value[2..] == [0, 0]).then(|| u16::from_be_bytes([value[0], value[1]]))
}

/// Returns whether a well-formed PASSWORD-ALGORITHMS value contains the
/// selected no-parameter algorithm. This avoids accepting a malformed list
/// merely because its first two bytes look like a supported algorithm.
pub fn password_algorithms_contains(value: &[u8], selected: u16) -> bool {
  let mut offset = 0;
  while offset < value.len() {
    if offset + 4 > value.len() {
      return false;
    }
    let algorithm = u16::from_be_bytes([value[offset], value[offset + 1]]);
    let parameter_len = usize::from(u16::from_be_bytes([value[offset + 2], value[offset + 3]]));
    let Some(next) = offset
      .checked_add(4)
      .and_then(|next| next.checked_add(parameter_len))
      .and_then(|next| next.checked_add(padding(parameter_len)))
    else {
      return false;
    };
    if next > value.len() {
      return false;
    }
    if algorithm == selected && parameter_len == 0 {
      return true;
    }
    offset = next;
  }
  false
}

/// Encodes sorted, de-duplicated UNKNOWN-ATTRIBUTES codes for a 420 response.
pub fn encode_unknown_attributes(attributes: &[u16]) -> Vec<u8> {
  let mut attributes = attributes.to_vec();
  attributes.sort_unstable();
  attributes.dedup();
  let mut value = Vec::with_capacity(attributes.len() * 2);
  for attribute in attributes {
    value.extend_from_slice(&attribute.to_be_bytes());
  }
  value
}

pub fn encode_xor_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
  let mut out = Vec::new();
  out.push(0);
  match addr.ip() {
    IpAddr::V4(ip) => {
      out.push(0x01);
      out.extend_from_slice(&(addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
      let value = u32::from(ip) ^ MAGIC_COOKIE;
      out.extend_from_slice(&value.to_be_bytes());
    }
    IpAddr::V6(ip) => {
      out.push(0x02);
      out.extend_from_slice(&(addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)).to_be_bytes());
      let mut mask = [0u8; 16];
      mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
      mask[4..].copy_from_slice(transaction_id);
      for (byte, mask) in ip.octets().iter().zip(mask) {
        out.push(byte ^ mask);
      }
    }
  }
  out
}

pub fn decode_xor_address(value: &[u8], transaction_id: &[u8; 12]) -> anyhow::Result<SocketAddr> {
  if value.len() < 8 || value[0] != 0 {
    bail!("invalid XOR address");
  }
  let port = u16::from_be_bytes([value[2], value[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
  match value[1] {
    0x01 if value.len() == 8 => {
      let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ MAGIC_COOKIE;
      Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
    }
    0x02 if value.len() == 20 => {
      let mut mask = [0u8; 16];
      mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
      mask[4..].copy_from_slice(transaction_id);
      let mut addr = [0u8; 16];
      for index in 0..16 {
        addr[index] = value[4 + index] ^ mask[index];
      }
      Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
    }
    _ => bail!("unsupported XOR address family"),
  }
}

pub fn verify_message_integrity(message: &StunMessage<'_>, key: &[u8]) -> anyhow::Result<bool> {
  let Some(attr) = message
    .attrs
    .iter()
    .find(|attr| attr.kind == ATTR_MESSAGE_INTEGRITY)
  else {
    return Ok(false);
  };
  if attr.value.len() != 20 {
    return Ok(false);
  }
  let mut bytes = message.raw[..attr.offset].to_vec();
  let len = (attr.offset + 24 - HEADER_LEN) as u16;
  bytes[2..4].copy_from_slice(&len.to_be_bytes());
  Ok(crate::crypto::verify_hmac_sha1(key, &bytes, attr.value))
}

pub fn verify_message_integrity_sha256(
  message: &StunMessage<'_>,
  key: &[u8],
) -> anyhow::Result<bool> {
  let Some(attr) = message
    .attrs
    .iter()
    .find(|attr| attr.kind == ATTR_MESSAGE_INTEGRITY_SHA256)
  else {
    return Ok(false);
  };
  if attr.value.len() != 32 {
    return Ok(false);
  }
  let mut bytes = message.raw[..attr.offset].to_vec();
  let len = (attr.offset + 36 - HEADER_LEN) as u16;
  bytes[2..4].copy_from_slice(&len.to_be_bytes());
  Ok(constant_time_eq(
    &crate::crypto::hmac_sha256(key, &bytes),
    attr.value,
  ))
}

pub fn verify_fingerprint(message: &StunMessage<'_>) -> anyhow::Result<bool> {
  let Some(attr) = message
    .attrs
    .iter()
    .find(|attr| attr.kind == ATTR_FINGERPRINT)
  else {
    return Ok(false);
  };
  if attr.value.len() != 4 {
    return Ok(false);
  }
  let mut bytes = message.raw[..attr.offset].to_vec();
  let len = (attr.offset + 8 - HEADER_LEN) as u16;
  bytes[2..4].copy_from_slice(&len.to_be_bytes());
  let expected = crc32(&bytes) ^ 0x5354_554e;
  Ok(expected == u32::from_be_bytes([attr.value[0], attr.value[1], attr.value[2], attr.value[3]]))
}

pub fn hmac_sha1(key: &[u8], value: &[u8]) -> [u8; 20] {
  crate::crypto::hmac_sha1(key, value)
}

fn append_attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
  out.extend_from_slice(&kind.to_be_bytes());
  out.extend_from_slice(&(value.len() as u16).to_be_bytes());
  out.extend_from_slice(value);
  out.resize(out.len() + padding(value.len()), 0);
}

/// Appends a final FINGERPRINT after all response attributes and integrity material.
pub(crate) fn with_fingerprint(mut message: Vec<u8>) -> Vec<u8> {
  let final_len = (message.len() + 8 - HEADER_LEN) as u16;
  message[2..4].copy_from_slice(&final_len.to_be_bytes());
  let fingerprint = crc32(&message) ^ 0x5354_554e;
  append_attr(&mut message, ATTR_FINGERPRINT, &fingerprint.to_be_bytes());
  message
}

fn padding(len: usize) -> usize {
  (4 - (len % 4)) % 4
}

fn known_attribute(kind: u16) -> bool {
  matches!(
    kind,
    ATTR_USERNAME
      | ATTR_MESSAGE_INTEGRITY
      | ATTR_UNKNOWN_ATTRIBUTES
      | ATTR_ERROR_CODE
      | ATTR_CHANNEL_NUMBER
      | ATTR_LIFETIME
      | ATTR_XOR_PEER_ADDRESS
      | ATTR_DATA
      | ATTR_REALM
      | ATTR_NONCE
      | ATTR_XOR_RELAYED_ADDRESS
      | ATTR_REQUESTED_ADDRESS_FAMILY
      | ATTR_EVEN_PORT
      | ATTR_REQUESTED_TRANSPORT
      | ATTR_DONT_FRAGMENT
      | ATTR_XOR_MAPPED_ADDRESS
      | ATTR_RESERVATION_TOKEN
      | ATTR_CONNECTION_ID
      | ATTR_MESSAGE_INTEGRITY_SHA256
      | ATTR_PASSWORD_ALGORITHM
      | ATTR_USERHASH
      | ATTR_ADDITIONAL_ADDRESS_FAMILY
      | ATTR_ADDRESS_ERROR_CODE
      | ATTR_PASSWORD_ALGORITHMS
      | ATTR_SOFTWARE
      | ATTR_FINGERPRINT
  )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
  use subtle::ConstantTimeEq;
  left.len() == right.len() && bool::from(left.ct_eq(right))
}

pub(crate) fn crc32(bytes: &[u8]) -> u32 {
  crc32fast::hash(bytes)
}

pub async fn read_turn_frame<R>(reader: &mut R) -> anyhow::Result<Vec<u8>>
where
  R: tokio::io::AsyncRead + Unpin,
{
  use tokio::io::AsyncReadExt;

  let mut header = [0u8; 4];
  reader
    .read_exact(&mut header)
    .await
    .context("failed to read TURN frame header")?;
  if header[0] & 0b1100_0000 == 0b0100_0000 {
    let len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let mut frame = Vec::with_capacity(4 + len + padding(len));
    frame.extend_from_slice(&header);
    frame.resize(4 + len + padding(len), 0);
    reader
      .read_exact(&mut frame[4..])
      .await
      .context("failed to read TURN ChannelData frame")?;
    return Ok(frame);
  }
  let len = u16::from_be_bytes([header[2], header[3]]) as usize;
  let mut frame = Vec::with_capacity(HEADER_LEN + len);
  frame.extend_from_slice(&header);
  frame.resize(HEADER_LEN + len, 0);
  reader
    .read_exact(&mut frame[4..])
    .await
    .context("failed to read STUN frame")?;
  Ok(frame)
}

#[cfg(test)]
#[path = "protocol/tests.rs"]
mod tests;
