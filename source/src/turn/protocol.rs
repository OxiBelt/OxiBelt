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
pub const SEND_INDICATION: u16 = 0x0016;
pub const DATA_INDICATION: u16 = 0x0017;

pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000c;
pub const ATTR_LIFETIME: u16 = 0x000d;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;
pub const ATTR_ADDRESS_ERROR_CODE: u16 = 0x8001;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

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
    && u32::from_be_bytes(bytes[4..8].try_into().expect("length checked")) == MAGIC_COOKIE
}

pub fn parse_stun(bytes: &[u8]) -> anyhow::Result<StunMessage<'_>> {
  if !is_stun_message(bytes) {
    bail!("not a STUN message");
  }
  let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
  if !len.is_multiple_of(4) || bytes.len() < HEADER_LEN + len {
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
    if value_end > raw.len() {
      bail!("truncated STUN attribute value");
    }
    attrs.push(StunAttribute {
      kind,
      value: &raw[value_start..value_end],
      offset,
    });
    offset = value_end + padding(attr_len);
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
  if !(0x4000..=0x7fff).contains(&channel) || bytes.len() < 4 + len {
    bail!("invalid TURN ChannelData");
  }
  Ok(ChannelData {
    channel,
    payload: &bytes[4..4 + len],
  })
}

pub fn attr_string(message: &StunMessage<'_>, kind: u16) -> Option<String> {
  message
    .attrs
    .iter()
    .find(|attr| attr.kind == kind)
    .and_then(|attr| std::str::from_utf8(attr.value).ok())
    .map(ToOwned::to_owned)
}

pub fn attr_u32(message: &StunMessage<'_>, kind: u16) -> Option<u32> {
  message
    .attrs
    .iter()
    .find(|attr| attr.kind == kind && attr.value.len() == 4)
    .map(|attr| u32::from_be_bytes(attr.value.try_into().expect("length checked")))
}

pub fn attr_bytes<'a>(message: &'a StunMessage<'_>, kind: u16) -> Option<&'a [u8]> {
  message
    .attrs
    .iter()
    .find(|attr| attr.kind == kind)
    .map(|attr| attr.value)
}

pub fn attr_xor_addr(message: &StunMessage<'_>, kind: u16) -> anyhow::Result<Option<SocketAddr>> {
  let Some(attr) = message.attrs.iter().find(|attr| attr.kind == kind) else {
    return Ok(None);
  };
  decode_xor_address(attr.value, &message.transaction_id).map(Some)
}

pub fn attr_xor_addrs(message: &StunMessage<'_>, kind: u16) -> anyhow::Result<Vec<SocketAddr>> {
  message
    .attrs
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
  let class = (code / 100) as u8;
  let number = (code % 100) as u8;
  let mut error = vec![0, 0, 0, (class << 5) | number];
  error.extend_from_slice(reason.as_bytes());
  let mut attrs = vec![(ATTR_ERROR_CODE, error)];
  if let Some(realm) = realm {
    attrs.push((ATTR_REALM, realm.as_bytes().to_vec()));
  }
  if let Some(nonce) = nonce {
    attrs.push((ATTR_NONCE, nonce.as_bytes().to_vec()));
  }
  with_fingerprint(encode_message(
    error_type(request_type),
    transaction_id,
    &attrs,
  ))
}

pub fn encode_success(
  request_type: u16,
  transaction_id: [u8; 12],
  attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
  with_fingerprint(encode_message(
    success_type(request_type),
    transaction_id,
    attrs,
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

pub fn encode_channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(4 + payload.len() + padding(payload.len()));
  out.extend_from_slice(&channel.to_be_bytes());
  out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  out.extend_from_slice(payload);
  out.resize(out.len() + padding(payload.len()), 0);
  out
}

pub fn with_message_integrity(mut message: Vec<u8>, key: &[u8]) -> Vec<u8> {
  let final_len = (message.len() + 24 - HEADER_LEN) as u16;
  message[2..4].copy_from_slice(&final_len.to_be_bytes());
  let integrity = hmac_sha1(key, &message);
  append_attr(&mut message, ATTR_MESSAGE_INTEGRITY, &integrity);
  message
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
    0x01 if value.len() >= 8 => {
      let raw = u32::from_be_bytes(value[4..8].try_into().expect("length checked")) ^ MAGIC_COOKIE;
      Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
    }
    0x02 if value.len() >= 20 => {
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
  Ok(expected == u32::from_be_bytes(attr.value.try_into().expect("length checked")))
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

fn with_fingerprint(mut message: Vec<u8>) -> Vec<u8> {
  let final_len = (message.len() + 8 - HEADER_LEN) as u16;
  message[2..4].copy_from_slice(&final_len.to_be_bytes());
  let fingerprint = crc32(&message) ^ 0x5354_554e;
  append_attr(&mut message, ATTR_FINGERPRINT, &fingerprint.to_be_bytes());
  message
}

fn padding(len: usize) -> usize {
  (4 - (len % 4)) % 4
}

fn crc32(bytes: &[u8]) -> u32 {
  let mut crc = 0xffff_ffffu32;
  for byte in bytes {
    crc ^= *byte as u32;
    for _ in 0..8 {
      let mask = 0u32.wrapping_sub(crc & 1);
      crc = (crc >> 1) ^ (0xedb8_8320 & mask);
    }
  }
  !crc
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
mod tests {
  use super::*;

  #[test]
  fn stun_success_round_trips_with_fingerprint() {
    let txid = [7u8; 12];
    let mapped: SocketAddr = "192.0.2.10:54321".parse().unwrap();
    let encoded = encode_success(
      BINDING_REQUEST,
      txid,
      &[(ATTR_XOR_MAPPED_ADDRESS, encode_xor_address(mapped, &txid))],
    );
    let parsed = parse_stun(&encoded).expect("STUN response should parse");
    assert_eq!(parsed.message_type, success_type(BINDING_REQUEST));
    assert_eq!(
      attr_xor_addr(&parsed, ATTR_XOR_MAPPED_ADDRESS)
        .unwrap()
        .unwrap(),
      mapped
    );
    assert!(verify_fingerprint(&parsed).unwrap());
  }

  #[test]
  fn channel_data_round_trips() {
    let encoded = encode_channel_data(0x4001, b"hello");
    let parsed = parse_channel_data(&encoded).expect("ChannelData should parse");
    assert_eq!(parsed.channel, 0x4001);
    assert_eq!(parsed.payload, b"hello");
  }
}
