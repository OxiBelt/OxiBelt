use anyhow::{Context, bail};

use crate::config::normalize_sni_pattern;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ClientHelloSni {
  Complete(Option<String>),
  Incomplete,
}

pub(crate) fn tls_record_client_hello_sni(data: &[u8]) -> anyhow::Result<ClientHelloSni> {
  let Some(record_len) = tls_record_len(data)? else {
    return Ok(ClientHelloSni::Incomplete);
  };
  if data.len() < record_len {
    return Ok(ClientHelloSni::Incomplete);
  }
  let hello = clienthello::parse_from_record(&data[..record_len]).context("invalid TLS record")?;
  let sni = hello.server_name().map(normalize_visible_sni).transpose()?;
  Ok(ClientHelloSni::Complete(sni))
}

pub(crate) fn raw_client_hello_sni(data: &[u8]) -> anyhow::Result<Option<String>> {
  let hello = clienthello::parse(data).context("invalid TLS ClientHello")?;
  hello.server_name().map(normalize_visible_sni).transpose()
}

fn tls_record_len(data: &[u8]) -> anyhow::Result<Option<usize>> {
  if data.len() < 5 {
    return Ok(None);
  }
  if data[0] != 0x16 {
    bail!("expected TLS handshake record");
  }
  let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
  Ok(Some(5 + record_len))
}

fn normalize_visible_sni(value: &str) -> anyhow::Result<String> {
  if value.trim() != value || value.is_empty() {
    bail!("SNI must not be empty or padded");
  }
  if value.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("SNI contains a control character");
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("SNI contains invalid characters");
  }
  Ok(normalize_sni_pattern(value))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn tls_record_parser_waits_for_complete_record() {
    assert!(matches!(
      tls_record_client_hello_sni(&[0x16, 0x03, 0x01, 0x00]),
      Ok(ClientHelloSni::Incomplete)
    ));
    assert!(matches!(
      tls_record_client_hello_sni(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x01]),
      Ok(ClientHelloSni::Incomplete)
    ));
  }

  #[test]
  fn tls_record_parser_rejects_non_tls() {
    assert!(tls_record_client_hello_sni(b"GET / HTTP/1.1\r\n").is_err());
  }
}
