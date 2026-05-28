use anyhow::{Context, bail, ensure};

use crate::config::normalize_sni_pattern;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;
const TLS_NAME_TYPE_HOST_NAME: u8 = 0x00;

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
  let sni =
    raw_client_hello_sni(&data[TLS_RECORD_HEADER_LEN..record_len]).context("invalid TLS record")?;
  Ok(ClientHelloSni::Complete(sni))
}

pub(crate) fn raw_client_hello_sni(data: &[u8]) -> anyhow::Result<Option<String>> {
  parse_raw_client_hello_sni(data).context("invalid TLS ClientHello")
}

fn parse_raw_client_hello_sni(data: &[u8]) -> anyhow::Result<Option<String>> {
  let mut cursor = ByteCursor::new(data);
  let handshake_type = cursor.read_u8()?;
  ensure!(
    handshake_type == TLS_HANDSHAKE_CLIENT_HELLO,
    "expected TLS ClientHello handshake"
  );
  let body_len = cursor.read_u24()?;
  let body = cursor.take(body_len)?;
  parse_client_hello_body_sni(body)
}

fn parse_client_hello_body_sni(body: &[u8]) -> anyhow::Result<Option<String>> {
  let mut cursor = ByteCursor::new(body);
  cursor.skip(2)?; // legacy_version
  cursor.skip(32)?; // random

  let session_id_len = usize::from(cursor.read_u8()?);
  ensure!(session_id_len <= 32, "invalid TLS session ID length");
  cursor.skip(session_id_len)?;

  let cipher_suites_len = usize::from(cursor.read_u16()?);
  ensure!(
    cipher_suites_len > 0 && cipher_suites_len % 2 == 0,
    "invalid TLS cipher suite vector length"
  );
  cursor.skip(cipher_suites_len)?;

  let compression_methods_len = usize::from(cursor.read_u8()?);
  cursor.skip(compression_methods_len)?;

  if cursor.remaining() == 0 {
    return Ok(None);
  }

  let extensions_len = usize::from(cursor.read_u16()?);
  let extensions = cursor.take(extensions_len)?;
  parse_extensions_sni(extensions)
}

fn parse_extensions_sni(extensions: &[u8]) -> anyhow::Result<Option<String>> {
  let mut cursor = ByteCursor::new(extensions);
  while cursor.remaining() > 0 {
    let extension_type = cursor.read_u16()?;
    let extension_len = usize::from(cursor.read_u16()?);
    let extension = cursor.take(extension_len)?;
    if extension_type == TLS_EXTENSION_SERVER_NAME {
      return parse_server_name_extension_sni(extension);
    }
  }
  Ok(None)
}

fn parse_server_name_extension_sni(extension: &[u8]) -> anyhow::Result<Option<String>> {
  let mut cursor = ByteCursor::new(extension);
  let list_len = usize::from(cursor.read_u16()?);
  let names = cursor.take(list_len)?;
  let mut names_cursor = ByteCursor::new(names);
  while names_cursor.remaining() > 0 {
    let name_type = names_cursor.read_u8()?;
    let name_len = usize::from(names_cursor.read_u16()?);
    let name = names_cursor.take(name_len)?;
    if name_type == TLS_NAME_TYPE_HOST_NAME {
      let value = std::str::from_utf8(name).context("SNI is not valid UTF-8")?;
      return normalize_visible_sni(value).map(Some);
    }
  }
  Ok(None)
}

fn tls_record_len(data: &[u8]) -> anyhow::Result<Option<usize>> {
  if data.len() < TLS_RECORD_HEADER_LEN {
    return Ok(None);
  }
  if data[0] != 0x16 {
    bail!("expected TLS handshake record");
  }
  let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
  Ok(Some(TLS_RECORD_HEADER_LEN + record_len))
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

struct ByteCursor<'a> {
  data: &'a [u8],
  offset: usize,
}

impl<'a> ByteCursor<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self { data, offset: 0 }
  }

  fn remaining(&self) -> usize {
    self.data.len().saturating_sub(self.offset)
  }

  fn skip(&mut self, len: usize) -> anyhow::Result<()> {
    self.take(len).map(|_| ())
  }

  fn take(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
    let end = self
      .offset
      .checked_add(len)
      .context("TLS ClientHello offset overflow")?;
    let bytes = self
      .data
      .get(self.offset..end)
      .context("truncated TLS ClientHello")?;
    self.offset = end;
    Ok(bytes)
  }

  fn read_u8(&mut self) -> anyhow::Result<u8> {
    Ok(self.take(1)?[0])
  }

  fn read_u16(&mut self) -> anyhow::Result<u16> {
    let bytes = self.take(2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
  }

  fn read_u24(&mut self) -> anyhow::Result<usize> {
    let bytes = self.take(3)?;
    Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
  }
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

  #[test]
  fn raw_client_hello_parser_extracts_sni() {
    let hello = client_hello_with_sni("Example.TEST");

    let sni = raw_client_hello_sni(&hello).expect("parse");

    assert_eq!(sni.as_deref(), Some("example.test"));
  }

  #[test]
  fn tls_record_parser_extracts_sni() {
    let hello = client_hello_with_sni("app.example.test");
    let record = tls_record(&hello);

    let sni = tls_record_client_hello_sni(&record).expect("parse");

    assert_eq!(
      sni,
      ClientHelloSni::Complete(Some("app.example.test".to_string()))
    );
  }

  #[test]
  fn raw_client_hello_parser_allows_missing_sni() {
    let hello = client_hello_without_extensions();

    let sni = raw_client_hello_sni(&hello).expect("parse");

    assert_eq!(sni, None);
  }

  fn tls_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x03]);
    record.extend_from_slice(
      &u16::try_from(payload.len())
        .expect("payload fits TLS record")
        .to_be_bytes(),
    );
    record.extend_from_slice(payload);
    record
  }

  fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    let mut server_name = Vec::new();
    let sni_len = u16::try_from(sni.len()).expect("sni fits u16");
    let list_len = 1u16 + 2 + sni_len;
    server_name.extend_from_slice(&list_len.to_be_bytes());
    server_name.push(TLS_NAME_TYPE_HOST_NAME);
    server_name.extend_from_slice(&sni_len.to_be_bytes());
    server_name.extend_from_slice(sni.as_bytes());

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&TLS_EXTENSION_SERVER_NAME.to_be_bytes());
    extensions.extend_from_slice(
      &u16::try_from(server_name.len())
        .expect("extension fits u16")
        .to_be_bytes(),
    );
    extensions.extend_from_slice(&server_name);

    client_hello_with_extensions(&extensions)
  }

  fn client_hello_without_extensions() -> Vec<u8> {
    client_hello_with_extensions(&[])
  }

  fn client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    if !extensions.is_empty() {
      body.extend_from_slice(
        &u16::try_from(extensions.len())
          .expect("extensions fit u16")
          .to_be_bytes(),
      );
      body.extend_from_slice(extensions);
    }

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(TLS_HANDSHAKE_CLIENT_HELLO);
    let body_len = u32::try_from(body.len()).expect("body fits u24");
    message.push(((body_len >> 16) & 0xff) as u8);
    message.push(((body_len >> 8) & 0xff) as u8);
    message.push((body_len & 0xff) as u8);
    message.extend_from_slice(&body);
    message
  }
}
