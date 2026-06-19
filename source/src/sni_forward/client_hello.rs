//! TLS ClientHello parsing for SNI forwarding.
//! The parser extracts routing metadata without completing a TLS handshake.

use anyhow::{Context, bail, ensure};

use crate::config::{SniForwardClientHelloParseMethod, normalize_sni_pattern};

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x0000;
const TLS_NAME_TYPE_HOST_NAME: u8 = 0x00;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ClientHelloSni {
  Complete(Option<String>),
  Incomplete,
}

pub(crate) fn tls_record_client_hello_sni(
  data: &[u8],
  methods: &[SniForwardClientHelloParseMethod],
) -> anyhow::Result<ClientHelloSni> {
  if methods.contains(&SniForwardClientHelloParseMethod::TlsRecordReassembly) {
    return reassembled_tls_record_client_hello_sni(data);
  }
  single_record_client_hello_sni(data)
}

fn single_record_client_hello_sni(data: &[u8]) -> anyhow::Result<ClientHelloSni> {
  let Some((payload_start, record_end)) = tls_record_bounds(data, 0)? else {
    return Ok(ClientHelloSni::Incomplete);
  };
  let sni = raw_client_hello_sni(&data[payload_start..record_end]).context("invalid TLS record")?;
  Ok(ClientHelloSni::Complete(sni))
}

fn reassembled_tls_record_client_hello_sni(data: &[u8]) -> anyhow::Result<ClientHelloSni> {
  let mut cursor = 0usize;
  let mut handshake = Vec::new();
  let mut expected_handshake_len = None;
  loop {
    let Some((payload_start, record_end)) = tls_record_bounds(data, cursor)? else {
      return Ok(ClientHelloSni::Incomplete);
    };
    handshake.extend_from_slice(&data[payload_start..record_end]);
    if expected_handshake_len.is_none() {
      expected_handshake_len = client_hello_message_len(&handshake)?;
    }
    if let Some(expected_len) = expected_handshake_len
      && handshake.len() >= expected_len
    {
      let sni = raw_client_hello_sni(&handshake[..expected_len]).context("invalid TLS record")?;
      return Ok(ClientHelloSni::Complete(sni));
    }
    cursor = record_end;
  }
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

fn client_hello_message_len(data: &[u8]) -> anyhow::Result<Option<usize>> {
  if data.len() < 4 {
    return Ok(None);
  }
  let mut cursor = ByteCursor::new(data);
  let handshake_type = cursor.read_u8()?;
  ensure!(
    handshake_type == TLS_HANDSHAKE_CLIENT_HELLO,
    "expected TLS ClientHello handshake"
  );
  let body_len = cursor.read_u24()?;
  Ok(Some(4 + body_len))
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
  ensure!(
    cursor.remaining() == 0,
    "unexpected trailing data after TLS ClientHello extensions"
  );
  parse_extensions_sni(extensions)
}

fn parse_extensions_sni(extensions: &[u8]) -> anyhow::Result<Option<String>> {
  let mut cursor = ByteCursor::new(extensions);
  let mut saw_server_name = false;
  let mut sni = None;
  while cursor.remaining() > 0 {
    let extension_type = cursor.read_u16()?;
    let extension_len = usize::from(cursor.read_u16()?);
    let extension = cursor.take(extension_len)?;
    if extension_type == TLS_EXTENSION_SERVER_NAME {
      ensure!(!saw_server_name, "duplicate TLS server_name extension");
      saw_server_name = true;
      sni = parse_server_name_extension_sni(extension)?;
    }
  }
  Ok(sni)
}

fn parse_server_name_extension_sni(extension: &[u8]) -> anyhow::Result<Option<String>> {
  let mut cursor = ByteCursor::new(extension);
  let list_len = usize::from(cursor.read_u16()?);
  let names = cursor.take(list_len)?;
  ensure!(
    cursor.remaining() == 0,
    "unexpected trailing data after TLS server_name list"
  );

  let mut sni = None;
  let mut names_cursor = ByteCursor::new(names);
  while names_cursor.remaining() > 0 {
    let name_type = names_cursor.read_u8()?;
    let name_len = usize::from(names_cursor.read_u16()?);
    let name = names_cursor.take(name_len)?;
    if name_type == TLS_NAME_TYPE_HOST_NAME {
      ensure!(sni.is_none(), "duplicate TLS host_name entry");
      let value = std::str::from_utf8(name).context("SNI is not valid UTF-8")?;
      sni = Some(normalize_visible_sni(value)?);
    }
  }
  Ok(sni)
}

fn tls_record_bounds(data: &[u8], offset: usize) -> anyhow::Result<Option<(usize, usize)>> {
  if data.len() < TLS_RECORD_HEADER_LEN {
    return Ok(None);
  }
  let header_end = offset
    .checked_add(TLS_RECORD_HEADER_LEN)
    .context("TLS record offset overflow")?;
  if data.len() < header_end {
    return Ok(None);
  }
  if data[offset] != 0x16 {
    bail!("expected TLS handshake record");
  }
  let record_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
  let record_end = header_end
    .checked_add(record_len)
    .context("TLS record length overflow")?;
  if data.len() < record_end {
    return Ok(None);
  }
  Ok(Some((header_end, record_end)))
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
      tls_record_client_hello_sni(&[0x16, 0x03, 0x01, 0x00], &single_record_methods()),
      Ok(ClientHelloSni::Incomplete)
    ));
    assert!(matches!(
      tls_record_client_hello_sni(
        &[0x16, 0x03, 0x01, 0x00, 0x10, 0x01],
        &single_record_methods()
      ),
      Ok(ClientHelloSni::Incomplete)
    ));
  }

  #[test]
  fn tls_record_parser_rejects_non_tls() {
    assert!(tls_record_client_hello_sni(b"GET / HTTP/1.1\r\n", &single_record_methods()).is_err());
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

    let sni = tls_record_client_hello_sni(&record, &single_record_methods()).expect("parse");

    assert_eq!(
      sni,
      ClientHelloSni::Complete(Some("app.example.test".to_string()))
    );
  }

  #[test]
  fn tls_record_parser_rejects_fragmented_client_hello_without_reassembly() {
    let host = "split.example.test";
    let hello = client_hello_with_sni(host);
    let sni_offset = hello
      .windows(host.len())
      .position(|window| window == host.as_bytes())
      .expect("synthetic hello includes SNI");
    let record = fragmented_tls_records(&hello, sni_offset + 1);

    let error = tls_record_client_hello_sni(&record, &single_record_methods())
      .expect_err("strict parser should reject fragmented ClientHello records");

    assert!(
      format!("{error:#}").contains("truncated TLS ClientHello"),
      "{error:#}"
    );
  }

  #[test]
  fn tls_record_parser_reassembles_fragmented_client_hello_when_enabled() {
    let host = "split.example.test";
    let hello = client_hello_with_sni(host);
    let sni_offset = hello
      .windows(host.len())
      .position(|window| window == host.as_bytes())
      .expect("synthetic hello includes SNI");
    let record = fragmented_tls_records(&hello, sni_offset + 1);

    let sni = tls_record_client_hello_sni(&record, &reassembly_methods()).expect("parse");

    assert_eq!(sni, ClientHelloSni::Complete(Some(host.to_string())));
  }

  #[test]
  fn raw_client_hello_parser_allows_missing_sni() {
    let hello = client_hello_without_extensions();

    let sni = raw_client_hello_sni(&hello).expect("parse");

    assert_eq!(sni, None);
  }

  #[test]
  fn raw_client_hello_parser_rejects_duplicate_server_name_extensions() {
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&server_name_extension(&["first.example.test"], &[]));
    extensions.extend_from_slice(&server_name_extension(&["second.example.test"], &[]));
    let hello = client_hello_with_extensions(&extensions);

    let error = raw_client_hello_sni(&hello).expect_err("duplicate server_name should fail");

    assert!(
      format!("{error:#}").contains("duplicate TLS server_name extension"),
      "{error:#}"
    );
  }

  #[test]
  fn raw_client_hello_parser_rejects_duplicate_host_name_entries() {
    let extensions = server_name_extension(&["first.example.test", "second.example.test"], &[]);
    let hello = client_hello_with_extensions(&extensions);

    let error = raw_client_hello_sni(&hello).expect_err("duplicate host_name should fail");

    assert!(
      format!("{error:#}").contains("duplicate TLS host_name entry"),
      "{error:#}"
    );
  }

  #[test]
  fn raw_client_hello_parser_rejects_trailing_server_name_bytes() {
    let extensions = server_name_extension(&["app.example.test"], &[0xff]);
    let hello = client_hello_with_extensions(&extensions);

    let error = raw_client_hello_sni(&hello).expect_err("trailing server_name bytes should fail");

    assert!(
      format!("{error:#}").contains("unexpected trailing data after TLS server_name list"),
      "{error:#}"
    );
  }

  #[test]
  fn raw_client_hello_parser_rejects_trailing_client_hello_extension_bytes() {
    let extensions = server_name_extension(&["app.example.test"], &[]);
    let hello = client_hello_with_extensions_and_trailing(&extensions, &[0xff]);

    let error =
      raw_client_hello_sni(&hello).expect_err("trailing ClientHello extension bytes should fail");

    assert!(
      format!("{error:#}").contains("unexpected trailing data after TLS ClientHello extensions"),
      "{error:#}"
    );
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

  fn fragmented_tls_records(payload: &[u8], split_at: usize) -> Vec<u8> {
    assert!(split_at > 0 && split_at < payload.len());
    let mut records = tls_record(&payload[..split_at]);
    records.extend_from_slice(&tls_record(&payload[split_at..]));
    records
  }

  fn single_record_methods() -> [SniForwardClientHelloParseMethod; 1] {
    [SniForwardClientHelloParseMethod::SingleRecord]
  }

  fn reassembly_methods() -> [SniForwardClientHelloParseMethod; 2] {
    [
      SniForwardClientHelloParseMethod::SingleRecord,
      SniForwardClientHelloParseMethod::TlsRecordReassembly,
    ]
  }

  fn client_hello_with_sni(sni: &str) -> Vec<u8> {
    client_hello_with_extensions(&server_name_extension(&[sni], &[]))
  }

  fn server_name_extension(names: &[&str], trailing: &[u8]) -> Vec<u8> {
    let mut server_name = Vec::new();
    let list_len = names.iter().fold(0u16, |len, name| {
      let name_len = u16::try_from(name.len()).expect("sni fits u16");
      len
        .checked_add(1 + 2 + name_len)
        .expect("server name list fits u16")
    });
    server_name.extend_from_slice(&list_len.to_be_bytes());
    for name in names {
      let name_len = u16::try_from(name.len()).expect("sni fits u16");
      server_name.push(TLS_NAME_TYPE_HOST_NAME);
      server_name.extend_from_slice(&name_len.to_be_bytes());
      server_name.extend_from_slice(name.as_bytes());
    }
    server_name.extend_from_slice(trailing);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&TLS_EXTENSION_SERVER_NAME.to_be_bytes());
    extensions.extend_from_slice(
      &u16::try_from(server_name.len())
        .expect("extension fits u16")
        .to_be_bytes(),
    );
    extensions.extend_from_slice(&server_name);
    extensions
  }

  fn client_hello_without_extensions() -> Vec<u8> {
    client_hello_with_extensions(&[])
  }

  fn client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
    client_hello_with_extensions_and_trailing(extensions, &[])
  }

  fn client_hello_with_extensions_and_trailing(extensions: &[u8], trailing: &[u8]) -> Vec<u8> {
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
    body.extend_from_slice(trailing);

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
