//! Lightweight client certificate metadata extraction for routing and WAF policy.
//! Parsing failures keep certificate presence and fingerprint available.

use std::net::IpAddr;

use anyhow::bail;
use rustls::pki_types::CertificateDer;

use crate::waf::metadata::WafClientCertificateMetadata;

pub(crate) fn client_certificate_metadata(
  certificates: &[CertificateDer<'_>],
) -> Option<WafClientCertificateMetadata> {
  let leaf = certificates.first()?;
  let fingerprint_sha256 = sha256_hex(leaf.as_ref());
  let parsed = parse_certificate_names(leaf.as_ref()).ok();
  Some(WafClientCertificateMetadata {
    fingerprint_sha256,
    subject_common_names: parsed
      .as_ref()
      .map(|names| names.subject_common_names.clone())
      .unwrap_or_default(),
    san_dns_names: parsed
      .as_ref()
      .map(|names| names.san_dns_names.clone())
      .unwrap_or_default(),
    san_ip_addresses: parsed
      .map(|names| names.san_ip_addresses)
      .unwrap_or_default(),
  })
}

#[derive(Debug, Default)]
struct CertificateNames {
  subject_common_names: Vec<String>,
  san_dns_names: Vec<String>,
  san_ip_addresses: Vec<String>,
}

fn parse_certificate_names(der: &[u8]) -> anyhow::Result<CertificateNames> {
  let cert = DerReader::single(der, 0x30)?;
  let tbs = DerReader::single(cert, 0x30)?;
  let mut reader = DerReader::new(tbs);
  if reader.peek_tag() == Some(0xa0) {
    reader.read_any()?;
  }
  reader.read_any()?; // serialNumber
  reader.read_any()?; // signature
  reader.read_any()?; // issuer
  reader.read_any()?; // validity
  let subject = reader.read(0x30)?;
  let mut names = CertificateNames::default();
  parse_subject_common_names(subject, &mut names)?;
  reader.read_any()?; // subjectPublicKeyInfo
  while !reader.is_empty() {
    let (tag, value) = reader.read_any()?;
    if tag == 0xa3 {
      parse_extensions(value, &mut names)?;
    }
  }
  Ok(names)
}

fn parse_subject_common_names(value: &[u8], names: &mut CertificateNames) -> anyhow::Result<()> {
  let mut reader = DerReader::new(value);
  while !reader.is_empty() {
    let relative_distinguished_name = reader.read(0x31)?;
    let mut rdn_reader = DerReader::new(relative_distinguished_name);
    while !rdn_reader.is_empty() {
      let attribute = rdn_reader.read(0x30)?;
      let mut attribute_reader = DerReader::new(attribute);
      let oid = attribute_reader.read(0x06)?;
      let (tag, value) = attribute_reader.read_any()?;
      if oid == [0x55, 0x04, 0x03]
        && let Some(common_name) = parse_directory_string(tag, value)
      {
        names.subject_common_names.push(common_name);
      }
    }
  }
  Ok(())
}

fn parse_extensions(value: &[u8], names: &mut CertificateNames) -> anyhow::Result<()> {
  let extensions = DerReader::single(value, 0x30)?;
  let mut reader = DerReader::new(extensions);
  while !reader.is_empty() {
    let extension = reader.read(0x30)?;
    let mut extension_reader = DerReader::new(extension);
    let oid = extension_reader.read(0x06)?;
    if extension_reader.peek_tag() == Some(0x01) {
      extension_reader.read_any()?;
    }
    let extn_value = extension_reader.read(0x04)?;
    if oid == [0x55, 0x1d, 0x11] {
      parse_subject_alt_names(extn_value, names)?;
    }
  }
  Ok(())
}

fn parse_subject_alt_names(value: &[u8], names: &mut CertificateNames) -> anyhow::Result<()> {
  let names_der = DerReader::single(value, 0x30)?;
  let mut reader = DerReader::new(names_der);
  while !reader.is_empty() {
    let (tag, value) = reader.read_any()?;
    match tag {
      0x82 => {
        if let Ok(name) = std::str::from_utf8(value) {
          names.san_dns_names.push(name.to_ascii_lowercase());
        }
      }
      0x87 => match value {
        [a, b, c, d] => names
          .san_ip_addresses
          .push(IpAddr::from([*a, *b, *c, *d]).to_string()),
        bytes if bytes.len() == 16 => {
          let mut octets = [0_u8; 16];
          octets.copy_from_slice(bytes);
          names
            .san_ip_addresses
            .push(IpAddr::from(octets).to_string());
        }
        _ => {}
      },
      _ => {}
    }
  }
  Ok(())
}

fn parse_directory_string(tag: u8, value: &[u8]) -> Option<String> {
  match tag {
    0x0c | 0x13 | 0x16 => std::str::from_utf8(value).ok().map(str::to_string),
    _ => None,
  }
}

#[derive(Clone, Copy)]
struct DerReader<'a> {
  input: &'a [u8],
}

impl<'a> DerReader<'a> {
  fn new(input: &'a [u8]) -> Self {
    Self { input }
  }

  fn single(input: &'a [u8], expected_tag: u8) -> anyhow::Result<&'a [u8]> {
    let mut reader = Self::new(input);
    let value = reader.read(expected_tag)?;
    if !reader.is_empty() {
      bail!("trailing DER data");
    }
    Ok(value)
  }

  fn is_empty(&self) -> bool {
    self.input.is_empty()
  }

  fn peek_tag(&self) -> Option<u8> {
    self.input.first().copied()
  }

  fn read(&mut self, expected_tag: u8) -> anyhow::Result<&'a [u8]> {
    let (tag, value) = self.read_any()?;
    if tag != expected_tag {
      bail!("unexpected DER tag {tag:#x}, expected {expected_tag:#x}");
    }
    Ok(value)
  }

  fn read_any(&mut self) -> anyhow::Result<(u8, &'a [u8])> {
    let Some((&tag, rest)) = self.input.split_first() else {
      bail!("unexpected end of DER data");
    };
    let (len, rest) = parse_der_len(rest)?;
    if rest.len() < len {
      bail!("truncated DER value");
    }
    let (value, remaining) = rest.split_at(len);
    self.input = remaining;
    Ok((tag, value))
  }
}

fn parse_der_len(input: &[u8]) -> anyhow::Result<(usize, &[u8])> {
  let Some((&first, rest)) = input.split_first() else {
    bail!("missing DER length");
  };
  if first & 0x80 == 0 {
    return Ok((usize::from(first), rest));
  }
  let len_len = usize::from(first & 0x7f);
  if len_len == 0 || len_len > std::mem::size_of::<usize>() || rest.len() < len_len {
    bail!("invalid DER length");
  }
  let mut len = 0_usize;
  for byte in &rest[..len_len] {
    len = (len << 8) | usize::from(*byte);
  }
  Ok((len, &rest[len_len..]))
}

fn sha256_hex(bytes: &[u8]) -> String {
  hex_encode(&crate::crypto::sha256(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[cfg(test)]
mod tests {
  use rustls::pki_types::CertificateDer;

  use super::*;

  #[test]
  fn client_certificate_metadata_keeps_fingerprint_when_parse_fails() {
    let cert = CertificateDer::from(vec![0_u8, 1, 2]);
    let metadata = client_certificate_metadata(&[cert]).expect("certificate should be present");

    assert_eq!(metadata.fingerprint_sha256.len(), 64);
    assert!(metadata.subject_common_names.is_empty());
    assert!(metadata.san_dns_names.is_empty());
    assert!(metadata.san_ip_addresses.is_empty());
  }
}
