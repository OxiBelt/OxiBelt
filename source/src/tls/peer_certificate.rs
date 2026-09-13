//! Bounded descriptive projection of a verified peer leaf certificate.
//!
//! This parser never retains DER. It is deliberately separate from certificate
//! verification and the legacy routing metadata extractor.

use std::net::IpAddr;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Tag, Tagged};

/// Bounded, immutable-by-convention names captured from one verified peer leaf.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PeerCertificateNames {
  pub values: Vec<String>,
  pub is_truncated: bool,
}

/// Descriptive certificate evidence; it does not replace TLS verification.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PeerCertificateMetadata {
  pub fingerprint_sha256: String,
  pub parse_complete: bool,
  pub subject_common_names: PeerCertificateNames,
  pub san_dns_names: PeerCertificateNames,
  pub san_ip_addresses: PeerCertificateNames,
  pub san_uri_names: PeerCertificateNames,
  pub san_email_addresses: PeerCertificateNames,
}

const MAX_DER_BYTES: usize = 64 * 1024;
const MAX_NAMES: usize = 256;
const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
enum NameKind {
  SubjectCommonName,
  Dns,
  Ip,
  Uri,
  Email,
}

/// Projects bounded descriptive evidence from the first certificate in a peer chain.
///
/// Callers must only use this after the TLS stack has accepted the peer certificate.
/// The projection is descriptive and cannot make an unverified certificate trusted.
pub(crate) fn peer_certificate_metadata(
  certificates: &[CertificateDer<'_>],
) -> Option<Arc<PeerCertificateMetadata>> {
  let leaf = certificates.first()?;
  let mut collector = NameCollector::new(sha256_hex(leaf.as_ref()));

  if leaf.as_ref().len() > MAX_DER_BYTES {
    collector.fail_all();
    return Some(Arc::new(collector.finish()));
  }

  let Ok(certificate) = Certificate::from_der(leaf.as_ref()) else {
    collector.fail_all();
    return Some(Arc::new(collector.finish()));
  };

  collector.collect_subject_common_names(&certificate);
  if let Some(extensions) = certificate.tbs_certificate().extensions() {
    for extension in extensions {
      if extension.extn_id.to_string() == "2.5.29.17"
        && collector
          .collect_subject_alt_names(extension.extn_value.as_bytes())
          .is_err()
      {
        collector.fail_all();
        break;
      }
    }
  }

  Some(Arc::new(collector.finish()))
}

struct NameCollector {
  metadata: PeerCertificateMetadata,
  names: usize,
  text_bytes: usize,
}

impl NameCollector {
  fn new(fingerprint_sha256: String) -> Self {
    Self {
      metadata: PeerCertificateMetadata {
        fingerprint_sha256,
        parse_complete: true,
        ..PeerCertificateMetadata::default()
      },
      names: 0,
      text_bytes: 0,
    }
  }

  fn finish(self) -> PeerCertificateMetadata {
    self.metadata
  }

  fn collect_subject_common_names(&mut self, certificate: &Certificate) {
    for attribute in certificate.tbs_certificate().subject().iter() {
      if attribute.oid.to_string() == "2.5.4.3" {
        match directory_string(attribute.value.tag(), attribute.value.value()) {
          Some(value) => self.capture(NameKind::SubjectCommonName, value),
          None => self.fail(NameKind::SubjectCommonName),
        }
      }
    }
  }

  fn collect_subject_alt_names(&mut self, extension_value: &[u8]) -> Result<(), ()> {
    let names = DerReader::single(extension_value, 0x30)?;
    let mut reader = DerReader::new(names);
    while !reader.is_empty() {
      let (tag, value) = reader.read_any()?;
      match tag {
        // rfc822Name, dNSName, uniformResourceIdentifier, and iPAddress are
        // IMPLICIT context-specific GeneralName values.
        0x81 => match ia5_string(value) {
          Some(email) => self.capture(NameKind::Email, email),
          None => self.fail(NameKind::Email),
        },
        0x82 => match ia5_string(value) {
          Some(dns_name) => self.capture(NameKind::Dns, dns_name.to_ascii_lowercase()),
          None => self.fail(NameKind::Dns),
        },
        0x86 => match ia5_string(value) {
          Some(uri) => self.capture(NameKind::Uri, uri),
          None => self.fail(NameKind::Uri),
        },
        0x87 => match ip_address(value) {
          Some(address) => self.capture(NameKind::Ip, address.to_string()),
          None => self.fail(NameKind::Ip),
        },
        // Recognized GeneralName tags must use their required primitive form.
        0xa1 => self.fail(NameKind::Email),
        0xa2 => self.fail(NameKind::Dns),
        0xa6 => self.fail(NameKind::Uri),
        0xa7 => self.fail(NameKind::Ip),
        // Other GeneralName forms intentionally have no projection.
        _ => {}
      }
    }
    Ok(())
  }

  fn capture(&mut self, kind: NameKind, value: String) {
    if self.names >= MAX_NAMES
      || self
        .text_bytes
        .checked_add(value.len())
        .is_none_or(|total| total > MAX_TEXT_BYTES)
    {
      // Both budgets are global, so any later recognized name could be omitted.
      self.fail_all();
      return;
    }

    self.names += 1;
    self.text_bytes += value.len();
    self.names_for(kind).values.push(value);
  }

  fn fail(&mut self, kind: NameKind) {
    self.metadata.parse_complete = false;
    self.names_for(kind).is_truncated = true;
  }

  fn fail_all(&mut self) {
    self.metadata.parse_complete = false;
    self.metadata.subject_common_names.is_truncated = true;
    self.metadata.san_dns_names.is_truncated = true;
    self.metadata.san_ip_addresses.is_truncated = true;
    self.metadata.san_uri_names.is_truncated = true;
    self.metadata.san_email_addresses.is_truncated = true;
  }

  fn names_for(&mut self, kind: NameKind) -> &mut PeerCertificateNames {
    match kind {
      NameKind::SubjectCommonName => &mut self.metadata.subject_common_names,
      NameKind::Dns => &mut self.metadata.san_dns_names,
      NameKind::Ip => &mut self.metadata.san_ip_addresses,
      NameKind::Uri => &mut self.metadata.san_uri_names,
      NameKind::Email => &mut self.metadata.san_email_addresses,
    }
  }
}

fn directory_string(tag: Tag, value: &[u8]) -> Option<String> {
  match tag {
    Tag::Utf8String => std::str::from_utf8(value).ok().map(str::to_string),
    Tag::PrintableString => printable_string(value),
    // T.61 has no unambiguous Unicode mapping. ASCII is its lossless subset.
    Tag::TeletexString => ia5_string(value),
    Tag::BmpString => bmp_string(value),
    // The historical extractor accepts IA5 common names. Preserve that
    // compatibility only when the bytes are valid IA5 text.
    Tag::Ia5String => ia5_string(value),
    _ => None,
  }
  .filter(|value| !value.is_empty())
}

fn printable_string(value: &[u8]) -> Option<String> {
  value
    .iter()
    .all(|byte| {
      byte.is_ascii_alphanumeric()
        || matches!(
          byte,
          b' ' | b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
    })
    .then(|| std::str::from_utf8(value).ok().map(str::to_string))
    .flatten()
}

fn bmp_string(value: &[u8]) -> Option<String> {
  value.len().is_multiple_of(2).then_some(())?;
  let units = value
    .chunks_exact(2)
    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    .collect::<Vec<_>>();
  String::from_utf16(&units).ok()
}

fn ia5_string(value: &[u8]) -> Option<String> {
  value
    .iter()
    .all(u8::is_ascii)
    .then(|| std::str::from_utf8(value).ok().map(str::to_string))
    .flatten()
    .filter(|value| !value.is_empty())
}

fn ip_address(value: &[u8]) -> Option<IpAddr> {
  match value {
    [a, b, c, d] => Some(IpAddr::from([*a, *b, *c, *d])),
    bytes if bytes.len() == 16 => {
      let mut octets = [0_u8; 16];
      octets.copy_from_slice(bytes);
      Some(IpAddr::from(octets))
    }
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

  fn single(input: &'a [u8], expected_tag: u8) -> Result<&'a [u8], ()> {
    let mut reader = Self::new(input);
    let value = reader.read(expected_tag)?;
    reader.is_empty().then_some(value).ok_or(())
  }

  fn is_empty(&self) -> bool {
    self.input.is_empty()
  }

  fn read(&mut self, expected_tag: u8) -> Result<&'a [u8], ()> {
    let (tag, value) = self.read_any()?;
    (tag == expected_tag).then_some(value).ok_or(())
  }

  fn read_any(&mut self) -> Result<(u8, &'a [u8]), ()> {
    let Some((&tag, rest)) = self.input.split_first() else {
      return Err(());
    };
    let (length, rest) = parse_der_length(rest)?;
    let Some(value) = rest.get(..length) else {
      return Err(());
    };
    self.input = &rest[length..];
    Ok((tag, value))
  }
}

fn parse_der_length(input: &[u8]) -> Result<(usize, &[u8]), ()> {
  let Some((&first, rest)) = input.split_first() else {
    return Err(());
  };
  if first & 0x80 == 0 {
    return Ok((usize::from(first), rest));
  }

  let length_bytes = usize::from(first & 0x7f);
  if length_bytes == 0 || length_bytes > std::mem::size_of::<usize>() || rest.len() < length_bytes {
    return Err(());
  }
  if rest[0] == 0 {
    return Err(());
  }

  let mut length = 0_usize;
  for byte in &rest[..length_bytes] {
    length = length.checked_shl(8).ok_or(())? | usize::from(*byte);
  }
  (length >= 128)
    .then_some((length, &rest[length_bytes..]))
    .ok_or(())
}

fn sha256_hex(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let digest = crate::crypto::sha256(bytes);
  let mut output = String::with_capacity(digest.len() * 2);
  for byte in digest {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::path::Path;
  use std::process::{Command, Stdio};

  use rustls::pki_types::pem::PemObject;
  use sha2::{Digest, Sha256};

  use super::*;

  #[allow(dead_code)]
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn projects_generated_certificate_names_and_leaf_hash() {
    let temp_dir = common::TempDir::new("peer-certificate-projection");
    let certificate = generated_certificate(
      temp_dir.path(),
      "[alt_names]\nDNS.1 = Client.EXAMPLE.test\nIP.1 = 127.0.0.1\nIP.2 = 2001:db8::1\nURI.1 = spiffe://example.test/ns/edge\nemail.1 = operator@example.test\n",
    );

    let metadata =
      peer_certificate_metadata(std::slice::from_ref(&certificate)).expect("leaf exists");

    assert_eq!(
      metadata.fingerprint_sha256,
      Sha256::digest(certificate.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    );
    assert!(metadata.parse_complete);
    assert_eq!(
      metadata.subject_common_names.values,
      vec![
        "client.example.test".to_string(),
        "backup.example.test".to_string(),
      ]
    );
    assert_eq!(
      metadata.san_dns_names.values,
      vec!["client.example.test".to_string()]
    );
    assert_eq!(
      metadata.san_ip_addresses.values,
      vec!["127.0.0.1".to_string(), "2001:db8::1".to_string()]
    );
    assert_eq!(
      metadata.san_uri_names.values,
      vec!["spiffe://example.test/ns/edge".to_string()]
    );
    assert_eq!(
      metadata.san_email_addresses.values,
      vec!["operator@example.test".to_string()]
    );
  }

  #[test]
  fn keeps_hash_and_marks_all_lists_incomplete_for_malformed_or_oversized_leaf() {
    for leaf in [
      CertificateDer::from(vec![0_u8, 1, 2]),
      CertificateDer::from(vec![0_u8; MAX_DER_BYTES + 1]),
    ] {
      let metadata = peer_certificate_metadata(std::slice::from_ref(&leaf)).expect("leaf exists");
      assert_eq!(metadata.fingerprint_sha256, sha256_hex(leaf.as_ref()));
      assert!(!metadata.parse_complete);
      assert!(metadata.subject_common_names.values.is_empty());
      assert!(metadata.subject_common_names.is_truncated);
      assert!(metadata.san_dns_names.is_truncated);
      assert!(metadata.san_ip_addresses.is_truncated);
      assert!(metadata.san_uri_names.is_truncated);
      assert!(metadata.san_email_addresses.is_truncated);
    }
  }

  #[test]
  fn bounds_total_captured_names_without_retaining_the_overflow() {
    let temp_dir = common::TempDir::new("peer-certificate-projection-bounds");
    let mut names = String::from("[alt_names]\n");
    for number in 1..=MAX_NAMES + 1 {
      names.push_str(&format!("DNS.{number} = name-{number}.example.test\n"));
    }
    let certificate = generated_certificate(temp_dir.path(), &names);

    let metadata = peer_certificate_metadata(&[certificate]).expect("leaf exists");

    assert!(!metadata.parse_complete);
    // Both subject common names share the same total name budget.
    assert_eq!(metadata.san_dns_names.values.len(), MAX_NAMES - 2);
    assert!(metadata.san_dns_names.is_truncated);
    assert!(metadata.san_ip_addresses.is_truncated);
  }

  #[test]
  fn ignores_unknown_subject_alt_name_forms_but_marks_invalid_recognized_forms() {
    let mut collector = NameCollector::new("00".to_string());
    // dNSName("a") followed by an intentionally unprojected, constructed
    // otherName. Its payload need not be interpreted by this projection.
    collector
      .collect_subject_alt_names(&[0x30, 0x08, 0x82, 0x01, b'a', 0xa0, 0x03, 0x30, 0x01, 0x00])
      .expect("well-framed GeneralNames");
    assert!(collector.metadata.parse_complete);
    assert_eq!(
      collector.metadata.san_dns_names.values,
      vec!["a".to_string()]
    );

    let mut collector = NameCollector::new("00".to_string());
    collector
      .collect_subject_alt_names(&[0x30, 0x08, 0x82, 0x02, b'o', b'k', 0x82, 0x02, 0xff, 0xff])
      .expect("well-framed GeneralNames");
    assert!(!collector.metadata.parse_complete);
    assert_eq!(
      collector.metadata.san_dns_names.values,
      vec!["ok".to_string()]
    );
    assert!(collector.metadata.san_dns_names.is_truncated);
  }

  #[test]
  fn bounds_total_captured_text_without_dropping_the_prior_value() {
    let mut collector = NameCollector::new("00".to_string());
    collector.capture(NameKind::Dns, "a".repeat(MAX_TEXT_BYTES));
    collector.capture(NameKind::Email, "b".to_string());

    assert!(!collector.metadata.parse_complete);
    assert_eq!(collector.metadata.san_dns_names.values.len(), 1);
    assert!(collector.metadata.san_dns_names.is_truncated);
    assert!(collector.metadata.san_email_addresses.values.is_empty());
    assert!(collector.metadata.san_email_addresses.is_truncated);
  }

  fn generated_certificate(directory: &Path, alt_names: &str) -> CertificateDer<'static> {
    let config = directory.join("certificate.cnf");
    let certificate = directory.join("certificate.pem");
    let key = directory.join("certificate.key");
    fs::write(
      &config,
      format!(
        "[req]\ndistinguished_name = subject\nx509_extensions = extensions\nprompt = no\n\n[subject]\n0.CN = client.example.test\n1.CN = backup.example.test\n\n[extensions]\nsubjectAltName = @alt_names\nbasicConstraints = critical, CA:FALSE\n\n{alt_names}"
      ),
    )
    .expect("write OpenSSL config");
    let status = Command::new("openssl")
      .args([
        "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1", "-config",
      ])
      .arg(&config)
      .arg("-keyout")
      .arg(&key)
      .arg("-out")
      .arg(&certificate)
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .expect("spawn openssl");
    assert!(status.success(), "openssl failed with {status}");

    let pem = fs::read(certificate).expect("read certificate");
    CertificateDer::pem_slice_iter(&pem)
      .next()
      .expect("certificate PEM exists")
      .expect("certificate PEM parses")
  }
}
