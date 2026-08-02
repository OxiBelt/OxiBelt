//! Lightweight client certificate metadata extraction for routing and WAF policy.
//! Parsing failures keep certificate presence and fingerprint available.

use std::net::IpAddr;

use anyhow::bail;
use rustls::pki_types::CertificateDer;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Tag, Tagged};

use crate::waf::metadata::WafClientCertificateMetadata;

#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedCertificateMetadata {
  pub(crate) not_before_unix_seconds: i64,
  pub(crate) not_after_unix_seconds: i64,
  pub(crate) subject_common_names: Vec<String>,
  pub(crate) san_dns_names: Vec<String>,
  pub(crate) san_uri_names: Vec<String>,
  pub(crate) san_ip_addresses: Vec<IpAddr>,
}

/// Leaf-client-certificate evidence captured only after the TLS stack has verified it.
///
/// This type intentionally carries parsed SANs and a fingerprint rather than raw DER so
/// downstream authorization and audit code cannot accidentally retain certificate material.
#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum VerifiedClientCertificate {
  Parsed(VerifiedClientCertificateIdentity),
  Unparseable { fingerprint_sha256: String },
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VerifiedClientCertificateIdentity {
  pub(crate) fingerprint_sha256: String,
  pub(crate) san_dns_names: Vec<String>,
  pub(crate) san_uri_names: Vec<String>,
  pub(crate) spiffe_ids: Vec<String>,
}

/// Extracts identity evidence from a certificate chain that rustls has already accepted.
///
/// A malformed leaf is represented explicitly. Binding callers must treat it as a failed
/// identity assertion, while feature-disabled callers can preserve the existing TLS behavior.
#[cfg(feature = "admin-runtime")]
pub(crate) fn verified_client_certificate(
  certificates: &[CertificateDer<'_>],
) -> Option<VerifiedClientCertificate> {
  let leaf = certificates.first()?;
  let fingerprint_sha256 = sha256_hex(leaf.as_ref());
  let metadata = match parse_certificate_metadata(leaf.as_ref()) {
    Ok(metadata) => metadata,
    Err(_) => return Some(VerifiedClientCertificate::Unparseable { fingerprint_sha256 }),
  };
  let spiffe_ids = (metadata.san_uri_names.len() == 1)
    .then(|| metadata.san_uri_names.first())
    .flatten()
    .filter(|identity| is_canonical_spiffe_id(identity))
    .cloned()
    .into_iter()
    .collect();
  Some(VerifiedClientCertificate::Parsed(
    VerifiedClientCertificateIdentity {
      fingerprint_sha256,
      san_dns_names: metadata.san_dns_names,
      san_uri_names: metadata.san_uri_names,
      spiffe_ids,
    },
  ))
}

pub(crate) fn client_certificate_metadata(
  certificates: &[CertificateDer<'_>],
) -> Option<WafClientCertificateMetadata> {
  let leaf = certificates.first()?;
  let fingerprint_sha256 = sha256_hex(leaf.as_ref());
  let parsed = parse_certificate_metadata(leaf.as_ref()).ok();
  Some(WafClientCertificateMetadata {
    fingerprint_sha256,
    subject_common_names: parsed
      .as_ref()
      .map(|metadata| metadata.subject_common_names.clone())
      .unwrap_or_default(),
    san_dns_names: parsed
      .as_ref()
      .map(|metadata| metadata.san_dns_names.clone())
      .unwrap_or_default(),
    san_ip_addresses: parsed
      .map(|metadata| {
        metadata
          .san_ip_addresses
          .into_iter()
          .map(|address| address.to_string())
          .collect()
      })
      .unwrap_or_default(),
  })
}

pub(crate) fn parse_certificate_metadata(der: &[u8]) -> anyhow::Result<ParsedCertificateMetadata> {
  let cert = Certificate::from_der(der)?;
  let validity = cert.tbs_certificate().validity();
  let mut metadata = ParsedCertificateMetadata {
    not_before_unix_seconds: unix_seconds(validity.not_before),
    not_after_unix_seconds: unix_seconds(validity.not_after),
    subject_common_names: subject_common_names(&cert),
    san_dns_names: Vec::new(),
    san_uri_names: Vec::new(),
    san_ip_addresses: Vec::new(),
  };
  if let Some(extensions) = cert.tbs_certificate().extensions() {
    for extension in extensions {
      if extension.extn_id.to_string() == "2.5.29.17" {
        collect_subject_alt_names(extension.extn_value.as_bytes(), &mut metadata)?;
      }
    }
  }
  Ok(metadata)
}

fn unix_seconds(time: x509_cert::time::Time) -> i64 {
  let seconds = time.to_unix_duration().as_secs();
  seconds.min(i64::MAX as u64) as i64
}

fn subject_common_names(cert: &Certificate) -> Vec<String> {
  cert
    .tbs_certificate()
    .subject()
    .iter()
    .filter_map(|attribute| {
      (attribute.oid.to_string() == "2.5.4.3")
        .then(|| directory_string_to_string(&attribute.value))
        .flatten()
    })
    .collect()
}

fn directory_string_to_string(value: &x509_cert::attr::AttributeValue) -> Option<String> {
  matches!(
    value.tag(),
    Tag::Utf8String | Tag::PrintableString | Tag::TeletexString | Tag::Ia5String
  )
  .then(|| std::str::from_utf8(value.value()).ok().map(str::to_string))
  .flatten()
}

fn collect_subject_alt_names(
  extension_value: &[u8],
  metadata: &mut ParsedCertificateMetadata,
) -> anyhow::Result<()> {
  let names = DerReader::single(extension_value, 0x30)?;
  let mut reader = DerReader::new(names);
  while !reader.is_empty() {
    let (tag, value) = reader.read_any()?;
    match tag {
      0x86 => {
        if let Ok(uri) = std::str::from_utf8(value) {
          metadata.san_uri_names.push(uri.to_string());
        }
      }
      0x82 => {
        if let Ok(name) = std::str::from_utf8(value) {
          metadata.san_dns_names.push(name.to_ascii_lowercase());
        }
      }
      0x87 => match value {
        [a, b, c, d] => metadata
          .san_ip_addresses
          .push(IpAddr::from([*a, *b, *c, *d])),
        bytes if bytes.len() == 16 => {
          let mut octets = [0_u8; 16];
          octets.copy_from_slice(bytes);
          metadata.san_ip_addresses.push(IpAddr::from(octets));
        }
        _ => {}
      },
      _ => {}
    }
  }
  Ok(())
}

#[cfg(feature = "admin-runtime")]
fn is_canonical_spiffe_id(value: &str) -> bool {
  const PREFIX: &str = "spiffe://";
  if value.len() > 2048 || !value.starts_with(PREFIX) || value.contains('%') {
    return false;
  }
  let rest = &value[PREFIX.len()..];
  let Some((trust_domain, path)) = rest.split_once('/') else {
    return false;
  };
  if trust_domain.is_empty()
    || trust_domain != trust_domain.to_ascii_lowercase()
    || !trust_domain.bytes().all(|byte| {
      byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    })
    || path.is_empty()
    || path.ends_with('/')
    || value.contains('?')
    || value.contains('#')
    || value.contains('@')
    || trust_domain.contains(':')
  {
    return false;
  }
  path.split('/').all(|segment| {
    !segment.is_empty()
      && !matches!(segment, "." | "..")
      && segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
  })
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
  use std::fs;
  use std::path::{Path, PathBuf};
  use std::process::{Command, Stdio};

  use rustls::pki_types::CertificateDer;
  use rustls::pki_types::pem::PemObject;

  use super::*;

  #[allow(dead_code)]
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn client_certificate_metadata_extracts_x509_names() {
    let temp_dir = common::TempDir::new("client-cert-metadata");
    let (cert_path, _key_path) = create_self_signed_cert_with_ip_san(temp_dir.path());
    let cert = first_pem_certificate(&cert_path);

    let metadata = client_certificate_metadata(&[cert]).expect("certificate should be present");

    assert_eq!(metadata.fingerprint_sha256.len(), 64);
    assert_eq!(metadata.subject_common_names, vec!["client.example.test"]);
    assert_eq!(metadata.san_dns_names, vec!["client.example.test"]);
    assert_eq!(metadata.san_ip_addresses, vec!["127.0.0.1", "2001:db8::1"]);
  }

  #[test]
  fn client_certificate_metadata_keeps_fingerprint_when_parse_fails() {
    let cert = CertificateDer::from(vec![0_u8, 1, 2]);
    let metadata = client_certificate_metadata(&[cert]).expect("certificate should be present");

    assert_eq!(metadata.fingerprint_sha256.len(), 64);
    assert!(metadata.subject_common_names.is_empty());
    assert!(metadata.san_dns_names.is_empty());
    assert!(metadata.san_ip_addresses.is_empty());
  }

  #[test]
  #[cfg(feature = "admin-runtime")]
  fn verified_client_certificate_extracts_a_single_canonical_spiffe_id() {
    let temp_dir = common::TempDir::new("verified-client-spiffe");
    let (cert_path, _key_path) = create_self_signed_cert_with_uri_san(
      temp_dir.path(),
      "spiffe://example.test/ns/edge/sa/controller",
    );
    let cert = first_pem_certificate(&cert_path);

    let VerifiedClientCertificate::Parsed(identity) =
      verified_client_certificate(&[cert]).expect("certificate should be present")
    else {
      panic!("certificate should parse into workload identity evidence");
    };

    assert_eq!(identity.san_dns_names, vec!["client.example.test"]);
    assert_eq!(
      identity.san_uri_names,
      vec!["spiffe://example.test/ns/edge/sa/controller"]
    );
    assert_eq!(
      identity.spiffe_ids,
      vec!["spiffe://example.test/ns/edge/sa/controller"]
    );
    assert_eq!(identity.fingerprint_sha256.len(), 64);
  }

  #[test]
  fn certificate_metadata_extracts_uri_subject_alt_names_without_admin_runtime() {
    let temp_dir = common::TempDir::new("certificate-uri-san-metadata");
    let expected = "spiffe://example.test/ns/edge/sa/backend";
    let (cert_path, _key_path) = create_self_signed_cert_with_uri_san(temp_dir.path(), expected);
    let cert = first_pem_certificate(&cert_path);

    let metadata =
      parse_certificate_metadata(cert.as_ref()).expect("certificate metadata should parse");

    assert_eq!(metadata.san_uri_names, vec![expected]);
  }

  fn first_pem_certificate(path: &Path) -> CertificateDer<'static> {
    let bytes = fs::read(path).expect("certificate should be readable");
    CertificateDer::pem_slice_iter(&bytes)
      .next()
      .expect("certificate PEM should contain a certificate")
      .expect("certificate PEM should parse")
  }

  fn create_self_signed_cert_with_ip_san(dir: &Path) -> (PathBuf, PathBuf) {
    let key_path = dir.join("client-ip-san.key");
    let cert_path = dir.join("client-ip-san.pem");
    let config_path = dir.join("client-ip-san.cnf");
    fs::write(
      &config_path,
      r#"[req]
distinguished_name = req_distinguished_name
x509_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = client.example.test

[req_ext]
subjectAltName = @alt_names
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = client.example.test
IP.1 = 127.0.0.1
IP.2 = 2001:db8::1
"#,
    )
    .expect("failed to write certificate config");
    let status = Command::new("openssl")
      .args([
        "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1", "-config",
      ])
      .arg(&config_path)
      .arg("-keyout")
      .arg(&key_path)
      .arg("-out")
      .arg(&cert_path)
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .expect("failed to spawn openssl");
    assert!(status.success(), "openssl failed with status {status}");
    (cert_path, key_path)
  }

  fn create_self_signed_cert_with_uri_san(dir: &Path, uri: &str) -> (PathBuf, PathBuf) {
    let key_path = dir.join("client-uri-san.key");
    let cert_path = dir.join("client-uri-san.pem");
    let config_path = dir.join("client-uri-san.cnf");
    fs::write(
      &config_path,
      format!(
        r#"[req]
distinguished_name = req_distinguished_name
x509_extensions = req_ext
prompt = no

[req_distinguished_name]
CN = client.example.test

[req_ext]
subjectAltName = @alt_names
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth

[alt_names]
DNS.1 = client.example.test
URI.1 = {uri}
"#
      ),
    )
    .expect("failed to write certificate config");
    let status = Command::new("openssl")
      .args([
        "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1", "-config",
      ])
      .arg(&config_path)
      .arg("-keyout")
      .arg(&key_path)
      .arg("-out")
      .arg(&cert_path)
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .expect("failed to spawn openssl");
    assert!(status.success(), "openssl failed with status {status}");
    (cert_path, key_path)
  }
}
