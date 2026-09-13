//! PROXY protocol parsing for downstream peer identity.
//!
//! SSL TLVs are assertions made by a trusted PROXY peer. They never replace
//! locally verified TLS client-certificate evidence.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::config::{ProxyProtocolConfig, ProxyProtocolVersion};
use crate::identity::TrustedCidrs;
use crate::tls::PeerCertificateMetadata;

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V2_FIXED_HEADER_LEN: usize = 16;
const V2_IPV4_ADDRESS_LEN: usize = 12;
const V2_IPV6_ADDRESS_LEN: usize = 36;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const PP2_TYPE_SSL: u8 = 0x20;
const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
const PP2_SUBTYPE_SSL_CN: u8 = 0x22;
const PP2_SUBTYPE_SSL_CIPHER: u8 = 0x23;
const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24;
const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25;
const PP2_SUBTYPE_SSL_KEY_EXCHANGE_GROUP: u8 = 0x26;
const PP2_SUBTYPE_SSL_SIGNATURE_SCHEME: u8 = 0x27;
const PP2_SUBTYPE_SSL_CERT: u8 = 0x28;

#[derive(Clone)]
pub struct ProxyProtocolMetadata {
  pub version: ProxyProtocolVersion,
  pub source: SocketAddr,
  pub destination: Option<SocketAddr>,
  pub ssl: Option<Arc<ProxyProtocolSslMetadata>>,
}

impl ProxyProtocolMetadata {
  pub(crate) fn version_label(&self) -> Option<&'static str> {
    match self.version {
      ProxyProtocolVersion::V1 => Some("v1"),
      ProxyProtocolVersion::V2 => Some("v2"),
      ProxyProtocolVersion::Any => None,
    }
  }
}

impl fmt::Debug for ProxyProtocolMetadata {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ProxyProtocolMetadata")
      .field("version", &self.version)
      .field("source", &self.source)
      .field("destination", &self.destination)
      .field("has_ssl", &self.ssl.is_some())
      .finish()
  }
}

#[derive(Clone, Default, Eq, PartialEq)]
pub struct ProxyProtocolSslMetadata {
  pub client: u8,
  pub verify: u32,
  pub version: Option<String>,
  pub common_name: Option<String>,
  pub cipher_suite: Option<String>,
  pub certificate_signature_algorithm: Option<String>,
  pub certificate_key_algorithm: Option<String>,
  pub key_exchange_group: Option<String>,
  pub signature_scheme: Option<String>,
  pub certificate: Option<ProxyProtocolCertificate>,
}

impl fmt::Debug for ProxyProtocolSslMetadata {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ProxyProtocolSslMetadata")
      .field("client", &self.client)
      .field("verify", &self.verify)
      .field("has_certificate", &self.certificate.is_some())
      .finish_non_exhaustive()
  }
}

impl ProxyProtocolSslMetadata {
  /// Bounded parsed leaf evidence for WAF projection. Raw DER remains private
  /// to this module and explicit PROXY egress only.
  pub(crate) fn client_certificate_metadata(&self) -> Option<&Arc<PeerCertificateMetadata>> {
    self
      .certificate
      .as_ref()
      .map(|certificate| &certificate.metadata)
  }
}

/// Validated, bounded DER held only for explicit PROXY egress. The pre-parsed
/// projection is available inside the crate without exposing DER to WAF/logging.
#[derive(Clone)]
pub struct ProxyProtocolCertificate {
  der: Vec<u8>,
  metadata: Arc<PeerCertificateMetadata>,
}

impl ProxyProtocolCertificate {
  pub(crate) fn from_der(der: &[u8]) -> anyhow::Result<Self> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE_DER_BYTES {
      bail!(
        "PROXY protocol SSL certificate must be between 1 and {MAX_CERTIFICATE_DER_BYTES} bytes"
      );
    }
    Certificate::from_der(der).context("PROXY protocol SSL certificate is not valid DER")?;
    let metadata =
      crate::tls::peer_certificate_metadata(&[rustls::pki_types::CertificateDer::from(
        der.to_vec(),
      )])
      .context("validated PROXY protocol SSL certificate has no metadata")?;
    Ok(Self {
      der: der.to_vec(),
      metadata,
    })
  }

  pub(crate) fn der(&self) -> &[u8] {
    &self.der
  }
}

impl PartialEq for ProxyProtocolCertificate {
  fn eq(&self, other: &Self) -> bool {
    self.der == other.der
  }
}

impl Eq for ProxyProtocolCertificate {}

impl fmt::Debug for ProxyProtocolCertificate {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ProxyProtocolCertificate")
      .field("der", &"[redacted]")
      .finish()
  }
}

pub async fn accept_proxy_header(
  stream: TcpStream,
  peer_addr: SocketAddr,
  config: &ProxyProtocolConfig,
) -> anyhow::Result<(TcpStream, SocketAddr)> {
  let (stream, source, _) = accept_proxy_header_inner(stream, peer_addr, config, None).await?;
  Ok((stream, source))
}

/// Accept a header and, when `tls_tlvs` is enabled, retain typed metadata.
/// In that opt-in mode the timeout covers the complete header, including a
/// fragmented `any`-version prefix and TLVs. The disabled path is unchanged.
pub async fn accept_proxy_header_with_metadata(
  stream: TcpStream,
  peer_addr: SocketAddr,
  config: &ProxyProtocolConfig,
  timeout: Duration,
) -> anyhow::Result<(TcpStream, SocketAddr, Option<Arc<ProxyProtocolMetadata>>)> {
  accept_proxy_header_inner(stream, peer_addr, config, Some(timeout)).await
}

async fn accept_proxy_header_inner(
  mut stream: TcpStream,
  peer_addr: SocketAddr,
  config: &ProxyProtocolConfig,
  metadata_timeout: Option<Duration>,
) -> anyhow::Result<(TcpStream, SocketAddr, Option<Arc<ProxyProtocolMetadata>>)> {
  if !config.enabled {
    return Ok((stream, peer_addr, None));
  }
  let trusted = TrustedCidrs::parse(&config.trusted_sources)?;
  if !trusted.contains(peer_addr.ip()) {
    bail!("PROXY protocol peer {peer_addr} is not trusted");
  }
  let metadata_enabled = metadata_timeout.is_some() && config.tls_tlvs;
  let read = async {
    match config.version {
      ProxyProtocolVersion::V1 => Ok((read_v1(&mut stream).await?, None)),
      ProxyProtocolVersion::V2 => read_v2(&mut stream, metadata_enabled).await,
      ProxyProtocolVersion::Any if metadata_enabled => read_any_with_metadata(&mut stream).await,
      ProxyProtocolVersion::Any => {
        // Existing address-only path intentionally retains its historical peek behavior.
        let mut peek = [0u8; 12];
        stream
          .peek(&mut peek)
          .await
          .context("failed to peek PROXY protocol header")?;
        if &peek == V2_SIGNATURE {
          read_v2(&mut stream, false).await
        } else {
          Ok((read_v1(&mut stream).await?, None))
        }
      }
    }
  };
  let (source, metadata) = match metadata_timeout.filter(|_| metadata_enabled) {
    Some(timeout) => tokio::time::timeout(timeout, read)
      .await
      .context("PROXY protocol header timed out")??,
    None => read.await?,
  };
  Ok((stream, source, metadata.map(Arc::new)))
}

async fn read_any_with_metadata(
  stream: &mut TcpStream,
) -> anyhow::Result<(SocketAddr, Option<ProxyProtocolMetadata>)> {
  let mut prefix = [0u8; 12];
  stream
    .read_exact(&mut prefix)
    .await
    .context("failed to read PROXY protocol header")?;
  if &prefix == V2_SIGNATURE {
    read_v2_after_signature(stream, true).await
  } else {
    let source = read_v1_with_prefix(stream, &prefix).await?;
    Ok((
      source,
      Some(ProxyProtocolMetadata {
        version: ProxyProtocolVersion::V1,
        source,
        destination: None,
        ssl: None,
      }),
    ))
  }
}

async fn read_v1(stream: &mut TcpStream) -> anyhow::Result<SocketAddr> {
  read_v1_with_prefix(stream, &[]).await
}

async fn read_v1_with_prefix(stream: &mut TcpStream, prefix: &[u8]) -> anyhow::Result<SocketAddr> {
  let mut line = prefix.to_vec();
  loop {
    if line.len() > 107 {
      bail!("PROXY protocol v1 header is too long");
    }
    if line.last() == Some(&b'\n') {
      break;
    }
    let mut byte = [0u8; 1];
    stream
      .read_exact(&mut byte)
      .await
      .context("failed to read PROXY protocol v1 header")?;
    line.push(byte[0]);
  }
  let line = std::str::from_utf8(&line)
    .context("PROXY protocol v1 header is not UTF-8")?
    .trim_end_matches(['\r', '\n']);
  let parts = line.split_whitespace().collect::<Vec<_>>();
  if parts.len() != 6 || parts[0] != "PROXY" || parts[1] == "UNKNOWN" {
    bail!("invalid PROXY protocol v1 header");
  }
  let source_ip: IpAddr = parts[2].parse().context("invalid PROXY source IP")?;
  let source_port: u16 = parts[4].parse().context("invalid PROXY source port")?;
  Ok(SocketAddr::new(source_ip, source_port))
}

async fn read_v2(
  stream: &mut TcpStream,
  parse_ssl_tlvs: bool,
) -> anyhow::Result<(SocketAddr, Option<ProxyProtocolMetadata>)> {
  let mut signature = [0u8; 12];
  stream
    .read_exact(&mut signature)
    .await
    .context("failed to read PROXY protocol v2 signature")?;
  if &signature != V2_SIGNATURE {
    bail!("invalid PROXY protocol v2 signature");
  }
  read_v2_after_signature(stream, parse_ssl_tlvs).await
}

async fn read_v2_after_signature(
  stream: &mut TcpStream,
  parse_ssl_tlvs: bool,
) -> anyhow::Result<(SocketAddr, Option<ProxyProtocolMetadata>)> {
  let mut tail = [0u8; V2_FIXED_HEADER_LEN - V2_SIGNATURE.len()];
  stream
    .read_exact(&mut tail)
    .await
    .context("failed to read PROXY protocol v2 header")?;
  let mut payload = vec![0u8; u16::from_be_bytes([tail[2], tail[3]]) as usize];
  stream
    .read_exact(&mut payload)
    .await
    .context("failed to read PROXY protocol v2 payload")?;
  parse_v2_payload(tail[0], tail[1], &payload, parse_ssl_tlvs)
}

/// Pure v2 payload parser. It only parses SSL TLVs when asked, retaining the
/// previous behavior of ignoring all trailing bytes in address-only mode.
pub(crate) fn parse_v2_payload(
  version_command: u8,
  family_transport: u8,
  payload: &[u8],
  parse_ssl_tlvs: bool,
) -> anyhow::Result<(SocketAddr, Option<ProxyProtocolMetadata>)> {
  if version_command >> 4 != 2 || version_command & 0x0f != 1 {
    bail!("invalid PROXY protocol v2 command");
  }
  if family_transport & 0x0f != 1 {
    bail!("PROXY protocol v2 only supports TCP");
  }
  let (source, destination, address_len) = match family_transport >> 4 {
    1 if payload.len() >= V2_IPV4_ADDRESS_LEN => {
      let source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
          payload[0], payload[1], payload[2], payload[3],
        )),
        u16::from_be_bytes([payload[8], payload[9]]),
      );
      let destination = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
          payload[4], payload[5], payload[6], payload[7],
        )),
        u16::from_be_bytes([payload[10], payload[11]]),
      );
      (source, destination, V2_IPV4_ADDRESS_LEN)
    }
    2 if payload.len() >= V2_IPV6_ADDRESS_LEN => {
      let mut source_octets = [0u8; 16];
      source_octets.copy_from_slice(&payload[..16]);
      let mut destination_octets = [0u8; 16];
      destination_octets.copy_from_slice(&payload[16..32]);
      let source = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(source_octets)),
        u16::from_be_bytes([payload[32], payload[33]]),
      );
      let destination = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(destination_octets)),
        u16::from_be_bytes([payload[34], payload[35]]),
      );
      (source, destination, V2_IPV6_ADDRESS_LEN)
    }
    _ => bail!("unsupported PROXY protocol v2 address family"),
  };
  let ssl = if parse_ssl_tlvs {
    decode_ssl_tlvs(&payload[address_len..])?
  } else {
    None
  };
  let metadata = parse_ssl_tlvs.then(|| ProxyProtocolMetadata {
    version: ProxyProtocolVersion::V2,
    source,
    destination: Some(destination),
    ssl: ssl.map(Arc::new),
  });
  Ok((source, metadata))
}

/// Drives the pure v2 decoder from arbitrary bytes for the standalone fuzz
/// target. No socket, configuration, or trusted-peer state is involved.
#[cfg(feature = "fuzzing")]
pub fn fuzz_parse_v2_payload(data: &[u8]) {
  let (version_command, rest) = data
    .split_first()
    .map_or((0, &[][..]), |(value, rest)| (*value, rest));
  let (family_transport, payload) = rest
    .split_first()
    .map_or((0, &[][..]), |(value, rest)| (*value, rest));
  let _ = parse_v2_payload(version_command, family_transport, payload, true);
}

/// Decode the *value* of a standard `PP2_TYPE_SSL` TLV: its five fixed bytes
/// followed by nested TLVs. The outer type and length are parsed by the caller.
pub fn decode_ssl_tlv(value: &[u8]) -> anyhow::Result<ProxyProtocolSslMetadata> {
  if value.len() < 5 {
    bail!("PROXY protocol SSL TLV is shorter than its fixed fields");
  }
  let mut metadata = ProxyProtocolSslMetadata {
    client: value[0],
    verify: u32::from_be_bytes([value[1], value[2], value[3], value[4]]),
    ..ProxyProtocolSslMetadata::default()
  };
  let mut offset = 5;
  while offset < value.len() {
    let (kind, nested) = read_tlv(value, &mut offset)?;
    match kind {
      PP2_SUBTYPE_SSL_VERSION => set_unique_text(&mut metadata.version, nested, "SSL version")?,
      PP2_SUBTYPE_SSL_CN => set_unique_text(&mut metadata.common_name, nested, "SSL common name")?,
      PP2_SUBTYPE_SSL_CIPHER => {
        set_unique_text(&mut metadata.cipher_suite, nested, "SSL cipher suite")?
      }
      PP2_SUBTYPE_SSL_SIG_ALG => set_unique_text(
        &mut metadata.certificate_signature_algorithm,
        nested,
        "SSL certificate signature algorithm",
      )?,
      PP2_SUBTYPE_SSL_KEY_ALG => set_unique_text(
        &mut metadata.certificate_key_algorithm,
        nested,
        "SSL certificate key algorithm",
      )?,
      PP2_SUBTYPE_SSL_KEY_EXCHANGE_GROUP => set_unique_text(
        &mut metadata.key_exchange_group,
        nested,
        "SSL key exchange group",
      )?,
      PP2_SUBTYPE_SSL_SIGNATURE_SCHEME => set_unique_text(
        &mut metadata.signature_scheme,
        nested,
        "SSL signature scheme",
      )?,
      PP2_SUBTYPE_SSL_CERT => {
        if metadata.certificate.is_some() {
          bail!("duplicate PROXY protocol SSL certificate TLV");
        }
        metadata.certificate = Some(ProxyProtocolCertificate::from_der(nested)?);
      }
      _ => {}
    }
  }
  Ok(metadata)
}

fn decode_ssl_tlvs(bytes: &[u8]) -> anyhow::Result<Option<ProxyProtocolSslMetadata>> {
  let mut offset = 0;
  let mut ssl = None;
  while offset < bytes.len() {
    let (kind, value) = read_tlv(bytes, &mut offset)?;
    if kind == PP2_TYPE_SSL {
      if ssl.is_some() {
        bail!("duplicate PROXY protocol SSL TLV");
      }
      ssl = Some(decode_ssl_tlv(value)?);
    }
  }
  Ok(ssl)
}

fn set_unique_text(slot: &mut Option<String>, value: &[u8], field: &str) -> anyhow::Result<()> {
  if slot.is_some() {
    bail!("duplicate PROXY protocol {field} TLV");
  }
  if value.is_empty() || value.contains(&0) {
    bail!("PROXY protocol {field} TLV must be non-empty UTF-8 without NUL bytes");
  }
  let value = std::str::from_utf8(value)
    .with_context(|| format!("PROXY protocol {field} TLV is not UTF-8"))?;
  if value.chars().any(char::is_control) {
    bail!("PROXY protocol {field} TLV contains a control character");
  }
  *slot = Some(value.to_owned());
  Ok(())
}

fn read_tlv<'a>(bytes: &'a [u8], offset: &mut usize) -> anyhow::Result<(u8, &'a [u8])> {
  if bytes.len().saturating_sub(*offset) < 3 {
    bail!("truncated PROXY protocol TLV header");
  }
  let kind = bytes[*offset];
  let length = u16::from_be_bytes([bytes[*offset + 1], bytes[*offset + 2]]) as usize;
  *offset += 3;
  let end = offset
    .checked_add(length)
    .context("PROXY protocol TLV length overflow")?;
  if end > bytes.len() {
    bail!("truncated PROXY protocol TLV value");
  }
  let value = &bytes[*offset..end];
  *offset = end;
  Ok((kind, value))
}

/// Encode the complete canonical outer SSL TLV for a v2 PROXY header.
pub fn encode_ssl_tlv(
  metadata: &ProxyProtocolSslMetadata,
  include_certificate: bool,
) -> anyhow::Result<Vec<u8>> {
  let mut value = Vec::with_capacity(5);
  value.push(metadata.client);
  value.extend_from_slice(&metadata.verify.to_be_bytes());
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_VERSION,
    metadata.version.as_deref(),
  )?;
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_CN,
    metadata.common_name.as_deref(),
  )?;
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_CIPHER,
    metadata.cipher_suite.as_deref(),
  )?;
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_SIG_ALG,
    metadata.certificate_signature_algorithm.as_deref(),
  )?;
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_KEY_ALG,
    metadata.certificate_key_algorithm.as_deref(),
  )?;
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_KEY_EXCHANGE_GROUP,
    metadata.key_exchange_group.as_deref(),
  )?;
  encode_optional_text(
    &mut value,
    PP2_SUBTYPE_SSL_SIGNATURE_SCHEME,
    metadata.signature_scheme.as_deref(),
  )?;
  if include_certificate && let Some(certificate) = &metadata.certificate {
    encode_tlv(&mut value, PP2_SUBTYPE_SSL_CERT, certificate.der())?;
  }
  let mut output = Vec::with_capacity(value.len() + 3);
  encode_tlv(&mut output, PP2_TYPE_SSL, &value)?;
  Ok(output)
}

fn encode_optional_text(output: &mut Vec<u8>, kind: u8, value: Option<&str>) -> anyhow::Result<()> {
  if let Some(value) = value {
    if value.is_empty() || value.contains('\0') || value.chars().any(char::is_control) {
      bail!("invalid PROXY protocol SSL text value");
    }
    encode_tlv(output, kind, value.as_bytes())?;
  }
  Ok(())
}

fn encode_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) -> anyhow::Result<()> {
  let length = u16::try_from(value.len()).context("PROXY protocol TLV exceeds 65535 bytes")?;
  output.push(kind);
  output.extend_from_slice(&length.to_be_bytes());
  output.extend_from_slice(value);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ssl_tlv_round_trip_is_canonical() {
    let metadata = ProxyProtocolSslMetadata {
      client: 7,
      verify: 42,
      version: Some("TLSv1.3".into()),
      cipher_suite: Some("TLS_AES_128_GCM_SHA256".into()),
      ..ProxyProtocolSslMetadata::default()
    };
    let wire = encode_ssl_tlv(&metadata, false).expect("encode");
    assert_eq!(decode_ssl_tlv(&wire[3..]).expect("decode"), metadata);
  }

  #[test]
  fn ssl_tlv_rejects_duplicate_and_truncated_nested_values() {
    let duplicate = [
      0,
      0,
      0,
      0,
      0,
      PP2_SUBTYPE_SSL_VERSION,
      0,
      1,
      b'a',
      PP2_SUBTYPE_SSL_VERSION,
      0,
      1,
      b'b',
    ];
    assert!(decode_ssl_tlv(&duplicate).is_err());
    let truncated = [0, 0, 0, 0, 0, PP2_SUBTYPE_SSL_VERSION, 0, 1];
    assert!(decode_ssl_tlv(&truncated).is_err());
  }

  #[test]
  fn ssl_tlv_decodes_each_standard_text_subtype_and_skips_unknown() {
    let mut value = vec![0x07, 0, 0, 0, 0];
    for (kind, text) in [
      (PP2_SUBTYPE_SSL_VERSION, "TLSv1.3"),
      (PP2_SUBTYPE_SSL_CN, "client.example"),
      (PP2_SUBTYPE_SSL_CIPHER, "TLS_AES_128_GCM_SHA256"),
      (PP2_SUBTYPE_SSL_SIG_ALG, "sha256WithRSAEncryption"),
      (PP2_SUBTYPE_SSL_KEY_ALG, "rsaEncryption"),
      (PP2_SUBTYPE_SSL_KEY_EXCHANGE_GROUP, "X25519"),
      (PP2_SUBTYPE_SSL_SIGNATURE_SCHEME, "rsa_pss_rsae_sha256"),
    ] {
      encode_tlv(&mut value, kind, text.as_bytes()).expect("nested text");
    }
    encode_tlv(&mut value, 0xee, b"ignored").expect("unknown TLV");
    let metadata = decode_ssl_tlv(&value).expect("decode standard fields");
    assert_eq!(metadata.client, 7);
    assert_eq!(metadata.verify, 0);
    assert_eq!(metadata.version.as_deref(), Some("TLSv1.3"));
    assert_eq!(metadata.common_name.as_deref(), Some("client.example"));
    assert_eq!(
      metadata.cipher_suite.as_deref(),
      Some("TLS_AES_128_GCM_SHA256")
    );
    assert_eq!(
      metadata.certificate_signature_algorithm.as_deref(),
      Some("sha256WithRSAEncryption")
    );
    assert_eq!(
      metadata.certificate_key_algorithm.as_deref(),
      Some("rsaEncryption")
    );
    assert_eq!(metadata.key_exchange_group.as_deref(), Some("X25519"));
    assert_eq!(
      metadata.signature_scheme.as_deref(),
      Some("rsa_pss_rsae_sha256")
    );
  }

  #[test]
  fn v2_payload_preserves_address_pair_and_skips_unknown_tlvs() {
    let mut payload = vec![192, 0, 2, 1, 198, 51, 100, 2, 0x12, 0x34, 0x01, 0xbb];
    payload.extend_from_slice(&[0xee, 0, 2, 1, 2]);
    let (source, metadata) = parse_v2_payload(0x21, 0x11, &payload, true).expect("parse");
    assert_eq!(source, "192.0.2.1:4660".parse().unwrap());
    assert_eq!(
      metadata.expect("metadata").destination,
      Some("198.51.100.2:443".parse().unwrap())
    );
  }

  #[test]
  fn address_only_mode_ignores_malformed_trailing_tlvs() {
    let mut payload = vec![192, 0, 2, 1, 198, 51, 100, 2, 0x12, 0x34, 0x01, 0xbb];
    payload.extend_from_slice(&[PP2_TYPE_SSL, 0, 8, 0]);
    assert!(parse_v2_payload(0x21, 0x11, &payload, false).is_ok());
    assert!(parse_v2_payload(0x21, 0x11, &payload, true).is_err());
  }
}

#[cfg(test)]
#[path = "proxy_protocol_tests.rs"]
mod socket_tests;
