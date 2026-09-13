//! Capture local TLS facts without promoting forwarded assertions to authentication evidence.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::CertificateDer;

use crate::config::ProxyProtocolVersion;
use crate::proxy_protocol::{
  ProxyProtocolCertificate, ProxyProtocolMetadata, ProxyProtocolSslMetadata,
};

pub(crate) fn capture_tcp(
  connection: &rustls::ServerConnection,
  source: SocketAddr,
  destination: SocketAddr,
  retain_certificate: bool,
) -> anyhow::Result<Arc<ProxyProtocolMetadata>> {
  let version = match connection.protocol_version() {
    Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
    Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
    _ => anyhow::bail!("completed TLS protocol version is unavailable"),
  };
  let current_certificate = matches!(
    connection.handshake_kind(),
    Some(rustls::HandshakeKind::Full | rustls::HandshakeKind::FullWithHelloRetryRequest)
  );
  let mut metadata = capture_authenticated_session(
    source,
    destination,
    version,
    connection.peer_certificates().unwrap_or_default(),
    current_certificate,
    retain_certificate,
  )?;
  let ssl = Arc::get_mut(&mut metadata)
    .and_then(|metadata| metadata.ssl.as_mut())
    .and_then(Arc::get_mut)
    .context("local TLS capture ownership is unavailable")?;
  ssl.cipher_suite = connection
    .negotiated_cipher_suite()
    .map(|suite| format!("{:?}", suite.suite()));
  ssl.key_exchange_group = connection
    .negotiated_key_exchange_group()
    .map(|group| format!("{:?}", group.name()));
  Ok(metadata)
}

pub(crate) fn capture_authenticated_session(
  source: SocketAddr,
  destination: SocketAddr,
  version: &str,
  certificates: &[CertificateDer<'_>],
  current_certificate: bool,
  retain_certificate: bool,
) -> anyhow::Result<Arc<ProxyProtocolMetadata>> {
  let leaf = certificates.first();
  let mut ssl = ProxyProtocolSslMetadata {
    client: 0x01,
    verify: 1,
    version: Some(version.to_owned()),
    ..Default::default()
  };
  if let Some(leaf) = leaf {
    ssl.client |= 0x04;
    if current_certificate {
      ssl.client |= 0x02;
    }
    ssl.verify = 0;
    let metadata = super::parse_certificate_metadata(leaf.as_ref())
      .map_err(|_| anyhow::anyhow!("local client certificate metadata is invalid"))?;
    ssl.common_name = metadata.subject_common_names.into_iter().next();
    if retain_certificate {
      ssl.certificate = Some(ProxyProtocolCertificate::from_der(leaf.as_ref())?);
    }
  }
  Ok(Arc::new(ProxyProtocolMetadata {
    version: ProxyProtocolVersion::V2,
    source,
    destination: Some(destination),
    ssl: Some(Arc::new(ssl)),
  }))
}
