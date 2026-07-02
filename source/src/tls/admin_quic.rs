//! Admin QUIC TLS builder.
//! Admin transport uses a separate resumption scope from public data-plane QUIC.

use std::sync::Arc;

use anyhow::Context;
use h3_quinn::quinn::ServerConfig as QuinnServerConfig;
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
use rustls::{ServerConfig, sign::CertifiedKey};

use super::certificate_io::{load_certs, load_private_key};
use super::*;
use crate::config::{AdminTlsConfig, CryptoConfig, QuicConfig};

pub fn build_admin_quic_server_config_with_resumption(
  tls: &AdminTlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<QuinnServerConfig> {
  let crypto = CryptoConfig::default();
  build_admin_quic_server_config_with_crypto_and_resumption(
    &crypto,
    tls,
    quic,
    quic_host_key_base_dir,
    resumption_state,
  )
}

pub(crate) fn build_admin_quic_server_config_with_crypto_and_resumption(
  crypto: &CryptoConfig,
  tls: &AdminTlsConfig,
  quic: &QuicConfig,
  quic_host_key_base_dir: Option<&std::path::Path>,
  resumption_state: Option<&TlsResumptionState>,
) -> anyhow::Result<QuinnServerConfig> {
  let provider = Arc::new(super::provider::crypto_provider(crypto)?);
  let mut certificates = Vec::new();
  let mut default = None;
  let mut identity_certs = Vec::new();
  for (index, certificate) in tls.certificates.iter().enumerate() {
    let certs = load_certs(&certificate.cert_chain)?;
    identity_certs.extend(certs.iter().cloned());
    let key = load_private_key(&certificate.private_key)?;
    let certified_key = CertifiedKey::from_der(certs, key, &provider)
      .context("failed to create admin QUIC rustls certified key")?;
    let certified_key = Arc::new(certified_key);
    if certificate.default || (tls.certificates.len() == 1 && index == 0) {
      default = Some(certified_key.clone());
    }
    certificates.push(AdminCertificate {
      server_names: certificate
        .server_names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect(),
      certified_key,
    });
  }

  let resolver = AdminCertResolver {
    certificates,
    default,
    require_sni: tls.require_sni,
    reject_unknown_sni: tls.reject_unknown_sni,
  };
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("failed to configure admin QUIC TLS versions")?;
  let mut server_config = match downstream_client_cert_verifier(&tls.client_auth, provider)? {
    Some(verifier) => builder.with_client_cert_verifier(verifier),
    None => builder.with_no_client_auth(),
  }
  .with_cert_resolver(Arc::new(resolver));
  configure_server_resumption(
    &mut server_config,
    &tls.resumption,
    TlsServerResumptionKey {
      scope: "admin-quic",
      mode: tls.resumption.mode,
      server_identity: certificate_identity(&identity_certs),
      client_auth_identity: client_auth_identity(&tls.client_auth)?,
      alpn_family: "admin-h3",
      tls_provider: crypto.tls_provider,
    },
    resumption_state,
  )?;
  server_config.alpn_protocols = vec![b"h3".to_vec()];

  let quic_crypto = QuicServerConfig::try_from(server_config)
    .context("failed to build admin QUIC server TLS config")?;
  let mut quic_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
  crate::quic::apply_server_config(quic, quic_host_key_base_dir, &mut quic_config)?;
  Ok(quic_config)
}
