use std::fs;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use h3_quinn::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use h3_quinn::quinn::{ClientConfig as QuinnClientConfig, ServerConfig as QuinnServerConfig};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, sign::CertifiedKey};

use crate::config::{
  ListenerConfig, OcspMode, QuicConfig, QuicZeroRttMode, TlsClientAuthConfig, TlsClientAuthMode,
  TlsConfig, TlsVersion, UpstreamEchConfig, UpstreamEchMode, canonicalize_existing_file,
};

pub fn install_default_provider() -> anyhow::Result<()> {
  let provider = rustls::crypto::aws_lc_rs::default_provider();
  let _ = provider.install_default();
  Ok(())
}

pub fn build_server_config(
  tls: &TlsConfig,
  listeners: &ListenerConfig,
) -> anyhow::Result<Arc<ServerConfig>> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let certs = load_certs(&tls.cert_chain)?;
  let key = load_private_key(&tls.private_key)?;
  let mut certified_key = CertifiedKey::from_der(certs, key, &provider)
    .context("failed to create rustls certified key")?;
  certified_key.ocsp = load_ocsp_response(tls)?;

  let cert_resolver = rustls::sign::SingleCertAndKey::from(certified_key);
  let versions = tls_protocol_versions(tls.min_version, tls.max_version);
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&versions)
    .context("failed to configure TLS versions")?;
  let mut server_config = match downstream_client_cert_verifier(&tls.client_auth, provider)? {
    Some(verifier) => builder.with_client_cert_verifier(verifier),
    None => builder.with_no_client_auth(),
  }
  .with_cert_resolver(Arc::new(cert_resolver));
  if !tls.session_tickets {
    server_config.send_tls13_tickets = 0;
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
  }

  let mut alpn = Vec::new();
  if listeners.http2 {
    alpn.push(b"h2".to_vec());
  }
  if listeners.http1 {
    alpn.push(b"http/1.1".to_vec());
  }
  server_config.alpn_protocols = alpn;

  Ok(Arc::new(server_config))
}

pub fn build_quic_server_config(
  tls: &TlsConfig,
  quic: &QuicConfig,
) -> anyhow::Result<QuinnServerConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let certs = load_certs(&tls.cert_chain)?;
  let key = load_private_key(&tls.private_key)?;
  let mut certified_key = CertifiedKey::from_der(certs, key, &provider)
    .context("failed to create rustls certified key")?;
  certified_key.ocsp = load_ocsp_response(tls)?;

  let cert_resolver = rustls::sign::SingleCertAndKey::from(certified_key);
  let builder = ServerConfig::builder_with_provider(provider.clone())
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("failed to configure QUIC TLS versions")?;
  let mut server_config = match downstream_client_cert_verifier(&tls.client_auth, provider)? {
    Some(verifier) => builder.with_client_cert_verifier(verifier),
    None => builder.with_no_client_auth(),
  }
  .with_cert_resolver(Arc::new(cert_resolver));
  if quic.zero_rtt == QuicZeroRttMode::SafeMethods {
    server_config.max_early_data_size = u32::MAX;
  }
  server_config.alpn_protocols = vec![b"h3".to_vec()];

  let quic_crypto =
    QuicServerConfig::try_from(server_config).context("failed to build QUIC server TLS config")?;
  let mut quic_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
  crate::quic::apply_server_config(quic, &mut quic_config)?;
  Ok(quic_config)
}

pub fn build_upstream_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
) -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let roots = load_upstream_root_store(extra_root_certificates)?;

  let builder = ClientConfig::builder_with_provider(provider);
  let builder = match upstream_ech_mode(ech)? {
    Some(mode) => builder
      .with_ech(mode)
      .context("failed to configure upstream TLS 1.3 ECH")?,
    None => builder
      .with_safe_default_protocol_versions()
      .context("failed to configure upstream TLS versions")?,
  };

  let client_config = builder.with_root_certificates(roots).with_no_client_auth();

  Ok(client_config)
}

pub fn build_upstream_quic_client_config(
  extra_root_certificates: &[std::path::PathBuf],
  ech: &UpstreamEchConfig,
  quic: &QuicConfig,
) -> anyhow::Result<QuinnClientConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let roots = load_upstream_root_store(extra_root_certificates)?;

  let builder = ClientConfig::builder_with_provider(provider);
  let builder = match upstream_ech_mode(ech)? {
    Some(mode) => builder
      .with_ech(mode)
      .context("failed to configure upstream QUIC TLS 1.3 ECH")?,
    None => builder
      .with_protocol_versions(&[&rustls::version::TLS13])
      .context("failed to configure upstream QUIC TLS versions")?,
  };

  let mut client_config = builder.with_root_certificates(roots).with_no_client_auth();
  client_config.alpn_protocols = vec![b"h3".to_vec()];

  let quic_crypto =
    QuicClientConfig::try_from(client_config).context("failed to build QUIC client TLS config")?;
  let mut quic_config = QuinnClientConfig::new(Arc::new(quic_crypto));
  quic_config.transport_config(crate::quic::transport_config(quic)?);
  Ok(quic_config)
}

fn load_certs(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = read_existing_file("certificate file", path)?;
  let mut cursor = bytes.as_slice();
  rustls_pemfile::certs(&mut cursor)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

fn load_private_key(path: &std::path::Path) -> anyhow::Result<PrivateKeyDer<'static>> {
  let bytes = read_existing_file("private key file", path)?;
  let mut cursor = bytes.as_slice();
  rustls_pemfile::private_key(&mut cursor)
    .with_context(|| format!("failed to parse private key from {}", path.display()))?
    .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

fn load_ocsp_response(tls: &TlsConfig) -> anyhow::Result<Option<Vec<u8>>> {
  match tls.ocsp.mode {
    OcspMode::Disabled => Ok(None),
    OcspMode::StaticFile => {
      let path = tls
        .ocsp
        .response_file
        .as_ref()
        .ok_or_else(|| anyhow!("OCSP response file must be configured"))?;
      let bytes = read_existing_file("OCSP response file", path)?;
      Ok(Some(bytes))
    }
    OcspMode::LiveFetch => Err(anyhow!("live OCSP fetch is not implemented yet")),
  }
}

fn upstream_ech_mode(ech: &UpstreamEchConfig) -> anyhow::Result<Option<EchMode>> {
  match ech.mode {
    UpstreamEchMode::Disabled => Ok(None),
    UpstreamEchMode::Grease => Ok(Some(EchMode::Grease(build_ech_grease_config()?))),
    UpstreamEchMode::ConfigList => Ok(Some(EchMode::Enable(load_ech_config(ech)?))),
  }
}

fn build_ech_grease_config() -> anyhow::Result<EchGreaseConfig> {
  let suite = default_ech_hpke_suites()
    .first()
    .copied()
    .ok_or_else(|| anyhow!("aws-lc-rs provider does not expose HPKE suites for ECH"))?;
  let (public_key, _private_key) = suite
    .generate_key_pair()
    .context("failed to generate ECH GREASE placeholder key")?;

  Ok(EchGreaseConfig::new(suite, public_key))
}

fn load_ech_config(ech: &UpstreamEchConfig) -> anyhow::Result<EchConfig> {
  let path = ech
    .config_list_file
    .as_ref()
    .ok_or_else(|| anyhow!("upstream ECH config_list_file must be configured"))?;
  let bytes = read_existing_file("upstream ECH config list file", path)?;

  EchConfig::new(EchConfigListBytes::from(bytes), default_ech_hpke_suites()).with_context(|| {
    format!(
      "failed to parse upstream ECH config list from {}",
      path.display()
    )
  })
}

fn default_ech_hpke_suites() -> &'static [&'static dyn Hpke] {
  rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
}

fn read_existing_file(field_name: &str, path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
  let canonical_path = canonicalize_existing_file(field_name, path)?;
  let canonical_parent = path
    .parent()
    .unwrap_or_else(|| std::path::Path::new("."))
    .canonicalize()
    .with_context(|| {
      format!(
        "failed to resolve {field_name} parent for {}",
        path.display()
      )
    })?;

  if !canonical_path.starts_with(&canonical_parent) {
    bail!("{field_name} must stay within its configured directory");
  }

  fs::read(&canonical_path).with_context(|| format!("failed to read {}", canonical_path.display()))
}

fn load_upstream_root_store(
  extra_root_certificates: &[std::path::PathBuf],
) -> anyhow::Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

  for path in extra_root_certificates {
    let certs = load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable upstream root certificates found in {}",
        path.display()
      );
    }
  }

  Ok(roots)
}

fn load_client_auth_root_store(paths: &[std::path::PathBuf]) -> anyhow::Result<RootCertStore> {
  let mut roots = RootCertStore::empty();
  for path in paths {
    let certs = load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable downstream client auth root certificates found in {}",
        path.display()
      );
    }
  }
  Ok(roots)
}

fn downstream_client_cert_verifier(
  client_auth: &TlsClientAuthConfig,
  provider: Arc<rustls::crypto::CryptoProvider>,
) -> anyhow::Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>> {
  match client_auth.mode {
    TlsClientAuthMode::Off => Ok(None),
    TlsClientAuthMode::Optional | TlsClientAuthMode::Require => {
      let roots = load_client_auth_root_store(&client_auth.ca_certs)?;
      let mut verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
      if client_auth.mode == TlsClientAuthMode::Optional {
        verifier = verifier.allow_unauthenticated();
      }
      verifier
        .build()
        .context("failed to build downstream client certificate verifier")
        .map(Some)
    }
  }
}

fn tls_protocol_versions(
  min_version: TlsVersion,
  max_version: TlsVersion,
) -> Vec<&'static rustls::SupportedProtocolVersion> {
  match (min_version, max_version) {
    (TlsVersion::Tls12, TlsVersion::Tls12) => vec![&rustls::version::TLS12],
    (TlsVersion::Tls12, TlsVersion::Tls13) => {
      vec![&rustls::version::TLS13, &rustls::version::TLS12]
    }
    (TlsVersion::Tls13, TlsVersion::Tls13) => vec![&rustls::version::TLS13],
    (TlsVersion::Tls13, TlsVersion::Tls12) => vec![&rustls::version::TLS13],
  }
}
