use std::fs;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use rustls::client::{EchConfig, EchGreaseConfig, EchMode};
use rustls::crypto::hpke::Hpke;
use rustls::pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, sign::CertifiedKey};

use crate::config::{ListenerConfig, OcspMode, TlsConfig, UpstreamEchConfig, UpstreamEchMode};

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
  let mut server_config = ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("failed to configure TLS versions")?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(cert_resolver));

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

fn load_certs(path: &std::path::Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
  let mut cursor = bytes.as_slice();
  rustls_pemfile::certs(&mut cursor)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

fn load_private_key(path: &std::path::Path) -> anyhow::Result<PrivateKeyDer<'static>> {
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
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
      let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
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
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

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
