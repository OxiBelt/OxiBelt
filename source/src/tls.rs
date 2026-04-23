use std::fs;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig, sign::CertifiedKey};

use crate::config::{ListenerConfig, OcspMode, TlsConfig};

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
) -> anyhow::Result<ClientConfig> {
  let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
  let roots = load_upstream_root_store(extra_root_certificates)?;

  let client_config = ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()
    .context("failed to configure upstream TLS versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();

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
