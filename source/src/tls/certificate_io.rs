use std::fs;

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
#[cfg(feature = "admin-runtime")]
use rustls::sign::CertifiedKey;

#[cfg(feature = "admin-runtime")]
use crate::config::CryptoConfig;
use crate::config::{OcspConfig, OcspMode, canonicalize_existing_file};

#[cfg(feature = "admin-runtime")]
pub(crate) fn validate_local_certificate_key_pair(
  cert_chain: &std::path::Path,
  private_key: &std::path::Path,
  crypto: &CryptoConfig,
) -> anyhow::Result<()> {
  let certs = load_certs(cert_chain)?;
  let key = load_private_key(private_key)?;
  let provider = super::provider::crypto_provider(crypto)?;
  CertifiedKey::from_der(certs, key, &provider)?;
  Ok(())
}

pub(in crate::tls) fn load_certs(
  path: &std::path::Path,
) -> anyhow::Result<Vec<CertificateDer<'static>>> {
  let bytes = read_existing_file("certificate file", path)?;
  CertificateDer::pem_slice_iter(&bytes)
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

pub(in crate::tls) fn load_private_key(
  path: &std::path::Path,
) -> anyhow::Result<PrivateKeyDer<'static>> {
  let bytes = read_existing_file("private key file", path)?;
  PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| match error {
    rustls::pki_types::pem::Error::NoItemsFound => {
      anyhow!("no private key found in {}", path.display())
    }
    error => anyhow!(
      "failed to parse private key from {}: {error}",
      path.display()
    ),
  })
}

pub(in crate::tls) fn load_ocsp_response(ocsp: &OcspConfig) -> anyhow::Result<Option<Vec<u8>>> {
  match ocsp.mode {
    OcspMode::Disabled => Ok(None),
    OcspMode::StaticFile => {
      let path = ocsp
        .response_file
        .as_ref()
        .ok_or_else(|| anyhow!("OCSP response file must be configured"))?;
      let bytes = read_existing_file("OCSP response file", path)?;
      Ok(Some(bytes))
    }
    OcspMode::LiveFetch => Ok(None),
  }
}

pub(in crate::tls) fn read_existing_file(
  field_name: &str,
  path: &std::path::Path,
) -> anyhow::Result<Vec<u8>> {
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

pub(in crate::tls) fn end_entity_cert<'a>(
  certs: &'a [CertificateDer<'static>],
) -> anyhow::Result<&'a CertificateDer<'static>> {
  certs
    .first()
    .ok_or_else(|| anyhow!("certificate chain must include an end-entity certificate"))
}
