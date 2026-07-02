//! Crypto provider and primitive backend configuration.
//! Defaults preserve the historical AWS-LC rustls provider and RustCrypto primitives.

use anyhow::bail;
use serde::Deserialize;

use super::{Config, TlsKeyExchangeGroup, UpstreamEchMode};

pub(in crate::config) const CRYPTO_CONFIG_KEYS: &[&str] = &[
  "primitive_backend",
  "primitive_provider",
  "primitives",
  "tls_provider",
];

pub(in crate::config) const CRYPTO_PRIMITIVES_CONFIG_KEYS: &[&str] =
  &["aes_gcm", "chacha20poly1305", "hkdf", "hmac_sha256", "sha2"];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CryptoConfig {
  #[serde(default)]
  pub tls_provider: TlsCryptoProvider,
  #[serde(default)]
  pub primitive_provider: CryptoPrimitiveProvider,
  #[serde(default)]
  pub primitive_backend: CryptoPrimitiveBackend,
  #[serde(default)]
  pub primitives: CryptoPrimitiveOverrides,
}

impl Default for CryptoConfig {
  fn default() -> Self {
    Self {
      tls_provider: TlsCryptoProvider::AwsLcRs,
      primitive_provider: CryptoPrimitiveProvider::RustCrypto,
      primitive_backend: CryptoPrimitiveBackend::Auto,
      primitives: CryptoPrimitiveOverrides::default(),
    }
  }
}

impl CryptoConfig {
  pub(crate) fn sha2_provider(&self) -> CryptoPrimitiveProvider {
    self.primitives.sha2.unwrap_or(self.primitive_provider)
  }

  pub(crate) fn hkdf_provider(&self) -> CryptoPrimitiveProvider {
    self.primitives.hkdf.unwrap_or(self.primitive_provider)
  }

  pub(crate) fn hmac_sha256_provider(&self) -> CryptoPrimitiveProvider {
    self
      .primitives
      .hmac_sha256
      .unwrap_or(self.primitive_provider)
  }

  pub(crate) fn aes_gcm_provider(&self) -> CryptoPrimitiveProvider {
    self.primitives.aes_gcm.unwrap_or(self.primitive_provider)
  }

  pub(crate) fn chacha20poly1305_provider(&self) -> CryptoPrimitiveProvider {
    self
      .primitives
      .chacha20poly1305
      .unwrap_or(self.primitive_provider)
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsCryptoProvider {
  #[default]
  AwsLcRs,
  Ring,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPrimitiveProvider {
  AwsLcRs,
  #[serde(rename = "rustcrypto", alias = "rust_crypto")]
  #[default]
  RustCrypto,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CryptoPrimitiveBackend {
  #[default]
  Auto,
  Hardware,
  Software,
}

impl CryptoPrimitiveBackend {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Hardware => "hardware",
      Self::Software => "software",
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct CryptoPrimitiveOverrides {
  #[serde(default)]
  pub aes_gcm: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub chacha20poly1305: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub hkdf: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub hmac_sha256: Option<CryptoPrimitiveProvider>,
  #[serde(default)]
  pub sha2: Option<CryptoPrimitiveProvider>,
}

pub(super) fn validate_crypto(config: &Config) -> anyhow::Result<()> {
  validate_backend(config.crypto.primitive_backend)?;
  validate_tls_provider(config)?;
  Ok(())
}

fn validate_backend(backend: CryptoPrimitiveBackend) -> anyhow::Result<()> {
  if backend != CryptoPrimitiveBackend::Auto {
    bail!(
      "crypto.primitive_backend = \"{}\" is not supported by this build; use \"auto\"",
      backend.as_str()
    );
  }
  Ok(())
}

fn validate_tls_provider(config: &Config) -> anyhow::Result<()> {
  match config.crypto.tls_provider {
    TlsCryptoProvider::AwsLcRs => Ok(()),
    TlsCryptoProvider::Ring => {
      if !cfg!(feature = "crypto-ring") {
        bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature");
      }
      validate_ring_tls_compatibility(config)
    }
  }
}

fn validate_ring_tls_compatibility(config: &Config) -> anyhow::Result<()> {
  reject_ring_pq_groups(
    "tls.1_3.key_exchange_groups",
    &config.tls.tls13.key_exchange_groups,
  )?;
  for route in &config.routes {
    if let Some(groups) = &route.tls.tls13.key_exchange_groups {
      reject_ring_pq_groups(
        &format!("route {} tls.1_3.key_exchange_groups", route.name),
        groups,
      )?;
    }
  }
  for upstream in &config.upstreams {
    if upstream.tls.ech.mode != UpstreamEchMode::Disabled {
      bail!(
        "upstream {} tls.ech.mode requires crypto.tls_provider = \"aws_lc_rs\"",
        upstream.name
      );
    }
  }
  Ok(())
}

fn reject_ring_pq_groups(field_name: &str, groups: &[TlsKeyExchangeGroup]) -> anyhow::Result<()> {
  if groups.contains(&TlsKeyExchangeGroup::X25519MlKem768) {
    bail!("{field_name} cannot include x25519mlkem768 when crypto.tls_provider = \"ring\"");
  }
  Ok(())
}
