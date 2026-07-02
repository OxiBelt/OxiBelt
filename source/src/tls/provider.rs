//! Runtime rustls crypto-provider selection.
//! TLS builders call this module instead of hard-coding provider-specific paths.

use std::sync::Arc;

use crate::config::{CryptoConfig, TlsCryptoProvider};

pub(in crate::tls) fn crypto_provider(
  config: &CryptoConfig,
) -> anyhow::Result<rustls::crypto::CryptoProvider> {
  match config.tls_provider {
    TlsCryptoProvider::AwsLcRs => Ok(rustls::crypto::aws_lc_rs::default_provider()),
    TlsCryptoProvider::Ring => ring_crypto_provider(),
  }
}

pub(in crate::tls) fn default_crypto_provider() -> rustls::crypto::CryptoProvider {
  rustls::crypto::aws_lc_rs::default_provider()
}

pub(in crate::tls) fn ticketer_for_provider(
  provider: TlsCryptoProvider,
) -> anyhow::Result<Arc<dyn rustls::server::ProducesTickets>> {
  match provider {
    TlsCryptoProvider::AwsLcRs => rustls::crypto::aws_lc_rs::Ticketer::new()
      .map_err(anyhow::Error::from)
      .map_err(|error| {
        anyhow::anyhow!("failed to create AWS-LC TLS session ticket producer: {error}")
      }),
    TlsCryptoProvider::Ring => ring_ticketer(),
  }
}

#[cfg(feature = "crypto-ring")]
fn ring_crypto_provider() -> anyhow::Result<rustls::crypto::CryptoProvider> {
  Ok(rustls::crypto::ring::default_provider())
}

#[cfg(not(feature = "crypto-ring"))]
fn ring_crypto_provider() -> anyhow::Result<rustls::crypto::CryptoProvider> {
  anyhow::bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature")
}

#[cfg(feature = "crypto-ring")]
fn ring_ticketer() -> anyhow::Result<Arc<dyn rustls::server::ProducesTickets>> {
  rustls::crypto::ring::Ticketer::new()
    .map_err(anyhow::Error::from)
    .map_err(|error| anyhow::anyhow!("failed to create ring TLS session ticket producer: {error}"))
}

#[cfg(not(feature = "crypto-ring"))]
fn ring_ticketer() -> anyhow::Result<Arc<dyn rustls::server::ProducesTickets>> {
  anyhow::bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature")
}
