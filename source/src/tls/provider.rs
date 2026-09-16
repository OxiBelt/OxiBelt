//! Runtime rustls crypto-provider selection.
//! TLS builders call this module instead of hard-coding provider-specific paths.

use std::sync::Arc;

use crate::config::{CryptoConfig, TlsCryptoProvider};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ConfiguredProviderState {
  Missing,
  Matching,
  Conflicting,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ConfiguredProviderInstall {
  Applied,
  AlreadyMatching,
}

#[derive(Debug)]
pub(crate) enum ConfiguredProviderInstallError {
  Conflict,
  Unavailable(anyhow::Error),
}

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

/// Build an AWS-LC provider with an explicit RFC 10024 P-256 hybrid opt-in.
/// The existing first key share and process-global provider remain unchanged.
pub fn aws_lc_provider_with_secp256r1mlkem768(enabled: bool) -> rustls::crypto::CryptoProvider {
  let mut provider = default_crypto_provider();
  if enabled {
    let position = provider
      .kx_groups
      .iter()
      .position(|group| group.name() == rustls::NamedGroup::X25519MLKEM768)
      .map_or(0, |position| position + 1);
    provider.kx_groups.insert(
      position,
      rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
    );
  }
  provider
}

pub(in crate::tls) fn crypto_provider_with_secp256r1mlkem768(
  config: &CryptoConfig,
  enabled: bool,
) -> anyhow::Result<rustls::crypto::CryptoProvider> {
  if !enabled {
    return crypto_provider(config);
  }
  if config.tls_provider != TlsCryptoProvider::AwsLcRs {
    anyhow::bail!("secp256r1mlkem768 requires crypto.tls_provider = \"aws_lc_rs\"");
  }
  Ok(aws_lc_provider_with_secp256r1mlkem768(true))
}

pub(crate) fn configured_provider_state(
  config: &CryptoConfig,
) -> anyhow::Result<ConfiguredProviderState> {
  let configured = crypto_provider(config)?;
  Ok(match rustls::crypto::CryptoProvider::get_default() {
    None => ConfiguredProviderState::Missing,
    Some(active) if crypto_providers_match(active, &configured) => {
      ConfiguredProviderState::Matching
    }
    Some(_) => ConfiguredProviderState::Conflicting,
  })
}

pub(crate) fn ensure_configured_provider(
  config: &CryptoConfig,
) -> Result<ConfiguredProviderInstall, ConfiguredProviderInstallError> {
  let configured = crypto_provider(config).map_err(ConfiguredProviderInstallError::Unavailable)?;
  match rustls::crypto::CryptoProvider::get_default() {
    Some(active) if crypto_providers_match(active, &configured) => {
      return Ok(ConfiguredProviderInstall::AlreadyMatching);
    }
    Some(_) => return Err(ConfiguredProviderInstallError::Conflict),
    None => {}
  }

  match configured.install_default() {
    Ok(()) => Ok(ConfiguredProviderInstall::Applied),
    Err(_) => match configured_provider_state(config)
      .map_err(ConfiguredProviderInstallError::Unavailable)?
    {
      ConfiguredProviderState::Matching => Ok(ConfiguredProviderInstall::AlreadyMatching),
      ConfiguredProviderState::Missing | ConfiguredProviderState::Conflicting => {
        Err(ConfiguredProviderInstallError::Conflict)
      }
    },
  }
}

fn crypto_providers_match(
  active: &rustls::crypto::CryptoProvider,
  configured: &rustls::crypto::CryptoProvider,
) -> bool {
  active
    .cipher_suites
    .iter()
    .map(rustls::SupportedCipherSuite::suite)
    .eq(
      configured
        .cipher_suites
        .iter()
        .map(rustls::SupportedCipherSuite::suite),
    )
    && active
      .kx_groups
      .iter()
      .map(|group| group.name())
      .eq(configured.kx_groups.iter().map(|group| group.name()))
    && active.signature_verification_algorithms.supported_schemes()
      == configured
        .signature_verification_algorithms
        .supported_schemes()
    && active.signature_verification_algorithms.fips()
      == configured.signature_verification_algorithms.fips()
    && std::ptr::eq(active.secure_random, configured.secure_random)
    && std::ptr::eq(active.key_provider, configured.key_provider)
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
