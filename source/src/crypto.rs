//! Configuration adapter for OxiBelt-owned crypto primitives.
//! The primitive crate owns the single process-wide provider claim and all algorithms.

use crate::config::{CryptoConfig, CryptoPrimitiveProvider};
use oxibelt_crypto_primitives::{PrimitiveProvider, PrimitiveProviderSelection};

pub(crate) use oxibelt_crypto_primitives::{
  Aes256GcmKey, CryptoPrimitiveClaim, CryptoPrimitiveConflict, SHA256_HEX_LEN, hkdf_sha256,
  hmac_sha1, hmac_sha256, random_fill, sha1, sha256, verify_hmac_sha1, verify_hmac_sha256,
};

pub(crate) fn configure_runtime(
  config: &CryptoConfig,
) -> Result<CryptoPrimitiveClaim, CryptoPrimitiveConflict> {
  oxibelt_crypto_primitives::configure_runtime(provider_selection(config))
}

pub(crate) fn runtime_matches(config: &CryptoConfig) -> bool {
  oxibelt_crypto_primitives::runtime_matches(provider_selection(config))
}

fn provider_selection(config: &CryptoConfig) -> PrimitiveProviderSelection {
  PrimitiveProviderSelection::new(
    primitive_provider(config.sha2_provider()),
    primitive_provider(config.hkdf_provider()),
    primitive_provider(config.hmac_sha256_provider()),
    primitive_provider(config.aes_gcm_provider()),
    primitive_provider(config.chacha20poly1305_provider()),
  )
}

const fn primitive_provider(provider: CryptoPrimitiveProvider) -> PrimitiveProvider {
  match provider {
    CryptoPrimitiveProvider::RustCrypto => PrimitiveProvider::RustCrypto,
    CryptoPrimitiveProvider::AwsLcRs => PrimitiveProvider::AwsLcRs,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn per_primitive_overrides_keep_their_configured_positions() {
    let mut config = CryptoConfig {
      primitive_provider: CryptoPrimitiveProvider::AwsLcRs,
      ..CryptoConfig::default()
    };
    config.primitives.sha2 = Some(CryptoPrimitiveProvider::RustCrypto);
    config.primitives.aes_gcm = Some(CryptoPrimitiveProvider::RustCrypto);
    assert_eq!(
      provider_selection(&config),
      PrimitiveProviderSelection::new(
        PrimitiveProvider::RustCrypto,
        PrimitiveProvider::AwsLcRs,
        PrimitiveProvider::AwsLcRs,
        PrimitiveProvider::RustCrypto,
        PrimitiveProvider::AwsLcRs,
      )
    );
  }
}
