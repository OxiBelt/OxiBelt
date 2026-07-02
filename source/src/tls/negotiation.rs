use crate::config::{
  CryptoConfig, Tls12CipherSuite, Tls13CipherSuite, TlsCryptoProvider, TlsKeyExchangeGroup,
  TlsNegotiationPolicy,
};

pub(in crate::tls) fn downstream_crypto_provider_for_policy(
  crypto: &CryptoConfig,
  policy: &TlsNegotiationPolicy,
) -> anyhow::Result<rustls::crypto::CryptoProvider> {
  let mut provider = super::provider::crypto_provider(crypto)?;
  provider.kx_groups = policy
    .tls13
    .key_exchange_groups
    .iter()
    .copied()
    .map(|group| supported_key_exchange_group(crypto.tls_provider, group))
    .collect::<anyhow::Result<Vec<_>>>()?;
  provider.cipher_suites = policy
    .tls13
    .ciphers
    .iter()
    .copied()
    .map(|cipher| supported_tls13_cipher_suite(crypto.tls_provider, cipher))
    .collect::<anyhow::Result<Vec<_>>>()?
    .into_iter()
    .chain(
      policy
        .tls12
        .groups
        .iter()
        .copied()
        .map(|cipher| supported_tls12_cipher_suite(crypto.tls_provider, cipher))
        .collect::<anyhow::Result<Vec<_>>>()?,
    )
    .collect();
  Ok(provider)
}

pub(in crate::tls) fn downstream_crypto_provider_for_tls13(
  crypto: &CryptoConfig,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[Tls13CipherSuite],
) -> anyhow::Result<rustls::crypto::CryptoProvider> {
  let mut provider = super::provider::crypto_provider(crypto)?;
  provider.kx_groups = key_exchange_groups
    .iter()
    .copied()
    .map(|group| supported_key_exchange_group(crypto.tls_provider, group))
    .collect::<anyhow::Result<Vec<_>>>()?;
  provider.cipher_suites = ciphers
    .iter()
    .copied()
    .map(|cipher| supported_tls13_cipher_suite(crypto.tls_provider, cipher))
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(provider)
}

pub(in crate::tls) fn downstream_crypto_provider_for_tls12(
  crypto: &CryptoConfig,
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[Tls12CipherSuite],
) -> anyhow::Result<rustls::crypto::CryptoProvider> {
  let mut provider = super::provider::crypto_provider(crypto)?;
  provider.kx_groups = key_exchange_groups
    .iter()
    .copied()
    .map(|group| supported_key_exchange_group(crypto.tls_provider, group))
    .collect::<anyhow::Result<Vec<_>>>()?;
  provider.cipher_suites = ciphers
    .iter()
    .copied()
    .map(|cipher| supported_tls12_cipher_suite(crypto.tls_provider, cipher))
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(provider)
}

fn supported_key_exchange_group(
  provider: TlsCryptoProvider,
  group: TlsKeyExchangeGroup,
) -> anyhow::Result<&'static dyn rustls::crypto::SupportedKxGroup> {
  match provider {
    TlsCryptoProvider::AwsLcRs => Ok(match group {
      TlsKeyExchangeGroup::X25519MlKem768 => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
      TlsKeyExchangeGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
      TlsKeyExchangeGroup::Secp256r1 => rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
      TlsKeyExchangeGroup::Secp384r1 => rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
    }),
    TlsCryptoProvider::Ring => supported_ring_key_exchange_group(group),
  }
}

pub(in crate::tls) fn supported_tls13_cipher_suite(
  provider: TlsCryptoProvider,
  cipher: Tls13CipherSuite,
) -> anyhow::Result<rustls::SupportedCipherSuite> {
  match provider {
    TlsCryptoProvider::AwsLcRs => Ok(match cipher {
      Tls13CipherSuite::Aes256GcmSha384 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
      }
      Tls13CipherSuite::Aes128GcmSha256 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
      }
      Tls13CipherSuite::Chacha20Poly1305Sha256 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
      }
    }),
    TlsCryptoProvider::Ring => supported_ring_tls13_cipher_suite(cipher),
  }
}

pub(in crate::tls) fn supported_tls12_cipher_suite(
  provider: TlsCryptoProvider,
  cipher: Tls12CipherSuite,
) -> anyhow::Result<rustls::SupportedCipherSuite> {
  match provider {
    TlsCryptoProvider::AwsLcRs => Ok(match cipher {
      Tls12CipherSuite::EcdheEcdsaAes256GcmSha384 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      }
      Tls12CipherSuite::EcdheEcdsaAes128GcmSha256 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      }
      Tls12CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      }
      Tls12CipherSuite::EcdheRsaAes256GcmSha384 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      }
      Tls12CipherSuite::EcdheRsaAes128GcmSha256 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      }
      Tls12CipherSuite::EcdheRsaChacha20Poly1305Sha256 => {
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      }
    }),
    TlsCryptoProvider::Ring => supported_ring_tls12_cipher_suite(cipher),
  }
}

#[cfg(feature = "crypto-ring")]
fn supported_ring_key_exchange_group(
  group: TlsKeyExchangeGroup,
) -> anyhow::Result<&'static dyn rustls::crypto::SupportedKxGroup> {
  match group {
    TlsKeyExchangeGroup::X25519MlKem768 => {
      anyhow::bail!("x25519mlkem768 is not supported by crypto.tls_provider = \"ring\"")
    }
    TlsKeyExchangeGroup::X25519 => Ok(rustls::crypto::ring::kx_group::X25519),
    TlsKeyExchangeGroup::Secp256r1 => Ok(rustls::crypto::ring::kx_group::SECP256R1),
    TlsKeyExchangeGroup::Secp384r1 => Ok(rustls::crypto::ring::kx_group::SECP384R1),
  }
}

#[cfg(not(feature = "crypto-ring"))]
fn supported_ring_key_exchange_group(
  _group: TlsKeyExchangeGroup,
) -> anyhow::Result<&'static dyn rustls::crypto::SupportedKxGroup> {
  anyhow::bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature")
}

#[cfg(feature = "crypto-ring")]
fn supported_ring_tls13_cipher_suite(
  cipher: Tls13CipherSuite,
) -> anyhow::Result<rustls::SupportedCipherSuite> {
  Ok(match cipher {
    Tls13CipherSuite::Aes256GcmSha384 => {
      rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
    }
    Tls13CipherSuite::Aes128GcmSha256 => {
      rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
    }
    Tls13CipherSuite::Chacha20Poly1305Sha256 => {
      rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
    }
  })
}

#[cfg(not(feature = "crypto-ring"))]
fn supported_ring_tls13_cipher_suite(
  _cipher: Tls13CipherSuite,
) -> anyhow::Result<rustls::SupportedCipherSuite> {
  anyhow::bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature")
}

#[cfg(feature = "crypto-ring")]
fn supported_ring_tls12_cipher_suite(
  cipher: Tls12CipherSuite,
) -> anyhow::Result<rustls::SupportedCipherSuite> {
  Ok(match cipher {
    Tls12CipherSuite::EcdheEcdsaAes256GcmSha384 => {
      rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    }
    Tls12CipherSuite::EcdheEcdsaAes128GcmSha256 => {
      rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    }
    Tls12CipherSuite::EcdheEcdsaChacha20Poly1305Sha256 => {
      rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    }
    Tls12CipherSuite::EcdheRsaAes256GcmSha384 => {
      rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    }
    Tls12CipherSuite::EcdheRsaAes128GcmSha256 => {
      rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    }
    Tls12CipherSuite::EcdheRsaChacha20Poly1305Sha256 => {
      rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    }
  })
}

#[cfg(not(feature = "crypto-ring"))]
fn supported_ring_tls12_cipher_suite(
  _cipher: Tls12CipherSuite,
) -> anyhow::Result<rustls::SupportedCipherSuite> {
  anyhow::bail!("crypto.tls_provider = \"ring\" requires the crypto-ring build feature")
}
