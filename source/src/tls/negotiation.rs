use crate::config::{
  Tls12CipherSuite, Tls13CipherSuite, TlsKeyExchangeGroup, TlsNegotiationPolicy,
};

pub(in crate::tls) fn downstream_crypto_provider_for_policy(
  policy: &TlsNegotiationPolicy,
) -> rustls::crypto::CryptoProvider {
  let mut provider = rustls::crypto::aws_lc_rs::default_provider();
  provider.kx_groups = policy
    .tls13
    .key_exchange_groups
    .iter()
    .copied()
    .map(supported_key_exchange_group)
    .collect();
  provider.cipher_suites = policy
    .tls13
    .ciphers
    .iter()
    .copied()
    .map(supported_tls13_cipher_suite)
    .chain(
      policy
        .tls12
        .groups
        .iter()
        .copied()
        .map(supported_tls12_cipher_suite),
    )
    .collect();
  provider
}

pub(in crate::tls) fn downstream_crypto_provider_for_tls13(
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[Tls13CipherSuite],
) -> rustls::crypto::CryptoProvider {
  let mut provider = rustls::crypto::aws_lc_rs::default_provider();
  provider.kx_groups = key_exchange_groups
    .iter()
    .copied()
    .map(supported_key_exchange_group)
    .collect();
  provider.cipher_suites = ciphers
    .iter()
    .copied()
    .map(supported_tls13_cipher_suite)
    .collect();
  provider
}

pub(in crate::tls) fn downstream_crypto_provider_for_tls12(
  key_exchange_groups: &[TlsKeyExchangeGroup],
  ciphers: &[Tls12CipherSuite],
) -> rustls::crypto::CryptoProvider {
  let mut provider = rustls::crypto::aws_lc_rs::default_provider();
  provider.kx_groups = key_exchange_groups
    .iter()
    .copied()
    .map(supported_key_exchange_group)
    .collect();
  provider.cipher_suites = ciphers
    .iter()
    .copied()
    .map(supported_tls12_cipher_suite)
    .collect();
  provider
}

fn supported_key_exchange_group(
  group: TlsKeyExchangeGroup,
) -> &'static dyn rustls::crypto::SupportedKxGroup {
  match group {
    TlsKeyExchangeGroup::X25519MlKem768 => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
    TlsKeyExchangeGroup::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
    TlsKeyExchangeGroup::Secp256r1 => rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    TlsKeyExchangeGroup::Secp384r1 => rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
  }
}

pub(in crate::tls) fn supported_tls13_cipher_suite(
  cipher: Tls13CipherSuite,
) -> rustls::SupportedCipherSuite {
  match cipher {
    Tls13CipherSuite::Aes256GcmSha384 => {
      rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384
    }
    Tls13CipherSuite::Aes128GcmSha256 => {
      rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
    }
    Tls13CipherSuite::Chacha20Poly1305Sha256 => {
      rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
    }
  }
}

pub(in crate::tls) fn supported_tls12_cipher_suite(
  cipher: Tls12CipherSuite,
) -> rustls::SupportedCipherSuite {
  match cipher {
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
  }
}
