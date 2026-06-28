use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Default, Deserialize, Eq, Hash, PartialEq)]
pub struct RawTls12NegotiationConfig {
  #[serde(default)]
  pub groups: Option<Vec<Tls12CipherSuite>>,
  #[serde(default)]
  pub key_exchange_groups: Option<Vec<TlsKeyExchangeGroup>>,
}

#[derive(Debug, Clone, Default, Deserialize, Eq, Hash, PartialEq)]
pub struct RawTls13NegotiationConfig {
  #[serde(default)]
  pub key_exchange_groups: Option<Vec<TlsKeyExchangeGroup>>,
  #[serde(default)]
  pub ciphers: Option<Vec<Tls13CipherSuite>>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Tls12NegotiationConfig {
  pub groups: Vec<Tls12CipherSuite>,
  pub key_exchange_groups: Vec<TlsKeyExchangeGroup>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Tls13NegotiationConfig {
  pub key_exchange_groups: Vec<TlsKeyExchangeGroup>,
  pub ciphers: Vec<Tls13CipherSuite>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TlsNegotiationPolicy {
  pub tls12: Tls12NegotiationConfig,
  pub tls13: Tls13NegotiationConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TlsKeyExchangeGroup {
  X25519MlKem768,
  X25519,
  Secp256r1,
  Secp384r1,
}

impl TlsKeyExchangeGroup {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::X25519MlKem768 => "x25519mlkem768",
      Self::X25519 => "x25519",
      Self::Secp256r1 => "secp256r1",
      Self::Secp384r1 => "secp384r1",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Tls13CipherSuite {
  Aes256GcmSha384,
  Aes128GcmSha256,
  Chacha20Poly1305Sha256,
}

impl Tls13CipherSuite {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
      Self::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
      Self::Chacha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
    }
  }
}

impl<'de> Deserialize<'de> for Tls13CipherSuite {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = String::deserialize(deserializer)?;
    match raw.trim() {
      "TLS_AES_256_GCM_SHA384" => Ok(Self::Aes256GcmSha384),
      "TLS_AES_128_GCM_SHA256" => Ok(Self::Aes128GcmSha256),
      "TLS_CHACHA20_POLY1305_SHA256" => Ok(Self::Chacha20Poly1305Sha256),
      value => Err(serde::de::Error::custom(format!(
        "unsupported TLS 1.3 cipher suite {value}"
      ))),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Tls12CipherSuite {
  EcdheEcdsaAes256GcmSha384,
  EcdheEcdsaAes128GcmSha256,
  EcdheEcdsaChacha20Poly1305Sha256,
  EcdheRsaAes256GcmSha384,
  EcdheRsaAes128GcmSha256,
  EcdheRsaChacha20Poly1305Sha256,
}

impl Tls12CipherSuite {
  pub(crate) fn as_str(self) -> &'static str {
    match self {
      Self::EcdheEcdsaAes256GcmSha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      Self::EcdheEcdsaAes128GcmSha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      Self::EcdheEcdsaChacha20Poly1305Sha256 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      Self::EcdheRsaAes256GcmSha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      Self::EcdheRsaAes128GcmSha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      Self::EcdheRsaChacha20Poly1305Sha256 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    }
  }
}

impl<'de> Deserialize<'de> for Tls12CipherSuite {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = String::deserialize(deserializer)?;
    match raw.trim() {
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => Ok(Self::EcdheEcdsaAes256GcmSha384),
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => Ok(Self::EcdheEcdsaAes128GcmSha256),
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => Ok(Self::EcdheEcdsaChacha20Poly1305Sha256),
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => Ok(Self::EcdheRsaAes256GcmSha384),
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => Ok(Self::EcdheRsaAes128GcmSha256),
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => Ok(Self::EcdheRsaChacha20Poly1305Sha256),
      value => Err(serde::de::Error::custom(format!(
        "unsupported TLS 1.2 cipher suite {value}"
      ))),
    }
  }
}

pub(super) fn default_tls13_key_exchange_groups() -> Vec<TlsKeyExchangeGroup> {
  vec![
    TlsKeyExchangeGroup::X25519MlKem768,
    TlsKeyExchangeGroup::X25519,
    TlsKeyExchangeGroup::Secp256r1,
    TlsKeyExchangeGroup::Secp384r1,
  ]
}

pub(super) fn default_tls13_ciphers() -> Vec<Tls13CipherSuite> {
  vec![
    Tls13CipherSuite::Aes256GcmSha384,
    Tls13CipherSuite::Aes128GcmSha256,
    Tls13CipherSuite::Chacha20Poly1305Sha256,
  ]
}

pub(super) fn default_tls12_ciphers() -> Vec<Tls12CipherSuite> {
  vec![
    Tls12CipherSuite::EcdheEcdsaAes256GcmSha384,
    Tls12CipherSuite::EcdheEcdsaAes128GcmSha256,
    Tls12CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
    Tls12CipherSuite::EcdheRsaAes256GcmSha384,
    Tls12CipherSuite::EcdheRsaAes128GcmSha256,
    Tls12CipherSuite::EcdheRsaChacha20Poly1305Sha256,
  ]
}

pub(super) fn default_tls12_key_exchange_groups() -> Vec<TlsKeyExchangeGroup> {
  vec![
    TlsKeyExchangeGroup::X25519,
    TlsKeyExchangeGroup::Secp256r1,
    TlsKeyExchangeGroup::Secp384r1,
  ]
}
