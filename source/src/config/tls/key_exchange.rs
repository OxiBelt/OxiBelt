use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize, Eq, Hash, PartialEq)]
pub struct RawTlsVersionKeyExchangeConfig {
  #[serde(default)]
  pub key_exchange_groups: Option<Vec<TlsKeyExchangeGroup>>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TlsVersionKeyExchangeConfig {
  pub key_exchange_groups: Vec<TlsKeyExchangeGroup>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TlsKeyExchangePolicy {
  pub tls12: TlsVersionKeyExchangeConfig,
  pub tls13: TlsVersionKeyExchangeConfig,
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

pub(super) fn default_tls13_key_exchange_groups() -> Vec<TlsKeyExchangeGroup> {
  vec![
    TlsKeyExchangeGroup::X25519MlKem768,
    TlsKeyExchangeGroup::X25519,
    TlsKeyExchangeGroup::Secp256r1,
    TlsKeyExchangeGroup::Secp384r1,
  ]
}

pub(super) fn default_tls12_key_exchange_groups() -> Vec<TlsKeyExchangeGroup> {
  vec![
    TlsKeyExchangeGroup::X25519,
    TlsKeyExchangeGroup::Secp256r1,
    TlsKeyExchangeGroup::Secp384r1,
  ]
}
