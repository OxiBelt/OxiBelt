//! Small crypto primitive adapters used by OxiBelt-owned protocol code.
//! These helpers keep fixed algorithms and constant-time tag checks explicit.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub(crate) const SHA1_LEN: usize = 20;
pub(crate) const SHA256_LEN: usize = 32;
pub(crate) const SHA256_HEX_LEN: usize = SHA256_LEN * 2;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

pub(crate) fn random_fill(bytes: &mut [u8]) -> Result<(), getrandom::Error> {
  getrandom::fill(bytes)
}

pub(crate) fn sha1(bytes: &[u8]) -> [u8; SHA1_LEN] {
  let digest = Sha1::digest(bytes);
  let mut out = [0u8; SHA1_LEN];
  out.copy_from_slice(&digest);
  out
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
  let digest = Sha256::digest(bytes);
  let mut out = [0u8; SHA256_LEN];
  out.copy_from_slice(&digest);
  out
}

pub(crate) fn hmac_sha1(key: &[u8], value: &[u8]) -> [u8; SHA1_LEN] {
  let mut mac = HmacSha1::new_from_slice(key).expect("HMAC-SHA1 accepts keys of any length");
  mac.update(value);
  let tag = mac.finalize().into_bytes();
  let mut out = [0u8; SHA1_LEN];
  out.copy_from_slice(&tag);
  out
}

pub(crate) fn verify_hmac_sha1(key: &[u8], value: &[u8], tag: &[u8]) -> bool {
  let mut mac = HmacSha1::new_from_slice(key).expect("HMAC-SHA1 accepts keys of any length");
  mac.update(value);
  mac.verify_slice(tag).is_ok()
}

pub(crate) fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; SHA256_LEN] {
  let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
  mac.update(value);
  let tag = mac.finalize().into_bytes();
  let mut out = [0u8; SHA256_LEN];
  out.copy_from_slice(&tag);
  out
}

pub(crate) fn verify_hmac_sha256(key: &[u8], value: &[u8], tag: &[u8]) -> bool {
  let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
  mac.update(value);
  mac.verify_slice(tag).is_ok()
}
