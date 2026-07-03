//! Small crypto primitive adapters used by OxiBelt-owned protocol code.
//! These helpers keep fixed algorithms and constant-time tag checks explicit.

use std::sync::atomic::{AtomicU8, Ordering};

use aes_gcm::Aes256Gcm as RustCryptoAes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit as AeadKeyInit};
use aes_gcm::aead::{Nonce as RustCryptoNonce, Tag as RustCryptoTag};
use anyhow::Context;
use aws_lc_rs::aead::{
  AES_256_GCM, Aad as AwsAad, LessSafeKey as AwsLessSafeKey, Nonce as AwsNonce,
  UnboundKey as AwsUnboundKey,
};
use aws_lc_rs::{digest as aws_digest, hkdf as aws_hkdf, hmac as aws_hmac};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::config::{CryptoConfig, CryptoPrimitiveProvider};

pub(crate) const SHA1_LEN: usize = 20;
pub(crate) const SHA256_LEN: usize = 32;
pub(crate) const SHA256_HEX_LEN: usize = SHA256_LEN * 2;

const PROVIDER_RUSTCRYPTO: u8 = 0;
const PROVIDER_AWS_LC_RS: u8 = 1;

static SHA2_PROVIDER: AtomicU8 = AtomicU8::new(PROVIDER_RUSTCRYPTO);
static HKDF_PROVIDER: AtomicU8 = AtomicU8::new(PROVIDER_RUSTCRYPTO);
static HMAC_SHA256_PROVIDER: AtomicU8 = AtomicU8::new(PROVIDER_RUSTCRYPTO);
static AES_GCM_PROVIDER: AtomicU8 = AtomicU8::new(PROVIDER_RUSTCRYPTO);
static CHACHA20POLY1305_PROVIDER: AtomicU8 = AtomicU8::new(PROVIDER_RUSTCRYPTO);

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

pub(crate) fn configure_runtime(config: &CryptoConfig) {
  SHA2_PROVIDER.store(encode_provider(config.sha2_provider()), Ordering::Relaxed);
  HKDF_PROVIDER.store(encode_provider(config.hkdf_provider()), Ordering::Relaxed);
  HMAC_SHA256_PROVIDER.store(
    encode_provider(config.hmac_sha256_provider()),
    Ordering::Relaxed,
  );
  AES_GCM_PROVIDER.store(
    encode_provider(config.aes_gcm_provider()),
    Ordering::Relaxed,
  );
  CHACHA20POLY1305_PROVIDER.store(
    encode_provider(config.chacha20poly1305_provider()),
    Ordering::Relaxed,
  );
}

fn encode_provider(provider: CryptoPrimitiveProvider) -> u8 {
  match provider {
    CryptoPrimitiveProvider::RustCrypto => PROVIDER_RUSTCRYPTO,
    CryptoPrimitiveProvider::AwsLcRs => PROVIDER_AWS_LC_RS,
  }
}

fn decode_provider(value: u8) -> CryptoPrimitiveProvider {
  match value {
    PROVIDER_AWS_LC_RS => CryptoPrimitiveProvider::AwsLcRs,
    _ => CryptoPrimitiveProvider::RustCrypto,
  }
}

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
  match decode_provider(SHA2_PROVIDER.load(Ordering::Relaxed)) {
    CryptoPrimitiveProvider::RustCrypto => rustcrypto_sha256(bytes),
    CryptoPrimitiveProvider::AwsLcRs => {
      let digest = aws_digest::digest(&aws_digest::SHA256, bytes);
      let mut out = [0u8; SHA256_LEN];
      out.copy_from_slice(digest.as_ref());
      out
    }
  }
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
  match decode_provider(HMAC_SHA256_PROVIDER.load(Ordering::Relaxed)) {
    CryptoPrimitiveProvider::RustCrypto => rustcrypto_hmac_sha256(key, value),
    CryptoPrimitiveProvider::AwsLcRs => {
      let key = aws_hmac::Key::new(aws_hmac::HMAC_SHA256, key);
      let tag = aws_hmac::sign(&key, value);
      let mut out = [0u8; SHA256_LEN];
      out.copy_from_slice(tag.as_ref());
      out
    }
  }
}

pub(crate) fn verify_hmac_sha256(key: &[u8], value: &[u8], tag: &[u8]) -> bool {
  if decode_provider(HMAC_SHA256_PROVIDER.load(Ordering::Relaxed))
    == CryptoPrimitiveProvider::AwsLcRs
  {
    let key = aws_hmac::Key::new(aws_hmac::HMAC_SHA256, key);
    return aws_hmac::verify(&key, value, tag).is_ok();
  }
  rustcrypto_verify_hmac_sha256(key, value, tag)
}

pub(crate) fn hkdf_sha256(
  salt: &[u8],
  secret: &[u8],
  info: &[u8],
  out: &mut [u8],
) -> anyhow::Result<()> {
  match decode_provider(HKDF_PROVIDER.load(Ordering::Relaxed)) {
    CryptoPrimitiveProvider::RustCrypto => {
      hkdf::Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(info, out)
        .map_err(|_| anyhow::anyhow!("failed to fill HKDF-SHA256 output"))?;
    }
    CryptoPrimitiveProvider::AwsLcRs => {
      let salt = aws_hkdf::Salt::new(aws_hkdf::HKDF_SHA256, salt);
      let prk = salt.extract(secret);
      prk
        .expand(&[info], HkdfOutputLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| anyhow::anyhow!("failed to fill AWS-LC HKDF-SHA256 output"))?;
    }
  }
  Ok(())
}

pub(crate) enum Aes256GcmKey {
  RustCrypto(Box<RustCryptoAes256Gcm>),
  AwsLcRs(AwsLessSafeKey),
}

impl Aes256GcmKey {
  pub(crate) fn new_from_slice(key: &[u8]) -> anyhow::Result<Self> {
    match decode_provider(AES_GCM_PROVIDER.load(Ordering::Relaxed)) {
      CryptoPrimitiveProvider::RustCrypto => Ok(Self::RustCrypto(Box::new(
        RustCryptoAes256Gcm::new_from_slice(key).context("AES-256-GCM requires a 32-byte key")?,
      ))),
      CryptoPrimitiveProvider::AwsLcRs => {
        let key = AwsUnboundKey::new(&AES_256_GCM, key)
          .map_err(|_| anyhow::anyhow!("AES-256-GCM requires a 32-byte key"))?;
        Ok(Self::AwsLcRs(AwsLessSafeKey::new(key)))
      }
    }
  }

  pub(crate) fn seal_in_place_append_tag(
    &self,
    nonce: [u8; 12],
    additional_data: &[u8],
    data: &mut Vec<u8>,
  ) -> Result<(), ()> {
    match self {
      Self::RustCrypto(key) => {
        let nonce = RustCryptoNonce::<RustCryptoAes256Gcm>::try_from(&nonce[..]).map_err(|_| ())?;
        key
          .encrypt_in_place(&nonce, additional_data, data)
          .map_err(|_| ())
      }
      Self::AwsLcRs(key) => key
        .seal_in_place_append_tag(
          AwsNonce::assume_unique_for_key(nonce),
          AwsAad::from(additional_data),
          data,
        )
        .map_err(|_| ()),
    }
  }

  pub(crate) fn open_in_place<'a>(
    &self,
    nonce: [u8; 12],
    additional_data: &[u8],
    data: &'a mut [u8],
  ) -> Result<&'a mut [u8], ()> {
    match self {
      Self::RustCrypto(key) => {
        if data.len() < 16 {
          return Err(());
        }
        let tag_start = data.len() - 16;
        let (ciphertext, tag) = data.split_at_mut(tag_start);
        let nonce = RustCryptoNonce::<RustCryptoAes256Gcm>::try_from(&nonce[..]).map_err(|_| ())?;
        let tag = RustCryptoTag::<RustCryptoAes256Gcm>::try_from(&*tag).map_err(|_| ())?;
        key
          .decrypt_inout_detached(&nonce, additional_data, ciphertext.into(), &tag)
          .map_err(|_| ())?;
        Ok(ciphertext)
      }
      Self::AwsLcRs(key) => key
        .open_in_place(
          AwsNonce::assume_unique_for_key(nonce),
          AwsAad::from(additional_data),
          data,
        )
        .map_err(|_| ()),
    }
  }
}

struct HkdfOutputLen(usize);

impl aws_hkdf::KeyType for HkdfOutputLen {
  fn len(&self) -> usize {
    self.0
  }
}

fn rustcrypto_sha256(bytes: &[u8]) -> [u8; SHA256_LEN] {
  let digest = Sha256::digest(bytes);
  let mut out = [0u8; SHA256_LEN];
  out.copy_from_slice(&digest);
  out
}

fn rustcrypto_hmac_sha256(key: &[u8], value: &[u8]) -> [u8; SHA256_LEN] {
  let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
  mac.update(value);
  let tag = mac.finalize().into_bytes();
  let mut out = [0u8; SHA256_LEN];
  out.copy_from_slice(&tag);
  out
}

fn rustcrypto_verify_hmac_sha256(key: &[u8], value: &[u8], tag: &[u8]) -> bool {
  let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
  mac.update(value);
  mac.verify_slice(tag).is_ok()
}
