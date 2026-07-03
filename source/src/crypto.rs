//! Small crypto primitive adapters used by OxiBelt-owned protocol code.
//! These helpers keep fixed algorithms and constant-time tag checks explicit.

use std::sync::atomic::{AtomicU8, Ordering};

use aes_gcm::Aes256Gcm as RustCryptoAes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit as AeadKeyInit};
use aes_gcm::aead::{Nonce as RustCryptoNonce, Tag as RustCryptoTag};
use anyhow::Context;
use aws_lc_rs::aead::{
  AES_256_GCM, Aad as AwsAad, CHACHA20_POLY1305, LessSafeKey as AwsLessSafeKey, Nonce as AwsNonce,
  UnboundKey as AwsUnboundKey,
};
use aws_lc_rs::{digest as aws_digest, hkdf as aws_hkdf, hmac as aws_hmac};
use chacha20poly1305::ChaCha20Poly1305 as RustCryptoChaCha20Poly1305;
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

// The config surface exposes ChaCha20-Poly1305 before a production path needs
// this direct helper; unit tests exercise both providers until then.
#[allow(dead_code)]
pub(crate) enum ChaCha20Poly1305Key {
  RustCrypto(Box<RustCryptoChaCha20Poly1305>),
  AwsLcRs(AwsLessSafeKey),
}

#[allow(dead_code)]
impl ChaCha20Poly1305Key {
  pub(crate) fn new_from_slice(key: &[u8]) -> anyhow::Result<Self> {
    match decode_provider(CHACHA20POLY1305_PROVIDER.load(Ordering::Relaxed)) {
      CryptoPrimitiveProvider::RustCrypto => Ok(Self::RustCrypto(Box::new(
        RustCryptoChaCha20Poly1305::new_from_slice(key)
          .context("ChaCha20-Poly1305 requires a 32-byte key")?,
      ))),
      CryptoPrimitiveProvider::AwsLcRs => {
        let key = AwsUnboundKey::new(&CHACHA20_POLY1305, key)
          .map_err(|_| anyhow::anyhow!("ChaCha20-Poly1305 requires a 32-byte key"))?;
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
        let nonce =
          RustCryptoNonce::<RustCryptoChaCha20Poly1305>::try_from(&nonce[..]).map_err(|_| ())?;
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
        let nonce =
          RustCryptoNonce::<RustCryptoChaCha20Poly1305>::try_from(&nonce[..]).map_err(|_| ())?;
        let tag = RustCryptoTag::<RustCryptoChaCha20Poly1305>::try_from(&*tag).map_err(|_| ())?;
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

#[cfg(test)]
mod tests {
  use super::*;

  use crate::config::{CryptoPrimitiveBackendOverrides, CryptoPrimitiveOverrides};

  static PROVIDER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

  fn config(provider: CryptoPrimitiveProvider) -> CryptoConfig {
    CryptoConfig {
      primitive_provider: provider,
      primitive_backend: crate::config::CryptoPrimitiveBackend::Auto,
      primitives: CryptoPrimitiveOverrides::default(),
      primitive_backends: CryptoPrimitiveBackendOverrides::default(),
      ..CryptoConfig::default()
    }
  }

  fn with_provider(provider: CryptoPrimitiveProvider, test: impl FnOnce()) {
    let _guard = PROVIDER_TEST_LOCK
      .lock()
      .expect("provider test lock poisoned");
    configure_runtime(&config(provider));
    test();
    configure_runtime(&CryptoConfig::default());
  }

  #[test]
  fn sha_hmac_hkdf_match_between_configured_providers() {
    let mut rustcrypto_hkdf = [0u8; 42];
    let mut aws_lc_hkdf = [0u8; 42];
    let mut rustcrypto_sha = [0u8; SHA256_LEN];
    let mut aws_lc_sha = [0u8; SHA256_LEN];
    let mut rustcrypto_hmac = [0u8; SHA256_LEN];
    let mut aws_lc_hmac = [0u8; SHA256_LEN];

    with_provider(CryptoPrimitiveProvider::RustCrypto, || {
      rustcrypto_sha = sha256(b"hash material");
      rustcrypto_hmac = hmac_sha256(b"key", b"message");
      assert!(verify_hmac_sha256(b"key", b"message", &rustcrypto_hmac));
      assert!(!verify_hmac_sha256(b"key", b"tampered", &rustcrypto_hmac));
      hkdf_sha256(b"salt", b"secret", b"context", &mut rustcrypto_hkdf)
        .expect("RustCrypto HKDF should fill output");
    });

    with_provider(CryptoPrimitiveProvider::AwsLcRs, || {
      aws_lc_sha = sha256(b"hash material");
      aws_lc_hmac = hmac_sha256(b"key", b"message");
      assert!(verify_hmac_sha256(b"key", b"message", &aws_lc_hmac));
      assert!(!verify_hmac_sha256(b"key", b"tampered", &aws_lc_hmac));
      hkdf_sha256(b"salt", b"secret", b"context", &mut aws_lc_hkdf)
        .expect("AWS-LC HKDF should fill output");
    });

    assert_eq!(rustcrypto_sha, aws_lc_sha);
    assert_eq!(rustcrypto_hmac, aws_lc_hmac);
    assert_eq!(rustcrypto_hkdf, aws_lc_hkdf);
  }

  #[test]
  fn aes_gcm_round_trips_with_configured_providers() {
    with_provider(CryptoPrimitiveProvider::RustCrypto, || {
      assert_aes_gcm_round_trip();
    });
    with_provider(CryptoPrimitiveProvider::AwsLcRs, || {
      assert_aes_gcm_round_trip();
    });
  }

  #[test]
  fn chacha20poly1305_round_trips_with_configured_providers() {
    with_provider(CryptoPrimitiveProvider::RustCrypto, || {
      assert_chacha20poly1305_round_trip();
    });
    with_provider(CryptoPrimitiveProvider::AwsLcRs, || {
      assert_chacha20poly1305_round_trip();
    });
  }

  fn assert_aes_gcm_round_trip() {
    let key = Aes256GcmKey::new_from_slice(&[7u8; 32]).expect("key length should be valid");
    let mut data = b"plaintext".to_vec();
    key
      .seal_in_place_append_tag([3u8; 12], b"aad", &mut data)
      .expect("seal should succeed");
    assert!(data.len() > b"plaintext".len());

    let mut tampered = data.clone();
    tampered[0] ^= 0x80;
    assert!(key.open_in_place([3u8; 12], b"aad", &mut tampered).is_err());

    let plaintext = key
      .open_in_place([3u8; 12], b"aad", &mut data)
      .expect("open should succeed");
    assert_eq!(plaintext, b"plaintext");
  }

  fn assert_chacha20poly1305_round_trip() {
    let key = ChaCha20Poly1305Key::new_from_slice(&[9u8; 32]).expect("key length should be valid");
    let mut data = b"plaintext".to_vec();
    key
      .seal_in_place_append_tag([5u8; 12], b"aad", &mut data)
      .expect("seal should succeed");
    assert!(data.len() > b"plaintext".len());

    let mut tampered = data.clone();
    tampered[0] ^= 0x80;
    assert!(key.open_in_place([5u8; 12], b"aad", &mut tampered).is_err());

    let plaintext = key
      .open_in_place([5u8; 12], b"aad", &mut data)
      .expect("open should succeed");
    assert_eq!(plaintext, b"plaintext");
  }
}
