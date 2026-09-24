//! Asymmetric JWK verification for the Web Bot Auth HTTP signature profile.

use aws_lc_rs::signature::{
  ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, RSA_PKCS1_2048_8192_SHA256,
  RSA_PSS_2048_8192_SHA512, RsaPublicKeyComponents, UnparsedPublicKey,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::protocol::Candidate;

fn member<'a>(jwk: &'a Value, name: &str) -> Option<&'a str> {
  jwk.get(name)?.as_str()
}
fn bytes(jwk: &Value, name: &str) -> Option<Vec<u8>> {
  let encoded = member(jwk, name)?;
  let decoded = URL_SAFE_NO_PAD.decode(encoded).ok()?;
  if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
    return None;
  }
  Some(decoded)
}

/// RFC 7638 SHA-256 thumbprint, including the RFC 8037 OKP member set.
pub fn jwk_thumbprint(jwk: &Value) -> Option<String> {
  let canonical = match member(jwk, "kty")? {
    "RSA" => {
      bytes(jwk, "n")?;
      bytes(jwk, "e")?;
      serde_json::json!({"e": member(jwk, "e")?, "kty":"RSA", "n": member(jwk, "n")?})
    }
    "EC" => {
      let curve = member(jwk, "crv")?;
      if !matches!(curve, "P-256" | "P-384") {
        return None;
      }
      bytes(jwk, "x")?;
      bytes(jwk, "y")?;
      serde_json::json!({"crv": curve, "kty":"EC", "x": member(jwk, "x")?, "y": member(jwk, "y")?})
    }
    "OKP" => {
      if member(jwk, "crv")? != "Ed25519" {
        return None;
      }
      bytes(jwk, "x")?;
      serde_json::json!({"crv":"Ed25519", "kty":"OKP", "x": member(jwk, "x")?})
    }
    _ => return None,
  };
  let digest = Sha256::digest(serde_json::to_vec(&canonical).ok()?);
  Some(URL_SAFE_NO_PAD.encode(digest))
}

fn permitted_algorithm(candidate: &Candidate, jwk: &Value, alg: &str) -> bool {
  candidate.alg.as_deref().is_none_or(|value| value == alg)
    && jwk
      .get("alg")
      .is_none_or(|value| value.as_str() == Some(alg))
}

/// Verify the signature against a public JWK whose thumbprint matches `keyid`.
/// Shared-secret JWKs and all unregistered algorithms fail closed.
pub fn verify_candidate(candidate: &Candidate, jwk: &Value) -> bool {
  if jwk_thumbprint(jwk).as_deref() != Some(candidate.keyid.as_str()) {
    return false;
  }
  if jwk
    .get("kid")
    .is_some_and(|value| value.as_str() != Some(candidate.keyid.as_str()))
  {
    return false;
  }
  if jwk
    .get("use")
    .is_some_and(|value| value.as_str() != Some("sig"))
  {
    return false;
  }
  if jwk.get("key_ops").is_some_and(|value| {
    !value
      .as_array()
      .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")))
  }) {
    return false;
  }
  match member(jwk, "kty") {
    Some("OKP")
      if member(jwk, "crv") == Some("Ed25519")
        && permitted_algorithm(candidate, jwk, "ed25519") =>
    {
      let Some(x) = bytes(jwk, "x") else {
        return false;
      };
      x.len() == 32
        && UnparsedPublicKey::new(&ED25519, x)
          .verify(&candidate.signature_base, &candidate.signature)
          .is_ok()
    }
    Some("EC") => {
      let (algorithm, coordinate_len, alg) = match member(jwk, "crv") {
        Some("P-256") => (&ECDSA_P256_SHA256_FIXED, 32, "ecdsa-p256-sha256"),
        Some("P-384") => (&ECDSA_P384_SHA384_FIXED, 48, "ecdsa-p384-sha384"),
        _ => return false,
      };
      if !permitted_algorithm(candidate, jwk, alg) {
        return false;
      }
      let (Some(x), Some(y)) = (bytes(jwk, "x"), bytes(jwk, "y")) else {
        return false;
      };
      if x.len() != coordinate_len || y.len() != coordinate_len {
        return false;
      }
      let mut point = Vec::with_capacity(1 + 2 * coordinate_len);
      point.push(4);
      point.extend_from_slice(&x);
      point.extend_from_slice(&y);
      UnparsedPublicKey::new(algorithm, point)
        .verify(&candidate.signature_base, &candidate.signature)
        .is_ok()
    }
    Some("RSA") => {
      let (Some(n), Some(e)) = (bytes(jwk, "n"), bytes(jwk, "e")) else {
        return false;
      };
      let key = RsaPublicKeyComponents { n: &n, e: &e };
      [
        ("rsa-pss-sha512", &RSA_PSS_2048_8192_SHA512),
        ("rsa-v1_5-sha256", &RSA_PKCS1_2048_8192_SHA256),
      ]
      .into_iter()
      .any(|(alg, params)| {
        permitted_algorithm(candidate, jwk, alg)
          && key.to_parsed_public_key(params).is_ok_and(|public| {
            public
              .verify_sig(&candidate.signature_base, &candidate.signature)
              .is_ok()
          })
      })
    }
    _ => false,
  }
}

#[cfg(test)]
mod tests {
  use super::super::protocol::{DiscoveryKind, DiscoveryReference};
  use super::*;
  use aws_lc_rs::rand::SystemRandom;
  use aws_lc_rs::rsa::KeySize;
  use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair,
    KeyPair as _, RSA_PKCS1_SHA256, RSA_PSS_SHA512, RsaEncoding, RsaKeyPair,
  };
  use url::Url;
  #[test]
  fn rfc8037_ed25519_thumbprint() {
    let key = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"});
    assert_eq!(
      jwk_thumbprint(&key).as_deref(),
      Some("poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U")
    );
  }
  #[test]
  fn symmetric_keys_have_no_thumbprint() {
    assert!(jwk_thumbprint(&serde_json::json!({"kty":"oct","k":"AA"})).is_none());
  }

  #[test]
  fn verifies_ed25519_and_rejects_wrong_algorithm() {
    let key = Ed25519KeyPair::generate().unwrap();
    let jwk = serde_json::json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.public_key().as_ref()), "use":"sig"});
    let base = b"\"@authority\": example.test\n\"@signature-params\": ()".to_vec();
    let mut candidate = Candidate {
      reference: DiscoveryReference {
        url: Url::parse("https://keys.example.test").unwrap(),
        kind: DiscoveryKind::Directory,
      },
      keyid: jwk_thumbprint(&jwk).unwrap(),
      alg: Some("ed25519".into()),
      signature: key.sign(&base).as_ref().to_vec(),
      signature_base: base,
      covers_content_digest: false,
    };
    assert!(verify_candidate(&candidate, &jwk));
    let mismatched_kid = serde_json::json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.public_key().as_ref()), "use":"sig", "kid":"wrong"});
    assert!(!verify_candidate(&candidate, &mismatched_kid));
    candidate.alg = Some("hmac-sha256".into());
    assert!(!verify_candidate(&candidate, &jwk));
  }

  #[test]
  fn verifies_fixed_ecdsa_p256_and_p384() {
    let random = SystemRandom::new();
    let base = b"signed HTTP request";
    for (signing, curve, coordinate_len, alg, wrong) in [
      (
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        "P-256",
        32,
        "ecdsa-p256-sha256",
        "ecdsa-p384-sha384",
      ),
      (
        &ECDSA_P384_SHA384_FIXED_SIGNING,
        "P-384",
        48,
        "ecdsa-p384-sha384",
        "ecdsa-p256-sha256",
      ),
    ] {
      let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing, &random).unwrap();
      let key = EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref()).unwrap();
      let point = key.public_key().as_ref();
      assert_eq!(point.len(), 1 + 2 * coordinate_len);
      assert_eq!(point[0], 4);
      let jwk = serde_json::json!({
        "kty":"EC", "crv":curve, "use":"sig",
        "x": URL_SAFE_NO_PAD.encode(&point[1..1 + coordinate_len]),
        "y": URL_SAFE_NO_PAD.encode(&point[1 + coordinate_len..]),
      });
      let signature = key.sign(&random, base).unwrap();
      let mut candidate = Candidate {
        reference: DiscoveryReference {
          url: Url::parse("https://keys.example.test").unwrap(),
          kind: DiscoveryKind::Directory,
        },
        keyid: jwk_thumbprint(&jwk).unwrap(),
        alg: Some(alg.into()),
        signature: signature.as_ref().to_vec(),
        signature_base: base.to_vec(),
        covers_content_digest: false,
      };
      assert!(verify_candidate(&candidate, &jwk), "{alg} should verify");
      candidate.alg = Some(wrong.into());
      assert!(
        !verify_candidate(&candidate, &jwk),
        "{wrong} mismatch should fail"
      );
    }
  }

  // The generated public key is RFC 8017 RSAPublicKey DER: SEQUENCE of n and e.
  fn der_tlv<'a>(input: &mut &'a [u8], tag: u8) -> &'a [u8] {
    assert_eq!(input[0], tag);
    *input = &input[1..];
    let first = input[0];
    *input = &input[1..];
    let len = if first < 128 {
      usize::from(first)
    } else {
      let count = usize::from(first & 0x7f);
      assert!((1..=4).contains(&count));
      let mut len = 0usize;
      for byte in &input[..count] {
        len = (len << 8) | usize::from(*byte);
      }
      *input = &input[count..];
      len
    };
    let (value, rest) = input.split_at(len);
    *input = rest;
    value
  }

  #[test]
  fn verifies_rsa_pss_and_pkcs1_v15() {
    let random = SystemRandom::new();
    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let mut der = key.public_key().as_ref();
    let mut sequence = der_tlv(&mut der, 0x30);
    let n = der_tlv(&mut sequence, 0x02);
    let e = der_tlv(&mut sequence, 0x02);
    assert!(der.is_empty() && sequence.is_empty());
    let jwk = serde_json::json!({
      "kty":"RSA", "use":"sig",
      "n":URL_SAFE_NO_PAD.encode(n.strip_prefix(&[0]).unwrap_or(n)),
      "e":URL_SAFE_NO_PAD.encode(e.strip_prefix(&[0]).unwrap_or(e)),
    });
    let base = b"signed HTTP request";
    let algorithms: [(&'static dyn RsaEncoding, &str, &str); 2] = [
      (&RSA_PSS_SHA512, "rsa-pss-sha512", "rsa-v1_5-sha256"),
      (&RSA_PKCS1_SHA256, "rsa-v1_5-sha256", "rsa-pss-sha512"),
    ];
    for (signing, alg, wrong) in algorithms {
      let mut signature = vec![0; key.public_modulus_len()];
      key.sign(signing, &random, base, &mut signature).unwrap();
      let mut candidate = Candidate {
        reference: DiscoveryReference {
          url: Url::parse("https://keys.example.test").unwrap(),
          kind: DiscoveryKind::Directory,
        },
        keyid: jwk_thumbprint(&jwk).unwrap(),
        alg: Some(alg.into()),
        signature,
        signature_base: base.to_vec(),
        covers_content_digest: false,
      };
      assert!(verify_candidate(&candidate, &jwk), "{alg} should verify");
      candidate.alg = Some(wrong.into());
      assert!(
        !verify_candidate(&candidate, &jwk),
        "{wrong} mismatch should fail"
      );
    }
  }
}
