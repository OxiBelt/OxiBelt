use super::super::{VerificationStatus, WebBotAuthRuntime, prepare_request};
use super::*;
use crate::config::WebBotAuthConfig;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::Full;
use sha2::{Digest, Sha256};

fn signed_request(agent: &str, covered: &str) -> Request<()> {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
  Request::builder()
    .uri("/resource?x=one+two")
    .header("host", "example.test")
    .header("signature-agent", agent)
    .header(
      "signature-input",
      format!(
        "sig=({covered});created={now};expires={};keyid=\"key\";tag=\"web-bot-auth\"",
        now + 60
      ),
    )
    .header("signature", "sig=:AQID:")
    .body(())
    .unwrap()
}

#[test]
fn binds_dictionary_member_and_extra_components() {
  let request = signed_request(
    "sig=\"https://keys.example.test\"",
    "\"@authority\" \"@path\" \"@query-param\";name=\"x\" \"signature-agent\";key=\"sig\"",
  );
  let parsed = parse_request(&request, "https", 300, 5);
  assert!(!parsed.had_invalid);
  assert_eq!(parsed.candidates.len(), 1);
  let base = String::from_utf8(parsed.candidates[0].signature_base.clone()).unwrap();
  assert!(base.contains("\"@authority\": example.test\n"));
  assert!(base.contains("\"@query-param\";name=\"x\": one%20two\n"));
  assert!(base.contains("\"signature-agent\";key=\"sig\": \"https://keys.example.test\"\n"));
}

#[test]
fn refuses_unsigned_or_wrong_dictionary_member() {
  let request = signed_request(
    "sig=\"https://keys.example.test\"",
    "\"@authority\" \"signature-agent\";key=\"other\"",
  );
  let parsed = parse_request(&request, "https", 300, 5);
  assert!(parsed.had_invalid);
  assert!(parsed.candidates.is_empty());
}

#[test]
fn query_parameter_uses_rfc9421_percent_encoding() {
  let request = Request::builder()
    .uri("/path?bar=with+plus+whitespace")
    .header("host", "example.test")
    .body(())
    .unwrap();
  let item = Item {
    bare: BareItem::String(sfv::String::from_string("@query-param".into()).unwrap()),
    params: vec![(
      "name".into(),
      BareItem::String(sfv::String::from_string("bar".into()).unwrap()),
    )],
  };
  assert_eq!(
    derived(&request, "https", &item).as_deref(),
    Some("with%20plus%20whitespace")
  );
}

#[test]
fn accepts_legacy_bare_string_only_when_signed_as_bare_field() {
  let request = signed_request(
    "\"https://keys.example.test\"",
    "\"@authority\" \"signature-agent\"",
  );
  let parsed = parse_request(&request, "https", 300, 5);
  assert!(!parsed.had_invalid);
  assert_eq!(parsed.candidates.len(), 1);
  assert!(
    String::from_utf8_lossy(&parsed.candidates[0].signature_base)
      .contains("\"signature-agent\": \"https://keys.example.test\"\n")
  );
}

#[test]
fn accepts_legacy_bare_string_with_leading_ows() {
  let request = signed_request(
    "  \"https://keys.example.test\"",
    "\"@authority\" \"signature-agent\"",
  );
  let parsed = parse_request(&request, "https", 300, 5);
  assert!(!parsed.had_invalid);
  assert_eq!(parsed.candidates.len(), 1);
}

#[tokio::test]
async fn signed_request_verifies_and_mutated_path_or_body_fails() {
  let config = WebBotAuthConfig {
    enabled: true,
    ..WebBotAuthConfig::default()
  };
  let runtime = WebBotAuthRuntime::new(&config).unwrap();
  let key = Ed25519KeyPair::generate().unwrap();
  let jwk = serde_json::json!({
    "kty": "OKP", "crv": "Ed25519", "use": "sig",
    "x": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
  });
  let keyid = super::super::crypto::jwk_thumbprint(&jwk).unwrap();
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();
  let payload = Bytes::from_static(b"hello");
  let digest = STANDARD.encode(Sha256::digest(payload.as_ref()));
  let input = format!(
    "sig=(\"@authority\" \"@method\" \"@path\" \"content-digest\" \"signature-agent\";key=\"sig\");created={now};expires={};keyid=\"{keyid}\";alg=\"ed25519\";tag=\"web-bot-auth\"",
    now + 60,
  );
  let build = |path: &'static str, body: Bytes, signature: &str| {
    Request::builder()
      .method("POST")
      .uri(path)
      .header("host", "origin.example.test")
      .header("content-digest", format!("sha-256=:{digest}:"))
      .header("signature-agent", "sig=\"https://keys.example.test\"")
      .header("signature-input", input.as_str())
      .header("signature", signature)
      .body(Full::new(body))
      .unwrap()
  };
  let unsigned = build("/resource", payload.clone(), "sig=:AA==:");
  let parsed = parse_request(&unsigned, "https", config.max_signature_age_seconds, 60);
  assert_eq!(parsed.candidates.len(), 1);
  runtime
    .discovery
    .seed_for_test(&parsed.candidates[0].reference, vec![jwk]);
  let signature = format!(
    "sig=:{}:",
    STANDARD.encode(key.sign(&parsed.candidates[0].signature_base).as_ref())
  );

  let verified = prepare_request(
    build("/resource", payload.clone(), &signature),
    "https",
    &runtime,
    &config,
  )
  .await;
  let result = verified
    .extensions()
    .get::<super::super::WebBotAuthResult>()
    .unwrap();
  assert_eq!(result.status, VerificationStatus::Verified);
  assert_eq!(result.verified_urls.len(), 1);
  assert_eq!(
    result.verified_urls[0],
    "https://keys.example.test/.well-known/http-message-signatures-directory"
  );

  let wrong_path = prepare_request(
    build("/other", payload.clone(), &signature),
    "https",
    &runtime,
    &config,
  )
  .await;
  assert_eq!(
    wrong_path
      .extensions()
      .get::<super::super::WebBotAuthResult>()
      .unwrap()
      .status,
    VerificationStatus::Invalid
  );

  let wrong_body = prepare_request(
    build("/resource", Bytes::from_static(b"altered"), &signature),
    "https",
    &runtime,
    &config,
  )
  .await;
  assert_eq!(
    wrong_body
      .extensions()
      .get::<super::super::WebBotAuthResult>()
      .unwrap()
      .status,
    VerificationStatus::Invalid
  );
}
