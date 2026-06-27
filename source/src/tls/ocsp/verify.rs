//! OCSP request construction and response verification.
//! This module is shared by downstream stapling and outbound revocation checks.

use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use sha1::Digest;
use url::Url;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::AuthorityInfoAccessSyntax;
use x509_cert::ext::pkix::name::GeneralName;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::{
  BasicOcspResponse, CertId, CertStatus, OcspResponse, OcspResponseStatus, Request, ResponderId,
  Version,
};

use super::cert_id::{build_sha1_cert_id, cert_ids_match};

const ID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";
const ID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
const ID_KP_OCSP_SIGNING_DER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

#[derive(Clone)]
pub(in crate::tls) struct OcspRequestContext {
  pub(in crate::tls) responder_url: Url,
  pub(in crate::tls) request_der: Vec<u8>,
  pub(in crate::tls) verification: OcspVerificationContext,
}

#[derive(Clone)]
pub(in crate::tls) struct OcspVerificationContext {
  expected_cert_id: CertId,
  issuer_der: Vec<u8>,
  clock_skew: Duration,
}

pub(in crate::tls) fn build_ocsp_request_context(
  leaf_der: &[u8],
  issuer_der: &[u8],
  responder_url: Option<&str>,
  clock_skew: Duration,
) -> anyhow::Result<OcspRequestContext> {
  let leaf = Certificate::from_der(leaf_der).context("failed to parse leaf certificate")?;
  let issuer = Certificate::from_der(issuer_der).context("failed to parse issuer certificate")?;
  let expected_cert_id = build_sha1_cert_id(&issuer, &leaf)
    .map_err(|error| anyhow!("failed to build OCSP CertID: {error}"))?;
  let request = Request::new(expected_cert_id.clone());
  let request_der = OcspRequestBuilder::new(Version::V1)
    .with_request(request)
    .build()
    .to_der()
    .context("failed to encode OCSP request")?;
  let responder_url = match responder_url {
    Some(raw) => Url::parse(raw).context("invalid tls.ocsp.responder_url")?,
    None => first_ocsp_aia_url(&leaf)?,
  };
  validate_responder_url(&responder_url)?;
  Ok(OcspRequestContext {
    responder_url,
    request_der,
    verification: OcspVerificationContext {
      expected_cert_id,
      issuer_der: issuer_der.to_vec(),
      clock_skew,
    },
  })
}

#[derive(Clone)]
pub(in crate::tls) struct VerifiedOcspResponse {
  pub(in crate::tls) response_der: Vec<u8>,
  pub(in crate::tls) this_update: SystemTime,
  pub(in crate::tls) next_update: SystemTime,
}

pub(in crate::tls) fn verify_ocsp_response(
  context: &OcspVerificationContext,
  response_der: &[u8],
) -> anyhow::Result<VerifiedOcspResponse> {
  let outer = OcspResponse::from_der(response_der).context("ocsp_parse")?;
  if outer.response_status != OcspResponseStatus::Successful {
    bail!("ocsp_unsuccessful_status");
  }
  let response_bytes = outer
    .response_bytes
    .ok_or_else(|| anyhow!("ocsp_no_response_bytes"))?;
  if response_bytes.response_type.to_string() != ID_PKIX_OCSP_BASIC {
    bail!("ocsp_unsupported_response_type");
  }
  let basic =
    BasicOcspResponse::from_der(response_bytes.response.as_bytes()).context("ocsp_basic_parse")?;
  verify_ocsp_signature(context, &basic)?;
  let now = SystemTime::now();
  let produced_at = basic.tbs_response_data.produced_at.0.to_system_time();
  if produced_at > now + context.clock_skew {
    bail!("ocsp_produced_at_future");
  }
  if basic.tbs_response_data.responses.len() != 1 {
    bail!("ocsp_response_count");
  }
  let single = &basic.tbs_response_data.responses[0];
  if !cert_ids_match(&single.cert_id, &context.expected_cert_id) {
    bail!("ocsp_cert_id_mismatch");
  }
  if !matches!(single.cert_status, CertStatus::Good(_)) {
    bail!("ocsp_cert_status");
  }
  let this_update = single.this_update.0.to_system_time();
  if this_update > now + context.clock_skew {
    bail!("ocsp_this_update_future");
  }
  let next_update = single
    .next_update
    .as_ref()
    .ok_or_else(|| anyhow!("ocsp_missing_next_update"))?
    .0
    .to_system_time();
  if next_update <= this_update {
    bail!("ocsp_invalid_update_window");
  }
  if next_update <= now {
    bail!("ocsp_stale_response");
  }
  Ok(VerifiedOcspResponse {
    response_der: response_der.to_vec(),
    this_update,
    next_update,
  })
}

fn verify_ocsp_signature(
  context: &OcspVerificationContext,
  basic: &BasicOcspResponse,
) -> anyhow::Result<()> {
  let tbs_der = basic
    .tbs_response_data
    .to_der()
    .context("failed to encode OCSP tbsResponseData")?;
  let signature = basic
    .signature
    .as_bytes()
    .ok_or_else(|| anyhow!("ocsp_signature_unused_bits"))?;
  let algorithm_der = basic
    .signature_algorithm
    .to_der()
    .context("failed to encode OCSP signature algorithm")?;

  let issuer = Certificate::from_der(&context.issuer_der).context("failed to parse issuer")?;
  if responder_id_matches_cert(&basic.tbs_response_data.responder_id, &issuer)?
    && verify_signature_with_cert(&context.issuer_der, &algorithm_der, &tbs_der, signature).is_ok()
  {
    return Ok(());
  }

  for responder in basic.certs.as_deref().unwrap_or(&[]) {
    if !responder_id_matches_cert(&basic.tbs_response_data.responder_id, responder)? {
      continue;
    }
    let responder_der = responder
      .to_der()
      .context("failed to encode delegated OCSP responder certificate")?;
    verify_delegated_responder_cert(&responder_der, &context.issuer_der)?;
    verify_signature_with_cert(&responder_der, &algorithm_der, &tbs_der, signature)
      .context("ocsp_signature")?;
    return Ok(());
  }
  bail!("ocsp_unauthorized_responder")
}

fn verify_signature_with_cert(
  cert_der: &[u8],
  algorithm_der: &[u8],
  message: &[u8],
  signature: &[u8],
) -> anyhow::Result<()> {
  let cert_der = CertificateDer::from(cert_der.to_vec());
  let cert = EndEntityCert::try_from(&cert_der).context("failed to parse OCSP signer cert")?;
  for algorithm in supported_signature_algorithms() {
    if algorithm.signature_alg_id().as_ref() != algorithm_der {
      continue;
    }
    cert
      .verify_signature(algorithm, message, signature)
      .context("signature verification failed")?;
    return Ok(());
  }
  bail!("ocsp_unsupported_signature_algorithm")
}

fn verify_delegated_responder_cert(responder_der: &[u8], issuer_der: &[u8]) -> anyhow::Result<()> {
  let responder_der = CertificateDer::from(responder_der.to_vec());
  let responder =
    EndEntityCert::try_from(&responder_der).context("failed to parse delegated OCSP responder")?;
  let issuer = CertificateDer::from(issuer_der.to_vec());
  let anchors = [anchor_from_trusted_cert(&issuer).context("failed to build issuer trust anchor")?];
  let intermediates: [CertificateDer<'_>; 0] = [];
  let supported = supported_signature_algorithms();
  responder
    .verify_for_usage(
      &supported,
      &anchors,
      &intermediates,
      UnixTime::now(),
      KeyUsage::required(ID_KP_OCSP_SIGNING_DER),
      None,
      None,
    )
    .context("ocsp_responder_cert")?;
  Ok(())
}

fn supported_signature_algorithms() -> [&'static dyn SignatureVerificationAlgorithm; 20] {
  [
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P256_SHA512,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA512,
    webpki::aws_lc_rs::ECDSA_P521_SHA256,
    webpki::aws_lc_rs::ECDSA_P521_SHA384,
    webpki::aws_lc_rs::ECDSA_P521_SHA512,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    webpki::aws_lc_rs::RSA_PKCS1_3072_8192_SHA384,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::aws_lc_rs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    webpki::aws_lc_rs::ED25519,
  ]
}

fn responder_id_matches_cert(
  responder_id: &ResponderId,
  cert: &Certificate,
) -> anyhow::Result<bool> {
  match responder_id {
    ResponderId::ByName(name) => Ok(name == &cert.tbs_certificate.subject),
    ResponderId::ByKey(hash) => {
      let actual = sha1::Sha1::digest(
        cert
          .tbs_certificate
          .subject_public_key_info
          .subject_public_key
          .raw_bytes(),
      );
      Ok(hash.as_bytes() == actual.as_slice())
    }
  }
}

fn first_ocsp_aia_url(leaf: &Certificate) -> anyhow::Result<Url> {
  let aia = leaf
    .tbs_certificate
    .get::<AuthorityInfoAccessSyntax>()
    .context("failed to parse authorityInfoAccess")?
    .map(|(_, aia)| aia)
    .ok_or_else(|| anyhow!("tls leaf certificate does not include an OCSP AIA responder"))?;
  for access in aia.0 {
    if access.access_method.to_string() != ID_AD_OCSP {
      continue;
    }
    let GeneralName::UniformResourceIdentifier(uri) = access.access_location else {
      continue;
    };
    let url = Url::parse(uri.as_ref()).context("invalid OCSP AIA responder URL")?;
    validate_responder_url(&url)?;
    return Ok(url);
  }
  bail!("tls leaf certificate does not include an HTTP OCSP AIA responder")
}

fn validate_responder_url(url: &Url) -> anyhow::Result<()> {
  if !matches!(url.scheme(), "http" | "https") {
    bail!("tls.ocsp.responder_url scheme must be http or https");
  }
  if url.host_str().is_none() {
    bail!("tls.ocsp.responder_url must include a host");
  }
  if !url.username().is_empty() || url.password().is_some() {
    bail!("tls.ocsp.responder_url must not include credentials");
  }
  if url.fragment().is_some() {
    bail!("tls.ocsp.responder_url must not include a fragment");
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn responder_url_policy_rejects_ssrf_prone_shapes() {
    for raw in [
      "ftp://ocsp.example.test/status",
      "https://user:pass@ocsp.example.test/status",
      "https://ocsp.example.test/status#fragment",
    ] {
      let url = Url::parse(raw).expect("test URL should parse");
      assert!(
        validate_responder_url(&url).is_err(),
        "{raw} should be rejected"
      );
    }

    let url = Url::parse("https://ocsp.example.test/status").expect("test URL should parse");
    validate_responder_url(&url).expect("plain HTTPS OCSP URL should be accepted");
  }
}
