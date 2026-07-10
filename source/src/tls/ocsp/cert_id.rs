use sha1::Digest;
use x509_cert_v2::Certificate;
use x509_cert_v2::der::{
  Encode,
  asn1::{Any, AnyRef, Null, ObjectIdentifier, OctetString},
};
use x509_cert_v2::spki::AlgorithmIdentifierOwned;
use x509_ocsp::CertId;

const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

pub(super) fn build_sha1_cert_id(
  issuer: &Certificate,
  leaf: &Certificate,
) -> anyhow::Result<CertId> {
  Ok(CertId {
    hash_algorithm: AlgorithmIdentifierOwned {
      oid: ID_SHA1,
      parameters: Some(Null.into()),
    },
    issuer_name_hash: OctetString::new(
      sha1::Sha1::digest(issuer.tbs_certificate.subject.to_der()?).to_vec(),
    )?,
    issuer_key_hash: OctetString::new(
      sha1::Sha1::digest(
        issuer
          .tbs_certificate
          .subject_public_key_info
          .subject_public_key
          .raw_bytes(),
      )
      .to_vec(),
    )?,
    serial_number: leaf.tbs_certificate.serial_number.clone(),
  })
}

pub(super) fn cert_ids_match(response: &CertId, expected: &CertId) -> bool {
  hash_algorithms_match(&response.hash_algorithm, &expected.hash_algorithm)
    && response.issuer_name_hash == expected.issuer_name_hash
    && response.issuer_key_hash == expected.issuer_key_hash
    && response.serial_number == expected.serial_number
}

fn hash_algorithms_match(
  response: &AlgorithmIdentifierOwned,
  expected: &AlgorithmIdentifierOwned,
) -> bool {
  if response.oid != expected.oid {
    return false;
  }

  if response.oid == ID_SHA1 {
    return sha1_parameters_match(&response.parameters)
      && sha1_parameters_match(&expected.parameters);
  }

  response.parameters == expected.parameters
}

fn sha1_parameters_match(parameters: &Option<Any>) -> bool {
  match parameters.as_ref() {
    Some(parameters) => AnyRef::from(parameters).is_null(),
    None => true,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use x509_cert_v2::der::Decode;

  const CERT_ID_WITH_SHA1_NULL_PARAMETERS_DER: &[u8] = &[
    0x30, 0x3a, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x04, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x02, 0x01, 0x01,
  ];

  const CERT_ID_WITH_SHA1_ABSENT_PARAMETERS_DER: &[u8] = &[
    0x30, 0x38, 0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x04, 0x14, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x04, 0x14, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x02, 0x01, 0x01,
  ];

  fn cert_id_from_der(der: &[u8]) -> CertId {
    CertId::from_der(der).expect("test CertID DER should parse")
  }

  #[test]
  fn cert_id_match_accepts_sha1_null_and_absent_parameters() {
    let expected = cert_id_from_der(CERT_ID_WITH_SHA1_NULL_PARAMETERS_DER);
    let response = cert_id_from_der(CERT_ID_WITH_SHA1_ABSENT_PARAMETERS_DER);

    assert_ne!(response, expected);
    assert!(cert_ids_match(&response, &expected));
  }

  #[test]
  fn cert_id_match_rejects_different_hash_or_serial_material() {
    let expected = cert_id_from_der(CERT_ID_WITH_SHA1_NULL_PARAMETERS_DER);
    let mut different_name_hash_der = CERT_ID_WITH_SHA1_ABSENT_PARAMETERS_DER.to_vec();
    different_name_hash_der[13] = 0x12;
    let different_name_hash = cert_id_from_der(&different_name_hash_der);
    let mut different_serial_der = CERT_ID_WITH_SHA1_ABSENT_PARAMETERS_DER.to_vec();
    let serial_byte = different_serial_der
      .last_mut()
      .expect("test DER should include a serial number byte");
    *serial_byte = 0x02;
    let different_serial = cert_id_from_der(&different_serial_der);

    assert!(!cert_ids_match(&different_name_hash, &expected));
    assert!(!cert_ids_match(&different_serial, &expected));
  }

  #[test]
  fn cert_id_match_keeps_non_sha1_parameters_strict() {
    let mut expected_der = CERT_ID_WITH_SHA1_NULL_PARAMETERS_DER.to_vec();
    expected_der[10] = 0x1b;
    let expected = cert_id_from_der(&expected_der);
    let mut response_der = CERT_ID_WITH_SHA1_ABSENT_PARAMETERS_DER.to_vec();
    response_der[10] = 0x1b;
    let response = cert_id_from_der(&response_der);

    assert!(!cert_ids_match(&response, &expected));
  }
}
