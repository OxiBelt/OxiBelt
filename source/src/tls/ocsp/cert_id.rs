use sha1::Digest;
use x509_cert::Certificate;
use x509_cert::der::{
  Encode,
  asn1::{Null, ObjectIdentifier, OctetString},
};
use x509_cert::spki::AlgorithmIdentifierOwned;
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
