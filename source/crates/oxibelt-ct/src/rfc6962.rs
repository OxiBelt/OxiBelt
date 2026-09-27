//! RFC 6962 Certificate Transparency v1 wire structures.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::codec::{Reader, U24_MAX, push_vector_u16, push_vector_u24};
use super::merkle::Hash;
use super::{CtError, Result};

pub const VERSION_V1: u8 = 0;
pub const SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP: u8 = 0;
pub const SIGNATURE_TYPE_TREE_HASH: u8 = 1;
pub const LOG_ENTRY_X509: u16 = 0;
pub const LOG_ENTRY_PRECERT: u16 = 1;
pub const MERKLE_LEAF_TIMESTAMPED_ENTRY: u8 = 0;
pub const HASH_ALGORITHM_SHA256: u8 = 4;
pub const SIGNATURE_ALGORITHM_RSA: u8 = 1;
pub const SIGNATURE_ALGORITHM_ECDSA: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignedEntryV1 {
  X509(Vec<u8>),
  Precertificate {
    issuer_key_hash: Hash,
    tbs_certificate: Vec<u8>,
  },
}

impl SignedEntryV1 {
  pub const fn entry_type(&self) -> u16 {
    match self {
      Self::X509(_) => LOG_ENTRY_X509,
      Self::Precertificate { .. } => LOG_ENTRY_PRECERT,
    }
  }

  fn encode_to(&self, output: &mut Vec<u8>) -> Result<()> {
    match self {
      Self::X509(certificate) => push_vector_u24(output, certificate, 1),
      Self::Precertificate {
        issuer_key_hash,
        tbs_certificate,
      } => {
        output.extend_from_slice(issuer_key_hash);
        push_vector_u24(output, tbs_certificate, 1)
      }
    }
  }

  fn decode(reader: &mut Reader<'_>, entry_type: u16) -> Result<Self> {
    match entry_type {
      LOG_ENTRY_X509 => Ok(Self::X509(reader.vector_u24(1, U24_MAX)?.to_vec())),
      LOG_ENTRY_PRECERT => {
        let issuer_key_hash = reader
          .take(32)?
          .try_into()
          .map_err(|_| CtError::new("RFC 6962 issuer key hash must be 32 bytes"))?;
        let tbs_certificate = reader.vector_u24(1, U24_MAX)?.to_vec();
        Ok(Self::Precertificate {
          issuer_key_hash,
          tbs_certificate,
        })
      }
      _ => Err(CtError::new("unsupported RFC 6962 log entry type")),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampedEntryV1 {
  pub timestamp: u64,
  pub signed_entry: SignedEntryV1,
  /// Raw `CtExtensions` contents, excluding the outer u16 length.
  pub extensions: Vec<u8>,
}

impl TimestampedEntryV1 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&self.timestamp.to_be_bytes());
    output.extend_from_slice(&self.signed_entry.entry_type().to_be_bytes());
    self.signed_entry.encode_to(&mut output)?;
    push_vector_u16(&mut output, &self.extensions, 0)?;
    Ok(output)
  }

  pub fn decode(input: &[u8]) -> Result<Self> {
    let mut reader = Reader::new(input);
    let value = Self::decode_from(&mut reader)?;
    reader.finish()?;
    Ok(value)
  }

  pub(crate) fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let timestamp = reader.u64()?;
    let entry_type = reader.u16()?;
    let signed_entry = SignedEntryV1::decode(reader, entry_type)?;
    let extensions = reader.vector_u16(0, usize::from(u16::MAX))?.to_vec();
    Ok(Self {
      timestamp,
      signed_entry,
      extensions,
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleTreeLeafV1(pub TimestampedEntryV1);

impl MerkleTreeLeafV1 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let body = self.0.encode()?;
    let mut output = Vec::with_capacity(2 + body.len());
    output.push(VERSION_V1);
    output.push(MERKLE_LEAF_TIMESTAMPED_ENTRY);
    output.extend_from_slice(&body);
    Ok(output)
  }

  pub fn decode(input: &[u8]) -> Result<Self> {
    let mut reader = Reader::new(input);
    if reader.u8()? != VERSION_V1 {
      return Err(CtError::new("RFC 6962 Merkle leaf is not v1"));
    }
    if reader.u8()? != MERKLE_LEAF_TIMESTAMPED_ENTRY {
      return Err(CtError::new("unsupported RFC 6962 Merkle leaf type"));
    }
    let value = TimestampedEntryV1::decode_from(&mut reader)?;
    reader.finish()?;
    Ok(Self(value))
  }
}

pub fn encode_sct_signed_input(entry: &TimestampedEntryV1) -> Result<Vec<u8>> {
  let mut output = Vec::new();
  output.push(VERSION_V1);
  output.push(SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP);
  output.extend_from_slice(&entry.timestamp.to_be_bytes());
  output.extend_from_slice(&entry.signed_entry.entry_type().to_be_bytes());
  entry.signed_entry.encode_to(&mut output)?;
  push_vector_u16(&mut output, &entry.extensions, 0)?;
  Ok(output)
}

pub fn encode_sth_signed_input(timestamp: u64, tree_size: u64, root_hash: &Hash) -> Vec<u8> {
  let mut output = Vec::with_capacity(50);
  output.push(VERSION_V1);
  output.push(SIGNATURE_TYPE_TREE_HASH);
  output.extend_from_slice(&timestamp.to_be_bytes());
  output.extend_from_slice(&tree_size.to_be_bytes());
  output.extend_from_slice(root_hash);
  output
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigitallySigned {
  pub hash_algorithm: u8,
  pub signature_algorithm: u8,
  pub signature: Vec<u8>,
}

impl DigitallySigned {
  pub fn encode(&self) -> Result<Vec<u8>> {
    if self.hash_algorithm != HASH_ALGORITHM_SHA256 {
      return Err(CtError::new("RFC 6962 v1 requires SHA-256 signatures"));
    }
    if !matches!(
      self.signature_algorithm,
      SIGNATURE_ALGORITHM_RSA | SIGNATURE_ALGORITHM_ECDSA
    ) {
      return Err(CtError::new("unsupported RFC 6962 v1 signature algorithm"));
    }
    let mut output = vec![self.hash_algorithm, self.signature_algorithm];
    push_vector_u16(&mut output, &self.signature, 1)?;
    Ok(output)
  }

  pub fn decode(input: &[u8]) -> Result<Self> {
    let mut reader = Reader::new(input);
    let value = Self::decode_from(&mut reader)?;
    reader.finish()?;
    Ok(value)
  }

  pub(crate) fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let hash_algorithm = reader.u8()?;
    if hash_algorithm != HASH_ALGORITHM_SHA256 {
      return Err(CtError::new("RFC 6962 v1 requires SHA-256 signatures"));
    }
    let signature_algorithm = reader.u8()?;
    if !matches!(
      signature_algorithm,
      SIGNATURE_ALGORITHM_RSA | SIGNATURE_ALGORITHM_ECDSA
    ) {
      return Err(CtError::new("unsupported RFC 6962 v1 signature algorithm"));
    }
    let signature = reader.vector_u16(1, usize::from(u16::MAX))?.to_vec();
    Ok(Self {
      hash_algorithm,
      signature_algorithm,
      signature,
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCertificateTimestampV1 {
  pub log_id: Hash,
  pub timestamp: u64,
  pub extensions: Vec<u8>,
  pub signature: DigitallySigned,
}

impl SignedCertificateTimestampV1 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.push(VERSION_V1);
    output.extend_from_slice(&self.log_id);
    output.extend_from_slice(&self.timestamp.to_be_bytes());
    push_vector_u16(&mut output, &self.extensions, 0)?;
    output.extend_from_slice(&self.signature.encode()?);
    Ok(output)
  }

  pub fn decode(input: &[u8]) -> Result<Self> {
    let mut reader = Reader::new(input);
    if reader.u8()? != VERSION_V1 {
      return Err(CtError::new("SCT is not RFC 6962 v1"));
    }
    let log_id = reader
      .take(32)?
      .try_into()
      .map_err(|_| CtError::new("RFC 6962 LogID must be 32 bytes"))?;
    let timestamp = reader.u64()?;
    let extensions = reader.vector_u16(0, usize::from(u16::MAX))?.to_vec();
    let signature = DigitallySigned::decode_from(&mut reader)?;
    reader.finish()?;
    Ok(Self {
      log_id,
      timestamp,
      extensions,
      signature,
    })
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddChainResponseV1 {
  pub sct_version: u8,
  pub id: String,
  pub timestamp: u64,
  pub extensions: String,
  pub signature: String,
}

impl AddChainResponseV1 {
  pub fn from_sct(sct: &SignedCertificateTimestampV1) -> Result<Self> {
    Ok(Self {
      sct_version: VERSION_V1,
      id: base64::engine::general_purpose::STANDARD.encode(sct.log_id),
      timestamp: sct.timestamp,
      extensions: base64::engine::general_purpose::STANDARD.encode(&sct.extensions),
      signature: base64::engine::general_purpose::STANDARD.encode(sct.signature.encode()?),
    })
  }

  pub fn into_sct(self) -> Result<SignedCertificateTimestampV1> {
    if self.sct_version != VERSION_V1 {
      return Err(CtError::new("add-chain response is not RFC 6962 v1"));
    }
    let id = decode_base64(&self.id)?;
    let log_id = id
      .as_slice()
      .try_into()
      .map_err(|_| CtError::new("RFC 6962 response LogID must be 32 bytes"))?;
    let extensions = decode_base64(&self.extensions)?;
    let signature = DigitallySigned::decode(&decode_base64(&self.signature)?)?;
    Ok(SignedCertificateTimestampV1 {
      log_id,
      timestamp: self.timestamp,
      extensions,
      signature,
    })
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSthResponseV1 {
  pub tree_size: u64,
  pub timestamp: u64,
  pub sha256_root_hash: String,
  pub tree_head_signature: String,
}

impl GetSthResponseV1 {
  pub fn decode_root_and_signature(&self) -> Result<(Hash, DigitallySigned)> {
    let root = decode_base64(&self.sha256_root_hash)?;
    let root = root
      .as_slice()
      .try_into()
      .map_err(|_| CtError::new("RFC 6962 STH root must be 32 bytes"))?;
    let signature = DigitallySigned::decode(&decode_base64(&self.tree_head_signature)?)?;
    Ok((root, signature))
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetEntriesEntryV1 {
  pub leaf_input: String,
  pub extra_data: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetEntriesResponseV1 {
  pub entries: Vec<GetEntriesEntryV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetProofByHashResponseV1 {
  pub leaf_index: u64,
  pub audit_path: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GetSthConsistencyResponseV1 {
  pub consistency: Vec<String>,
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value)
    .map_err(|_| CtError::new("RFC 6962 JSON field is not base64"))?;
  if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
    return Err(CtError::new("RFC 6962 JSON field is not canonical base64"));
  }
  Ok(decoded)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn signature() -> DigitallySigned {
    DigitallySigned {
      hash_algorithm: HASH_ALGORITHM_SHA256,
      signature_algorithm: SIGNATURE_ALGORITHM_ECDSA,
      signature: vec![0x30, 0x00],
    }
  }

  #[test]
  fn x509_leaf_and_signed_input_match_the_rfc6962_v1_transcript() {
    let entry = TimestampedEntryV1 {
      timestamp: 7,
      signed_entry: SignedEntryV1::X509(vec![1, 2, 3]),
      extensions: Vec::new(),
    };
    let leaf = MerkleTreeLeafV1(entry.clone()).encode().unwrap();
    let signed = encode_sct_signed_input(&entry).unwrap();
    assert_eq!(&leaf[..2], &[VERSION_V1, MERKLE_LEAF_TIMESTAMPED_ENTRY]);
    assert_eq!(
      &signed[..2],
      &[VERSION_V1, SIGNATURE_TYPE_CERTIFICATE_TIMESTAMP]
    );
    // Both RFC 6962 enum values happen to be zero, so the SCT transcript and
    // serialized MerkleTreeLeaf are byte-for-byte identical in v1.
    assert_eq!(leaf, signed);
    assert_eq!(MerkleTreeLeafV1::decode(&leaf).unwrap().0, entry);
  }

  #[test]
  fn precertificate_leaf_round_trips() {
    let leaf = MerkleTreeLeafV1(TimestampedEntryV1 {
      timestamp: u64::MAX,
      signed_entry: SignedEntryV1::Precertificate {
        issuer_key_hash: [9; 32],
        tbs_certificate: vec![0x30, 0],
      },
      extensions: vec![1, 2],
    });
    let encoded = leaf.encode().unwrap();
    assert_eq!(MerkleTreeLeafV1::decode(&encoded).unwrap(), leaf);
  }

  #[test]
  fn sct_and_json_response_round_trip() {
    let sct = SignedCertificateTimestampV1 {
      log_id: [4; 32],
      timestamp: 11,
      extensions: vec![1, 0, 0],
      signature: signature(),
    };
    assert_eq!(
      SignedCertificateTimestampV1::decode(&sct.encode().unwrap()).unwrap(),
      sct
    );
    let response = AddChainResponseV1::from_sct(&sct).unwrap();
    assert_eq!(response.into_sct().unwrap(), sct);
  }

  #[test]
  fn wrong_versions_types_and_lengths_fail_closed() {
    assert!(MerkleTreeLeafV1::decode(&[1, 0]).is_err());
    assert!(MerkleTreeLeafV1::decode(&[0, 1]).is_err());
    assert!(SignedCertificateTimestampV1::decode(&[0; 41]).is_err());
    let mut invalid = signature();
    invalid.hash_algorithm = 5;
    assert!(invalid.encode().is_err());
  }

  #[test]
  fn sth_signed_input_is_the_exact_fifty_byte_transcript() {
    let encoded = encode_sth_signed_input(1, 2, &[3; 32]);
    assert_eq!(encoded.len(), 50);
    assert_eq!(&encoded[..2], &[0, 1]);
    assert_eq!(&encoded[2..10], &1_u64.to_be_bytes());
    assert_eq!(&encoded[10..18], &2_u64.to_be_bytes());
    assert_eq!(&encoded[18..], &[3; 32]);
  }
}
