//! RFC 9162 Certificate Transparency v2 wire structures.
//!
//! RFC 9162 `TransItem` values are self-describing through their leading
//! `VersionedTransType`; they do not have an additional outer length.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::codec::{Reader, U24_MAX, push_vector_u8, push_vector_u16, push_vector_u24};
use super::merkle::{self, Hash};
use super::{CtError, Result};

pub const X509_ENTRY_V2: u16 = 0x0100;
pub const PRECERT_ENTRY_V2: u16 = 0x0101;
pub const X509_SCT_V2: u16 = 0x0102;
pub const PRECERT_SCT_V2: u16 = 0x0103;
pub const SIGNED_TREE_HEAD_V2: u16 = 0x0104;
pub const CONSISTENCY_PROOF_V2: u16 = 0x0105;
pub const INCLUSION_PROOF_V2: u16 = 0x0106;

pub const SUBMISSION_TYPE_X509: u16 = 1;
pub const SUBMISSION_TYPE_PRECERT: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogIdV2(Vec<u8>);

impl LogIdV2 {
  /// Constructs a LogID from the DER OBJECT IDENTIFIER value octets.
  ///
  /// The ASN.1 tag and length are deliberately not part of the value carried
  /// by RFC 9162.
  pub fn new(oid_value: Vec<u8>) -> Result<Self> {
    validate_oid_value(&oid_value)?;
    Ok(Self(oid_value))
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  fn encode_to(&self, output: &mut Vec<u8>) -> Result<()> {
    validate_oid_value(&self.0)?;
    push_vector_u8(output, &self.0, 2)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    Self::new(reader.vector_u8(2, 127)?.to_vec())
  }
}

fn validate_oid_value(value: &[u8]) -> Result<()> {
  if !(2..=127).contains(&value.len()) {
    return Err(CtError::new(
      "RFC 9162 LogID OID value must be 2..127 bytes",
    ));
  }

  let mut at_subidentifier_start = true;
  for &byte in value {
    // DER base-128 subidentifiers use the shortest possible encoding. A
    // leading continuation byte containing zero payload is non-canonical.
    if at_subidentifier_start && byte == 0x80 {
      return Err(CtError::new(
        "RFC 9162 LogID is not a canonical DER OID value",
      ));
    }
    at_subidentifier_start = byte & 0x80 == 0;
  }
  if !at_subidentifier_start {
    return Err(CtError::new(
      "RFC 9162 LogID has an unterminated OID subidentifier",
    ));
  }
  Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionV2 {
  pub extension_type: u16,
  pub data: Vec<u8>,
}

fn encode_extensions(extensions: &[ExtensionV2], output: &mut Vec<u8>) -> Result<()> {
  let mut contents = Vec::new();
  let mut previous = None;
  for extension in extensions {
    if previous.is_some_and(|value| extension.extension_type <= value) {
      return Err(CtError::new(
        "RFC 9162 extensions must be strictly sorted without duplicates",
      ));
    }
    contents.extend_from_slice(&extension.extension_type.to_be_bytes());
    push_vector_u16(&mut contents, &extension.data, 0)?;
    previous = Some(extension.extension_type);
  }
  push_vector_u16(output, &contents, 0)
}

fn decode_extensions(reader: &mut Reader<'_>) -> Result<Vec<ExtensionV2>> {
  let encoded = reader.vector_u16(0, usize::from(u16::MAX))?;
  let mut contents = Reader::new(encoded);
  let mut extensions = Vec::new();
  let mut previous = None;
  while !contents.is_empty() {
    let extension_type = contents.u16()?;
    if previous.is_some_and(|value| extension_type <= value) {
      return Err(CtError::new(
        "RFC 9162 extensions must be strictly sorted without duplicates",
      ));
    }
    let data = contents.vector_u16(0, usize::from(u16::MAX))?.to_vec();
    extensions.push(ExtensionV2 {
      extension_type,
      data,
    });
    previous = Some(extension_type);
  }
  Ok(extensions)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampedCertificateEntryV2 {
  pub timestamp: u64,
  /// Hash of the issuer's `SubjectPublicKeyInfo`; its size is a log parameter.
  pub issuer_key_hash: Vec<u8>,
  pub tbs_certificate: Vec<u8>,
  pub extensions: Vec<ExtensionV2>,
}

impl TimestampedCertificateEntryV2 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&self.timestamp.to_be_bytes());
    push_vector_u8(&mut output, &self.issuer_key_hash, 32)?;
    push_vector_u24(&mut output, &self.tbs_certificate, 1)?;
    encode_extensions(&self.extensions, &mut output)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let timestamp = reader.u64()?;
    let issuer_key_hash = reader.vector_u8(32, usize::from(u8::MAX))?.to_vec();
    let tbs_certificate = reader.vector_u24(1, U24_MAX)?.to_vec();
    let extensions = decode_extensions(reader)?;
    Ok(Self {
      timestamp,
      issuer_key_hash,
      tbs_certificate,
      extensions,
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCertificateTimestampV2 {
  pub log_id: LogIdV2,
  pub timestamp: u64,
  pub extensions: Vec<ExtensionV2>,
  /// Signature bytes in the algorithm-specific format selected by log policy.
  pub signature: Vec<u8>,
}

impl SignedCertificateTimestampV2 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    self.log_id.encode_to(&mut output)?;
    output.extend_from_slice(&self.timestamp.to_be_bytes());
    encode_extensions(&self.extensions, &mut output)?;
    push_vector_u16(&mut output, &self.signature, 1)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    Ok(Self {
      log_id: LogIdV2::decode_from(reader)?,
      timestamp: reader.u64()?,
      extensions: decode_extensions(reader)?,
      signature: reader.vector_u16(1, usize::from(u16::MAX))?.to_vec(),
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeHeadV2 {
  pub timestamp: u64,
  pub tree_size: u64,
  /// Root hash bytes; the length must match the log's configured HASH_SIZE.
  pub root_hash: Vec<u8>,
  pub extensions: Vec<ExtensionV2>,
}

impl TreeHeadV2 {
  /// Encodes the exact RFC 9162 transcript signed by an STH.
  pub fn encode_signed_input(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&self.timestamp.to_be_bytes());
    output.extend_from_slice(&self.tree_size.to_be_bytes());
    push_vector_u8(&mut output, &self.root_hash, 32)?;
    encode_extensions(&self.extensions, &mut output)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let timestamp = reader.u64()?;
    let tree_size = reader.u64()?;
    let root_hash = reader.vector_u8(32, usize::from(u8::MAX))?.to_vec();
    let extensions = decode_extensions(reader)?;
    Ok(Self {
      timestamp,
      tree_size,
      root_hash,
      extensions,
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTreeHeadV2 {
  pub log_id: LogIdV2,
  pub tree_head: TreeHeadV2,
  pub signature: Vec<u8>,
}

impl SignedTreeHeadV2 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    self.log_id.encode_to(&mut output)?;
    output.extend_from_slice(&self.tree_head.encode_signed_input()?);
    push_vector_u16(&mut output, &self.signature, 1)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    Ok(Self {
      log_id: LogIdV2::decode_from(reader)?,
      tree_head: TreeHeadV2::decode_from(reader)?,
      signature: reader.vector_u16(1, usize::from(u16::MAX))?.to_vec(),
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsistencyProofV2 {
  pub log_id: LogIdV2,
  pub tree_size_1: u64,
  pub tree_size_2: u64,
  pub path: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InclusionProofV2 {
  pub log_id: LogIdV2,
  pub tree_size: u64,
  pub leaf_index: u64,
  pub path: Vec<Vec<u8>>,
}

fn encode_node_path(path: &[Vec<u8>], output: &mut Vec<u8>) -> Result<()> {
  let mut contents = Vec::new();
  for hash in path {
    push_vector_u8(&mut contents, hash, 32)?;
  }
  push_vector_u16(output, &contents, 0)
}

fn decode_node_path(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>> {
  let encoded = reader.vector_u16(0, usize::from(u16::MAX))?;
  let mut path_reader = Reader::new(encoded);
  let mut path = Vec::new();
  while !path_reader.is_empty() {
    path.push(path_reader.vector_u8(32, usize::from(u8::MAX))?.to_vec());
  }
  Ok(path)
}

impl ConsistencyProofV2 {
  fn encode(&self) -> Result<Vec<u8>> {
    if self.tree_size_1 > self.tree_size_2 {
      return Err(CtError::new(
        "RFC 9162 consistency proof sizes are reversed",
      ));
    }
    let mut output = Vec::new();
    self.log_id.encode_to(&mut output)?;
    output.extend_from_slice(&self.tree_size_1.to_be_bytes());
    output.extend_from_slice(&self.tree_size_2.to_be_bytes());
    encode_node_path(&self.path, &mut output)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let log_id = LogIdV2::decode_from(reader)?;
    let tree_size_1 = reader.u64()?;
    let tree_size_2 = reader.u64()?;
    if tree_size_1 > tree_size_2 {
      return Err(CtError::new(
        "RFC 9162 consistency proof sizes are reversed",
      ));
    }
    Ok(Self {
      log_id,
      tree_size_1,
      tree_size_2,
      path: decode_node_path(reader)?,
    })
  }
}

impl InclusionProofV2 {
  fn encode(&self) -> Result<Vec<u8>> {
    if self.leaf_index >= self.tree_size {
      return Err(CtError::new(
        "RFC 9162 inclusion proof leaf index is outside the tree",
      ));
    }
    let mut output = Vec::new();
    self.log_id.encode_to(&mut output)?;
    output.extend_from_slice(&self.tree_size.to_be_bytes());
    output.extend_from_slice(&self.leaf_index.to_be_bytes());
    encode_node_path(&self.path, &mut output)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let log_id = LogIdV2::decode_from(reader)?;
    let tree_size = reader.u64()?;
    let leaf_index = reader.u64()?;
    if leaf_index >= tree_size {
      return Err(CtError::new(
        "RFC 9162 inclusion proof leaf index is outside the tree",
      ));
    }
    Ok(Self {
      log_id,
      tree_size,
      leaf_index,
      path: decode_node_path(reader)?,
    })
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransItemV2 {
  X509Entry(TimestampedCertificateEntryV2),
  PrecertificateEntry(TimestampedCertificateEntryV2),
  X509Sct(SignedCertificateTimestampV2),
  PrecertificateSct(SignedCertificateTimestampV2),
  SignedTreeHead(SignedTreeHeadV2),
  ConsistencyProof(ConsistencyProofV2),
  InclusionProof(InclusionProofV2),
  /// A future, experimental, or private-use TransItem preserved verbatim.
  Opaque {
    trans_type: u16,
    data: Vec<u8>,
  },
}

impl TransItemV2 {
  pub const fn trans_type(&self) -> u16 {
    match self {
      Self::X509Entry(_) => X509_ENTRY_V2,
      Self::PrecertificateEntry(_) => PRECERT_ENTRY_V2,
      Self::X509Sct(_) => X509_SCT_V2,
      Self::PrecertificateSct(_) => PRECERT_SCT_V2,
      Self::SignedTreeHead(_) => SIGNED_TREE_HEAD_V2,
      Self::ConsistencyProof(_) => CONSISTENCY_PROOF_V2,
      Self::InclusionProof(_) => INCLUSION_PROOF_V2,
      Self::Opaque { trans_type, .. } => *trans_type,
    }
  }

  pub fn encode(&self) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    output.extend_from_slice(&self.trans_type().to_be_bytes());
    output.extend_from_slice(&match self {
      Self::X509Entry(value) | Self::PrecertificateEntry(value) => value.encode()?,
      Self::X509Sct(value) | Self::PrecertificateSct(value) => value.encode()?,
      Self::SignedTreeHead(value) => value.encode()?,
      Self::ConsistencyProof(value) => value.encode()?,
      Self::InclusionProof(value) => value.encode()?,
      Self::Opaque { data, .. } => data.clone(),
    });
    Ok(output)
  }

  pub fn decode(input: &[u8]) -> Result<Self> {
    let mut reader = Reader::new(input);
    let value = Self::decode_from(&mut reader)?;
    reader.finish()?;
    Ok(value)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    match reader.u16()? {
      X509_ENTRY_V2 => Ok(Self::X509Entry(TimestampedCertificateEntryV2::decode_from(
        reader,
      )?)),
      PRECERT_ENTRY_V2 => Ok(Self::PrecertificateEntry(
        TimestampedCertificateEntryV2::decode_from(reader)?,
      )),
      X509_SCT_V2 => Ok(Self::X509Sct(SignedCertificateTimestampV2::decode_from(
        reader,
      )?)),
      PRECERT_SCT_V2 => Ok(Self::PrecertificateSct(
        SignedCertificateTimestampV2::decode_from(reader)?,
      )),
      SIGNED_TREE_HEAD_V2 => Ok(Self::SignedTreeHead(SignedTreeHeadV2::decode_from(reader)?)),
      CONSISTENCY_PROOF_V2 => Ok(Self::ConsistencyProof(ConsistencyProofV2::decode_from(
        reader,
      )?)),
      INCLUSION_PROOF_V2 => Ok(Self::InclusionProof(InclusionProofV2::decode_from(reader)?)),
      0x0000..=0x00ff => Err(CtError::new(
        "RFC 6962 v1 type is not an RFC 9162 TransItem",
      )),
      trans_type => Ok(Self::Opaque {
        trans_type,
        data: reader.take(reader.remaining())?.to_vec(),
      }),
    }
  }

  pub fn sct_signed_input(entry: &Self) -> Result<Vec<u8>> {
    if !matches!(entry, Self::X509Entry(_) | Self::PrecertificateEntry(_)) {
      return Err(CtError::new(
        "RFC 9162 SCT input must be an entry TransItem",
      ));
    }
    entry.encode()
  }
}

pub fn encode_trans_item_list(items: &[TransItemV2]) -> Result<Vec<u8>> {
  if items.is_empty() {
    return Err(CtError::new("RFC 9162 TransItemList must not be empty"));
  }
  let mut contents = Vec::new();
  for item in items {
    push_vector_u16(&mut contents, &item.encode()?, 1)?;
  }
  let mut output = Vec::new();
  push_vector_u16(&mut output, &contents, 1)?;
  Ok(output)
}

pub fn decode_trans_item_list(input: &[u8]) -> Result<Vec<TransItemV2>> {
  let mut reader = Reader::new(input);
  let contents = reader.vector_u16(1, usize::from(u16::MAX))?;
  reader.finish()?;
  let mut list_reader = Reader::new(contents);
  let mut items = Vec::new();
  while !list_reader.is_empty() {
    let serialized = list_reader.vector_u16(1, usize::from(u16::MAX))?;
    items.push(TransItemV2::decode(serialized)?);
  }
  Ok(items)
}

/// Final STH storage uses the same `signed_tree_head_v2` TransItem framing.
/// This wrapper intentionally adds no non-standard marker or envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalSthV2(pub SignedTreeHeadV2);

impl FinalSthV2 {
  pub fn encode(&self) -> Result<Vec<u8>> {
    TransItemV2::SignedTreeHead(self.0.clone()).encode()
  }

  pub fn decode(input: &[u8]) -> Result<Self> {
    match TransItemV2::decode(input)? {
      TransItemV2::SignedTreeHead(value) => Ok(Self(value)),
      _ => Err(CtError::new(
        "RFC 9162 final STH is not a signed_tree_head_v2 TransItem",
      )),
    }
  }
}

pub fn merkle_leaf_hash(entry: &TransItemV2) -> Result<Hash> {
  match entry {
    TransItemV2::X509Entry(value) | TransItemV2::PrecertificateEntry(value)
      if value.issuer_key_hash.len() != 32 =>
    {
      return Err(CtError::new(
        "RFC 9162 SHA-256 Merkle helper requires a 32-byte issuer hash",
      ));
    }
    _ => {}
  }
  Ok(merkle::leaf_hash(&TransItemV2::sct_signed_input(entry)?))
}

/// Hashes a serialized v2-or-later leaf while preserving an unrecognized
/// TransItem as opaque input, as required for forward-compatible monitors.
pub fn merkle_leaf_hash_serialized(entry: &[u8]) -> Result<Hash> {
  let mut reader = Reader::new(entry);
  if reader.u16()? <= 0x00ff {
    return Err(CtError::new(
      "RFC 6962 v1 item is not an RFC 9162 Merkle leaf",
    ));
  }
  Ok(merkle::leaf_hash(entry))
}

pub fn merkle_tree_hash(entries: &[TransItemV2]) -> Result<Hash> {
  let mut hashes = Vec::with_capacity(entries.len());
  for entry in entries {
    hashes.push(merkle_leaf_hash(entry)?);
  }
  Ok(merkle::root_from_leaf_hashes(&hashes))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEntryRequestV2 {
  pub submission: String,
  #[serde(rename = "type")]
  pub submission_type: u16,
  pub chain: Vec<String>,
}

impl SubmitEntryRequestV2 {
  pub fn decode_der(&self) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if !matches!(
      self.submission_type,
      SUBMISSION_TYPE_X509 | SUBMISSION_TYPE_PRECERT
    ) {
      return Err(CtError::new("unsupported RFC 9162 submission type"));
    }
    let submission = decode_base64(&self.submission)?;
    if submission.is_empty() {
      return Err(CtError::new("RFC 9162 submission must not be empty"));
    }
    let chain = self
      .chain
      .iter()
      .map(|certificate| decode_base64(certificate))
      .collect::<Result<Vec<_>>>()?;
    if chain.iter().any(Vec::is_empty) {
      return Err(CtError::new(
        "RFC 9162 chain certificates must not be empty",
      ));
    }
    Ok((submission, chain))
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitEntryResponseV2 {
  pub sct: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sth: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub inclusion: Option<String>,
}

impl SubmitEntryResponseV2 {
  pub fn from_items(
    sct: &TransItemV2,
    sth: Option<&SignedTreeHeadV2>,
    inclusion: Option<&InclusionProofV2>,
  ) -> Result<Self> {
    let sct_log_id = match sct {
      TransItemV2::X509Sct(value) | TransItemV2::PrecertificateSct(value) => &value.log_id,
      _ => {
        return Err(CtError::new(
          "RFC 9162 submission response requires an SCT TransItem",
        ));
      }
    };
    if sth.is_some_and(|value| value.log_id != *sct_log_id)
      || inclusion.is_some_and(|value| value.log_id != *sct_log_id)
    {
      return Err(CtError::new("RFC 9162 receipt items have different LogIDs"));
    }
    if let (Some(sth), Some(inclusion)) = (sth, inclusion)
      && sth.tree_head.tree_size != inclusion.tree_size
    {
      return Err(CtError::new(
        "RFC 9162 receipt STH and inclusion tree sizes differ",
      ));
    }
    Ok(Self {
      sct: encode_base64(&sct.encode()?),
      sth: sth
        .map(|value| TransItemV2::SignedTreeHead(value.clone()).encode())
        .transpose()?
        .map(|value| encode_base64(&value)),
      inclusion: inclusion
        .map(|value| TransItemV2::InclusionProof(value.clone()).encode())
        .transpose()?
        .map(|value| encode_base64(&value)),
    })
  }

  pub fn decode_items(
    &self,
  ) -> Result<(
    TransItemV2,
    Option<SignedTreeHeadV2>,
    Option<InclusionProofV2>,
  )> {
    let sct = TransItemV2::decode(&decode_base64(&self.sct)?)?;
    let log_id = match &sct {
      TransItemV2::X509Sct(value) | TransItemV2::PrecertificateSct(value) => &value.log_id,
      _ => {
        return Err(CtError::new(
          "RFC 9162 submission response contains a non-SCT item",
        ));
      }
    };
    let sth = self
      .sth
      .as_deref()
      .map(decode_base64)
      .transpose()?
      .map(|bytes| TransItemV2::decode(&bytes))
      .transpose()?
      .map(|item| match item {
        TransItemV2::SignedTreeHead(value) => Ok(value),
        _ => Err(CtError::new(
          "RFC 9162 receipt sth has the wrong TransItem type",
        )),
      })
      .transpose()?;
    let inclusion = self
      .inclusion
      .as_deref()
      .map(decode_base64)
      .transpose()?
      .map(|bytes| TransItemV2::decode(&bytes))
      .transpose()?
      .map(|item| match item {
        TransItemV2::InclusionProof(value) => Ok(value),
        _ => Err(CtError::new(
          "RFC 9162 receipt inclusion has the wrong TransItem type",
        )),
      })
      .transpose()?;
    if sth.as_ref().is_some_and(|value| value.log_id != *log_id)
      || inclusion
        .as_ref()
        .is_some_and(|value| value.log_id != *log_id)
    {
      return Err(CtError::new("RFC 9162 receipt items have different LogIDs"));
    }
    if let (Some(sth), Some(inclusion)) = (&sth, &inclusion)
      && sth.tree_head.tree_size != inclusion.tree_size
    {
      return Err(CtError::new(
        "RFC 9162 receipt STH and inclusion tree sizes differ",
      ));
    }
    Ok((sct, sth, inclusion))
  }
}

fn encode_base64(bytes: &[u8]) -> String {
  base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value)
    .map_err(|_| CtError::new("RFC 9162 JSON field is not base64"))?;
  if encode_base64(&decoded) != value {
    return Err(CtError::new("RFC 9162 JSON field is not canonical base64"));
  }
  Ok(decoded)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::ct::rfc6962::{
    DigitallySigned, HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_ECDSA, SignedCertificateTimestampV1,
  };

  fn log_id() -> LogIdV2 {
    // DER value octets for 1.2.840.10045.4.3.2 (ecdsa-with-SHA256).
    LogIdV2::new(vec![0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]).unwrap()
  }

  fn entry(index: u8) -> TransItemV2 {
    TransItemV2::X509Entry(TimestampedCertificateEntryV2 {
      timestamp: u64::from(index),
      issuer_key_hash: vec![index; 32],
      tbs_certificate: vec![0x30, index],
      extensions: vec![ExtensionV2 {
        extension_type: 7,
        data: vec![index],
      }],
    })
  }

  fn sct() -> TransItemV2 {
    TransItemV2::X509Sct(SignedCertificateTimestampV2 {
      log_id: log_id(),
      timestamp: 12,
      extensions: Vec::new(),
      signature: vec![1, 2, 3],
    })
  }

  fn sth() -> SignedTreeHeadV2 {
    SignedTreeHeadV2 {
      log_id: log_id(),
      tree_head: TreeHeadV2 {
        timestamp: 13,
        tree_size: 1,
        root_hash: vec![9; 32],
        extensions: Vec::new(),
      },
      signature: vec![4, 5],
    }
  }

  #[test]
  fn log_id_requires_canonical_der_oid_value_octets() {
    assert!(LogIdV2::new(vec![0x2a, 0x03]).is_ok());
    for invalid in [
      vec![0x2a],
      vec![0x2a; 128],
      vec![0x80, 0x00],
      vec![0x2a, 0x80],
    ] {
      assert!(LogIdV2::new(invalid).is_err());
    }
  }

  #[test]
  fn transitems_round_trip_with_exact_v2_type_prefixes() {
    let entry = entry(4);
    let encoded = entry.encode().unwrap();
    assert_eq!(&encoded[..2], &X509_ENTRY_V2.to_be_bytes());
    assert_eq!(TransItemV2::decode(&encoded).unwrap(), entry);

    let sct = sct();
    let encoded = sct.encode().unwrap();
    assert_eq!(&encoded[..2], &X509_SCT_V2.to_be_bytes());
    assert_eq!(TransItemV2::decode(&encoded).unwrap(), sct);

    let signed_tree_head = TransItemV2::SignedTreeHead(sth());
    assert_eq!(
      TransItemV2::decode(&signed_tree_head.encode().unwrap()).unwrap(),
      signed_tree_head
    );

    let unknown = TransItemV2::Opaque {
      trans_type: 0xe001,
      data: vec![1, 2, 3],
    };
    assert_eq!(
      TransItemV2::decode(&unknown.encode().unwrap()).unwrap(),
      unknown
    );
  }

  #[test]
  fn transitem_lists_bound_each_item_and_preserve_unknown_types() {
    let items = vec![
      sct(),
      TransItemV2::Opaque {
        trans_type: 0xe001,
        data: vec![7, 8],
      },
    ];
    let encoded = encode_trans_item_list(&items).unwrap();
    assert_eq!(decode_trans_item_list(&encoded).unwrap(), items);
    assert!(decode_trans_item_list(&[0, 0]).is_err());
    assert!(decode_trans_item_list(&[0, 2, 0, 1]).is_err());
  }

  #[test]
  fn extensions_are_strictly_sorted_and_bounded() {
    let mut value = match entry(1) {
      TransItemV2::X509Entry(value) => value,
      _ => unreachable!(),
    };
    value.extensions = vec![
      ExtensionV2 {
        extension_type: 2,
        data: Vec::new(),
      },
      ExtensionV2 {
        extension_type: 1,
        data: Vec::new(),
      },
    ];
    assert!(TransItemV2::X509Entry(value).encode().is_err());
  }

  #[test]
  fn sth_signed_input_excludes_log_id_signature_and_transitem_type() {
    let value = sth();
    let input = value.tree_head.encode_signed_input().unwrap();
    assert_eq!(&input[..8], &13_u64.to_be_bytes());
    assert_eq!(&input[8..16], &1_u64.to_be_bytes());
    assert_eq!(input[16], 32);
    assert!(
      !input
        .windows(value.log_id.as_bytes().len())
        .any(|w| w == value.log_id.as_bytes())
    );
    assert!(
      !input
        .windows(value.signature.len())
        .any(|w| w == value.signature)
    );
  }

  #[test]
  fn final_sth_is_exactly_the_signed_tree_head_transitem() {
    let value = sth();
    let final_sth = FinalSthV2(value.clone());
    assert_eq!(
      final_sth.encode().unwrap(),
      TransItemV2::SignedTreeHead(value).encode().unwrap()
    );
    assert_eq!(
      FinalSthV2::decode(&final_sth.encode().unwrap()).unwrap(),
      final_sth
    );
  }

  #[test]
  fn receipt_round_trips_and_binds_all_items_to_one_log() {
    let sct = sct();
    let sth = sth();
    let inclusion = InclusionProofV2 {
      log_id: log_id(),
      tree_size: 1,
      leaf_index: 0,
      path: Vec::new(),
    };
    let receipt = SubmitEntryResponseV2::from_items(&sct, Some(&sth), Some(&inclusion)).unwrap();
    assert_eq!(
      receipt.decode_items().unwrap(),
      (sct, Some(sth), Some(inclusion))
    );
  }

  #[test]
  fn merkle_helpers_reject_non_entries_and_cover_arbitrary_sizes() {
    let entries: Vec<_> = (0..=255).map(|index| entry(index)).collect();
    for size in 0..=entries.len() {
      let root = merkle_tree_hash(&entries[..size]).unwrap();
      let encoded: Vec<Vec<u8>> = entries[..size]
        .iter()
        .map(|value| value.encode().unwrap())
        .collect();
      assert_eq!(root, merkle::tree_hash(&encoded));
    }
    assert!(merkle_leaf_hash(&sct()).is_err());
    let opaque = TransItemV2::Opaque {
      trans_type: 0x0107,
      data: vec![1, 2],
    }
    .encode()
    .unwrap();
    assert_eq!(
      merkle_leaf_hash_serialized(&opaque).unwrap(),
      merkle::leaf_hash(&opaque)
    );
  }

  #[test]
  fn v1_and_v2_wire_domains_do_not_cross() {
    let v1 = SignedCertificateTimestampV1 {
      log_id: [0; 32],
      timestamp: 0,
      extensions: Vec::new(),
      signature: DigitallySigned {
        hash_algorithm: HASH_ALGORITHM_SHA256,
        signature_algorithm: SIGNATURE_ALGORITHM_ECDSA,
        signature: vec![1],
      },
    }
    .encode()
    .unwrap();
    assert!(TransItemV2::decode(&v1).is_err());
    assert!(SignedCertificateTimestampV1::decode(&sct().encode().unwrap()).is_err());
  }

  #[test]
  fn malformed_lengths_and_types_fail_closed() {
    let mut truncated = entry(1).encode().unwrap();
    truncated.pop();
    assert!(TransItemV2::decode(&truncated).is_err());
    assert!(TransItemV2::decode(&[0x01]).is_err());
    assert!(TransItemV2::decode(&[0x00, 0xff]).is_err());
    assert!(
      SubmitEntryRequestV2 {
        submission: encode_base64(b"x"),
        submission_type: 3,
        chain: Vec::new(),
      }
      .decode_der()
      .is_err()
    );
  }
}
