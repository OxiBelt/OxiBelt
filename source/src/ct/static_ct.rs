//! C2SP Static Certificate Transparency API v1.1.0 primitives.

use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::codec::{Reader, push_u40, push_vector_u16, push_vector_u24};
use super::merkle::{HASH_BYTES, Hash};
use super::rfc6962::{DigitallySigned, SignedEntryV1, TimestampedEntryV1, encode_sth_signed_input};
use super::{CtError, Result};

pub const TILE_WIDTH: usize = 256;
pub const MAX_TILE_LEVEL: u8 = 5;
pub const LEAF_INDEX_EXTENSION_TYPE: u8 = 0;
const RFC6962_NOTE_SIGNATURE_TYPE: u8 = 0x05;
const SIGNATURE_LINE_PREFIX: &str = "— ";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TileKind {
  Hashes { level: u8 },
  Data,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TilePath {
  pub kind: TileKind,
  pub index: u64,
  /// Present only for partial tiles and constrained to 1..=255.
  pub partial_width: Option<u8>,
}

impl TilePath {
  pub fn render(self) -> Result<String> {
    if let TileKind::Hashes { level } = self.kind
      && level > MAX_TILE_LEVEL
    {
      return Err(CtError::new("Static CT tile level exceeds 5"));
    }
    if self.partial_width == Some(0) {
      return Err(CtError::new(
        "Static CT partial tile width must be positive",
      ));
    }
    let index = render_tile_index(self.index);
    let kind = match self.kind {
      TileKind::Hashes { level } => level.to_string(),
      TileKind::Data => "data".to_string(),
    };
    let suffix = self
      .partial_width
      .map(|width| format!(".p/{width}"))
      .unwrap_or_default();
    Ok(format!("tile/{kind}/{index}{suffix}"))
  }

  pub fn parse(path: &str) -> Result<Self> {
    if path.starts_with('/') || path.ends_with('/') {
      return Err(CtError::new(
        "Static CT tile path must be relative and canonical",
      ));
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() < 3 || components[0] != "tile" {
      return Err(CtError::new("invalid Static CT tile path"));
    }
    let kind = if components[1] == "data" {
      TileKind::Data
    } else {
      let level = parse_canonical_decimal_u8(components[1])?;
      if level > MAX_TILE_LEVEL {
        return Err(CtError::new("Static CT tile level exceeds 5"));
      }
      TileKind::Hashes { level }
    };

    let partial_marker = components.iter().position(|part| part.ends_with(".p"));
    let (index_components, partial_width) = match partial_marker {
      Some(position) => {
        if position < 2 || position + 2 != components.len() {
          return Err(CtError::new("invalid Static CT partial tile suffix"));
        }
        let marker = components[position];
        if marker == ".p" || !marker.ends_with(".p") {
          return Err(CtError::new("invalid Static CT partial tile marker"));
        }
        let base = marker
          .strip_suffix(".p")
          .ok_or_else(|| CtError::new("invalid Static CT partial tile marker"))?;
        let mut index = components[2..position].to_vec();
        index.push(base);
        let width = parse_canonical_decimal_u8(components[position + 1])?;
        if width == 0 {
          return Err(CtError::new(
            "Static CT partial tile width must be positive",
          ));
        }
        (index, Some(width))
      }
      None => (components[2..].to_vec(), None),
    };
    let index = parse_tile_index(&index_components)?;
    let value = Self {
      kind,
      index,
      partial_width,
    };
    if value.render()? != path {
      return Err(CtError::new("Static CT tile path is not canonical"));
    }
    Ok(value)
  }
}

fn render_tile_index(index: u64) -> String {
  let decimal = index.to_string();
  let padded_length = decimal.len().div_ceil(3) * 3;
  let padded = format!("{index:0padded_length$}");
  let groups: Vec<&str> = (0..padded.len())
    .step_by(3)
    .map(|start| &padded[start..start + 3])
    .collect();
  let last = groups.len() - 1;
  groups
    .iter()
    .enumerate()
    .map(|(position, group)| {
      if position == last {
        (*group).to_string()
      } else {
        format!("x{group}")
      }
    })
    .collect::<Vec<_>>()
    .join("/")
}

fn parse_tile_index(groups: &[&str]) -> Result<u64> {
  if groups.is_empty() {
    return Err(CtError::new("Static CT tile index is missing"));
  }
  let mut decimal = String::new();
  for (position, group) in groups.iter().enumerate() {
    let digits = if position + 1 == groups.len() {
      *group
    } else {
      group
        .strip_prefix('x')
        .ok_or_else(|| CtError::new("Static CT tile index prefix is missing"))?
    };
    if digits.len() != 3 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
      return Err(CtError::new(
        "Static CT tile index group is not three decimal digits",
      ));
    }
    decimal.push_str(digits);
  }
  decimal
    .parse()
    .map_err(|_| CtError::new("Static CT tile index overflows u64"))
}

fn parse_canonical_decimal_u8(value: &str) -> Result<u8> {
  if value.is_empty()
    || (value.len() > 1 && value.starts_with('0'))
    || !value.bytes().all(|byte| byte.is_ascii_digit())
  {
    return Err(CtError::new("Static CT decimal value is not canonical"));
  }
  value
    .parse()
    .map_err(|_| CtError::new("Static CT decimal value overflows u8"))
}

pub fn encode_hash_tile(hashes: &[Hash]) -> Result<Vec<u8>> {
  if hashes.is_empty() || hashes.len() > TILE_WIDTH {
    return Err(CtError::new(
      "Static CT hash tile width must be between 1 and 256",
    ));
  }
  Ok(
    hashes
      .iter()
      .flat_map(|hash| hash.iter().copied())
      .collect(),
  )
}

pub fn decode_hash_tile(input: &[u8], expected_width: usize) -> Result<Vec<Hash>> {
  if !(1..=TILE_WIDTH).contains(&expected_width)
    || input.len() != expected_width.saturating_mul(HASH_BYTES)
  {
    return Err(CtError::new("Static CT hash tile has the wrong width"));
  }
  input
    .chunks_exact(HASH_BYTES)
    .map(|chunk| {
      chunk
        .try_into()
        .map_err(|_| CtError::new("Static CT tile hash must be 32 bytes"))
    })
    .collect()
}

pub fn leaf_index_extension(leaf_index: u64) -> Result<Vec<u8>> {
  let mut output = vec![LEAF_INDEX_EXTENSION_TYPE, 0, 5];
  push_u40(&mut output, leaf_index)?;
  Ok(output)
}

pub fn parse_leaf_index_extension(extensions: &[u8]) -> Result<u64> {
  let mut reader = Reader::new(extensions);
  let mut leaf_index = None;
  while !reader.is_empty() {
    let extension_type = reader.u8()?;
    let data = reader.vector_u16(0, usize::from(u16::MAX))?;
    if extension_type == LEAF_INDEX_EXTENSION_TYPE {
      if leaf_index.is_some() || data.len() != 5 {
        return Err(CtError::new(
          "invalid or duplicate Static CT leaf_index extension",
        ));
      }
      let mut index_reader = Reader::new(data);
      leaf_index = Some(index_reader.u40()?);
      index_reader.finish()?;
    }
  }
  leaf_index.ok_or_else(|| CtError::new("Static CT SCT is missing leaf_index extension"))
}

pub fn issuer_fingerprint(certificate_der: &[u8]) -> Hash {
  Sha256::digest(certificate_der).into()
}

pub fn issuer_fingerprint_hex(certificate_der: &[u8]) -> String {
  const DIGITS: &[u8; 16] = b"0123456789abcdef";
  issuer_fingerprint(certificate_der)
    .iter()
    .flat_map(|byte| {
      [
        char::from(DIGITS[usize::from(byte >> 4)]),
        char::from(DIGITS[usize::from(byte & 0x0f)]),
      ]
    })
    .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticTileLeaf {
  pub timestamped_entry: TimestampedEntryV1,
  /// Present only when `timestamped_entry` is a precertificate entry.
  pub pre_certificate: Option<Vec<u8>>,
  pub certificate_chain: Vec<Hash>,
}

impl StaticTileLeaf {
  pub fn encode(&self) -> Result<Vec<u8>> {
    let is_precertificate = matches!(
      self.timestamped_entry.signed_entry,
      SignedEntryV1::Precertificate { .. }
    );
    if is_precertificate != self.pre_certificate.is_some() {
      return Err(CtError::new(
        "Static CT pre_certificate presence does not match entry type",
      ));
    }
    let mut output = self.timestamped_entry.encode()?;
    if let Some(pre_certificate) = &self.pre_certificate {
      push_vector_u24(&mut output, pre_certificate, 1)?;
    }
    let fingerprints: Vec<u8> = self
      .certificate_chain
      .iter()
      .flat_map(|fingerprint| fingerprint.iter().copied())
      .collect();
    push_vector_u16(&mut output, &fingerprints, 0)?;
    Ok(output)
  }

  fn decode_from(reader: &mut Reader<'_>) -> Result<Self> {
    let timestamped_entry = TimestampedEntryV1::decode_from(reader)?;
    let pre_certificate = if matches!(
      timestamped_entry.signed_entry,
      SignedEntryV1::Precertificate { .. }
    ) {
      Some(reader.vector_u24(1, super::codec::U24_MAX)?.to_vec())
    } else {
      None
    };
    let fingerprints = reader.vector_u16(0, usize::from(u16::MAX))?;
    if fingerprints.len() % HASH_BYTES != 0 {
      return Err(CtError::new(
        "Static CT certificate chain fingerprint vector is misaligned",
      ));
    }
    let certificate_chain = fingerprints
      .chunks_exact(HASH_BYTES)
      .map(|chunk| {
        chunk
          .try_into()
          .map_err(|_| CtError::new("Static CT issuer fingerprint must be 32 bytes"))
      })
      .collect::<Result<Vec<Hash>>>()?;
    Ok(Self {
      timestamped_entry,
      pre_certificate,
      certificate_chain,
    })
  }
}

pub fn encode_data_tile(leaves: &[StaticTileLeaf]) -> Result<Vec<u8>> {
  if leaves.is_empty() || leaves.len() > TILE_WIDTH {
    return Err(CtError::new(
      "Static CT data tile width must be between 1 and 256",
    ));
  }
  let mut output = Vec::new();
  for leaf in leaves {
    output.extend_from_slice(&leaf.encode()?);
  }
  Ok(output)
}

pub fn decode_data_tile(input: &[u8], expected_width: usize) -> Result<Vec<StaticTileLeaf>> {
  if !(1..=TILE_WIDTH).contains(&expected_width) {
    return Err(CtError::new(
      "Static CT data tile expected width is invalid",
    ));
  }
  let mut reader = Reader::new(input);
  let mut leaves = Vec::with_capacity(expected_width);
  for _ in 0..expected_width {
    leaves.push(StaticTileLeaf::decode_from(&mut reader)?);
  }
  reader.finish()?;
  Ok(leaves)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticCheckpoint {
  pub origin: String,
  pub tree_size: u64,
  pub root_hash: Hash,
  pub timestamp: u64,
  pub tree_head_signature: DigitallySigned,
}

impl StaticCheckpoint {
  pub fn render(&self, log_id: &Hash) -> Result<String> {
    validate_origin(&self.origin)?;
    let text = checkpoint_text(&self.origin, self.tree_size, &self.root_hash);
    let key_id = checkpoint_key_id(&self.origin, log_id);
    let mut signature = Vec::new();
    signature.extend_from_slice(&key_id);
    signature.extend_from_slice(&self.timestamp.to_be_bytes());
    signature.extend_from_slice(&self.tree_head_signature.encode()?);
    Ok(format!(
      "{text}\n{SIGNATURE_LINE_PREFIX}{} {}\n",
      self.origin,
      base64::engine::general_purpose::STANDARD.encode(signature)
    ))
  }

  pub fn parse(input: &str, log_id: &Hash) -> Result<Self> {
    if input.len() > 128 * 1024 || !input.ends_with('\n') {
      return Err(CtError::new(
        "Static CT checkpoint is too large or lacks final newline",
      ));
    }
    if input
      .chars()
      .any(|character| character < ' ' && character != '\n')
    {
      return Err(CtError::new(
        "Static CT checkpoint contains forbidden control characters",
      ));
    }
    let separator = input
      .rfind("\n\n")
      .ok_or_else(|| CtError::new("Static CT checkpoint lacks signed-note separator"))?;
    let text = &input[..=separator];
    let signature_block = &input[separator + 2..];
    let text_lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if text_lines.len() != 3 {
      return Err(CtError::new(
        "Static CT checkpoint text must have exactly three lines",
      ));
    }
    let origin = text_lines[0].to_string();
    validate_origin(&origin)?;
    let tree_size = parse_canonical_u64(text_lines[1])?;
    let root = base64::engine::general_purpose::STANDARD
      .decode(text_lines[2])
      .map_err(|_| CtError::new("Static CT checkpoint root is not base64"))?;
    let root_hash = root
      .as_slice()
      .try_into()
      .map_err(|_| CtError::new("Static CT checkpoint root must be 32 bytes"))?;
    if checkpoint_text(&origin, tree_size, &root_hash) != text {
      return Err(CtError::new("Static CT checkpoint text is not canonical"));
    }

    let expected_key_id = checkpoint_key_id(&origin, log_id);
    let mut matching = None;
    let mut signature_count = 0;
    for line in signature_block.lines() {
      signature_count += 1;
      if signature_count > 16 {
        return Err(CtError::new("Static CT checkpoint has too many signatures"));
      }
      let Some(rest) = line.strip_prefix(SIGNATURE_LINE_PREFIX) else {
        return Err(CtError::new("invalid Static CT checkpoint signature line"));
      };
      let Some((key_name, encoded)) = rest.split_once(' ') else {
        return Err(CtError::new(
          "invalid Static CT checkpoint signature fields",
        ));
      };
      if encoded.is_empty() {
        return Err(CtError::new("empty Static CT checkpoint signature field"));
      }
      validate_key_name(key_name)?;
      let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| CtError::new("Static CT checkpoint signature is not base64"))?;
      if base64::engine::general_purpose::STANDARD.encode(&decoded) != encoded {
        return Err(CtError::new(
          "Static CT checkpoint signature is not canonical base64",
        ));
      }
      if key_name != origin || decoded.get(..4) != Some(expected_key_id.as_slice()) {
        continue;
      }
      if matching.is_some() {
        return Err(CtError::new(
          "duplicate Static CT RFC 6962 checkpoint signature",
        ));
      }
      let mut reader = Reader::new(&decoded[4..]);
      let timestamp = reader.u64()?;
      let tree_head_signature = DigitallySigned::decode_from(&mut reader)?;
      reader.finish()?;
      matching = Some((timestamp, tree_head_signature));
    }
    let (timestamp, tree_head_signature) = matching
      .ok_or_else(|| CtError::new("Static CT checkpoint lacks the expected log signature"))?;
    Ok(Self {
      origin,
      tree_size,
      root_hash,
      timestamp,
      tree_head_signature,
    })
  }

  pub fn signed_tree_head_input(&self) -> Vec<u8> {
    encode_sth_signed_input(self.timestamp, self.tree_size, &self.root_hash)
  }
}

fn checkpoint_text(origin: &str, tree_size: u64, root_hash: &Hash) -> String {
  format!(
    "{origin}\n{tree_size}\n{}\n",
    base64::engine::general_purpose::STANDARD.encode(root_hash)
  )
}

pub fn checkpoint_key_id(origin: &str, log_id: &Hash) -> [u8; 4] {
  let mut hash = Sha256::new();
  hash.update(origin.as_bytes());
  hash.update(b"\n");
  hash.update([RFC6962_NOTE_SIGNATURE_TYPE]);
  hash.update(log_id);
  let digest = hash.finalize();
  [digest[0], digest[1], digest[2], digest[3]]
}

fn validate_origin(origin: &str) -> Result<()> {
  if origin.is_empty()
    || origin.len() > 2048
    || origin.contains("://")
    || origin.starts_with('/')
    || origin.ends_with('/')
    || origin
      .chars()
      .any(|character| character.is_control() || character.is_whitespace() || character == '+')
  {
    return Err(CtError::new(
      "Static CT checkpoint origin is not a schema-less URL",
    ));
  }
  Ok(())
}

fn validate_key_name(key_name: &str) -> Result<()> {
  if key_name.is_empty()
    || key_name
      .chars()
      .any(|character| character.is_control() || character.is_whitespace() || character == '+')
  {
    return Err(CtError::new("Static CT signed-note key name is invalid"));
  }
  Ok(())
}

fn parse_canonical_u64(value: &str) -> Result<u64> {
  if value.is_empty()
    || (value.len() > 1 && value.starts_with('0'))
    || !value.bytes().all(|byte| byte.is_ascii_digit())
  {
    return Err(CtError::new(
      "Static CT checkpoint size is not canonical decimal",
    ));
  }
  value
    .parse()
    .map_err(|_| CtError::new("Static CT checkpoint size overflows u64"))
}

#[cfg(test)]
mod tests {
  use super::super::rfc6962::{HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_ECDSA};
  use super::*;

  fn x509_leaf(index: u8) -> StaticTileLeaf {
    StaticTileLeaf {
      timestamped_entry: TimestampedEntryV1 {
        timestamp: u64::from(index),
        signed_entry: SignedEntryV1::X509(vec![0x30, index]),
        extensions: leaf_index_extension(u64::from(index)).unwrap(),
      },
      pre_certificate: None,
      certificate_chain: vec![[index; 32]],
    }
  }

  #[test]
  fn tile_paths_round_trip_at_boundaries() {
    for value in [
      TilePath {
        kind: TileKind::Hashes { level: 0 },
        index: 0,
        partial_width: None,
      },
      TilePath {
        kind: TileKind::Hashes { level: 5 },
        index: 1_234_067,
        partial_width: Some(17),
      },
      TilePath {
        kind: TileKind::Data,
        index: u64::MAX,
        partial_width: Some(255),
      },
    ] {
      let rendered = value.render().unwrap();
      assert_eq!(TilePath::parse(&rendered).unwrap(), value);
    }
    assert_eq!(
      TilePath {
        kind: TileKind::Hashes { level: 1 },
        index: 1_234_067,
        partial_width: None,
      }
      .render()
      .unwrap(),
      "tile/1/x001/x234/067"
    );
  }

  #[test]
  fn noncanonical_tile_paths_fail_closed() {
    for path in [
      "/tile/0/000",
      "tile/00/000",
      "tile/6/000",
      "tile/0/0",
      "tile/0/x000/000",
      "tile/0/000.p/0",
      "tile/data/000/",
    ] {
      assert!(TilePath::parse(path).is_err(), "accepted {path}");
    }
  }

  #[test]
  fn leaf_index_extension_has_the_required_eight_bytes() {
    let encoded = leaf_index_extension((1_u64 << 40) - 1).unwrap();
    assert_eq!(encoded.len(), 8);
    assert_eq!(
      parse_leaf_index_extension(&encoded).unwrap(),
      (1_u64 << 40) - 1
    );
    assert!(leaf_index_extension(1_u64 << 40).is_err());
    let mut duplicate = encoded.clone();
    duplicate.extend_from_slice(&encoded);
    assert!(parse_leaf_index_extension(&duplicate).is_err());
  }

  #[test]
  fn hash_and_data_tiles_round_trip_and_reject_trailing_bytes() {
    let hashes = vec![[1; 32], [2; 32]];
    let encoded = encode_hash_tile(&hashes).unwrap();
    assert_eq!(decode_hash_tile(&encoded, 2).unwrap(), hashes);
    assert!(decode_hash_tile(&encoded, 1).is_err());

    let leaves = vec![x509_leaf(1), x509_leaf(2)];
    let encoded = encode_data_tile(&leaves).unwrap();
    assert_eq!(decode_data_tile(&encoded, 2).unwrap(), leaves);
    assert!(decode_data_tile(&encoded, 1).is_err());
    assert_eq!(issuer_fingerprint_hex(&[]).len(), 64);
    assert!(
      issuer_fingerprint_hex(&[])
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
  }

  #[test]
  fn checkpoint_round_trips_as_a_canonical_signed_note() {
    let checkpoint = StaticCheckpoint {
      origin: "ct.example/2026h1".to_string(),
      tree_size: 42,
      root_hash: [3; 32],
      timestamp: 99,
      tree_head_signature: DigitallySigned {
        hash_algorithm: HASH_ALGORITHM_SHA256,
        signature_algorithm: SIGNATURE_ALGORITHM_ECDSA,
        signature: vec![0x30, 0],
      },
    };
    let rendered = checkpoint.render(&[4; 32]).unwrap();
    assert_eq!(
      StaticCheckpoint::parse(&rendered, &[4; 32]).unwrap(),
      checkpoint
    );
    assert!(StaticCheckpoint::parse(&rendered, &[5; 32]).is_err());
    assert_eq!(checkpoint.signed_tree_head_input().len(), 50);
  }

  #[test]
  fn checkpoint_rejects_extensions_and_noncanonical_sizes() {
    let root = base64::engine::general_purpose::STANDARD.encode([0; 32]);
    let note = format!("ct.example\n01\n{root}\nextension\n\n");
    assert!(StaticCheckpoint::parse(&note, &[0; 32]).is_err());
  }
}
