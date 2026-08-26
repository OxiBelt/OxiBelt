//! Minimal, strict DER framing used to preserve the precertificate transcript.

use anyhow::{anyhow, bail};

const SCT_EXTENSION_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
const P256_SPKI_PREFIX: &[u8] = &[
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const RSA_ALGORITHM_IDENTIFIER: &[u8] = &[
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

#[derive(Debug)]
pub(super) struct EmbeddedSctMaterial {
  pub(super) tbs_certificate: Vec<u8>,
  pub(super) sct_list: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Tlv {
  tag: u8,
  start: usize,
  content_start: usize,
  end: usize,
}

impl Tlv {
  fn content(self, input: &[u8]) -> &[u8] {
    &input[self.content_start..self.end]
  }

  fn encoded(self, input: &[u8]) -> &[u8] {
    &input[self.start..self.end]
  }
}

pub(super) fn extract_embedded_sct_material(
  certificate_der: &[u8],
) -> anyhow::Result<Option<EmbeddedSctMaterial>> {
  let certificate = read_single(certificate_der, 0x30).map_err(|_| anyhow!("ct_leaf_der"))?;
  let certificate_children = children(certificate.content(certificate_der))?;
  let tbs = certificate_children
    .first()
    .copied()
    .filter(|value| value.tag == 0x30)
    .ok_or_else(|| anyhow!("ct_leaf_tbs"))?;
  let tbs_bytes = tbs.encoded(certificate.content(certificate_der));
  let tbs_outer = read_single(tbs_bytes, 0x30)?;
  let tbs_content = tbs_outer.content(tbs_bytes);
  let tbs_children = children(tbs_content)?;
  let extension_fields = tbs_children
    .iter()
    .copied()
    .filter(|value| value.tag == 0xa3)
    .collect::<Vec<_>>();
  if extension_fields.len() > 1 {
    bail!("ct_duplicate_extensions_field");
  }
  let Some(extension_field) = extension_fields.first().copied() else {
    return Ok(None);
  };
  let extension_sequence = read_single(extension_field.content(tbs_content), 0x30)
    .map_err(|_| anyhow!("ct_extensions_der"))?;
  let extension_sequence_bytes = extension_field.content(tbs_content);
  let extension_content = extension_sequence.content(extension_sequence_bytes);
  let extension_entries = children(extension_content)?;
  let mut matching = Vec::new();
  for extension in &extension_entries {
    if extension.tag != 0x30 {
      bail!("ct_extension_der");
    }
    let encoded = extension.encoded(extension_content);
    let parsed = parse_extension(encoded)?;
    if parsed.oid == SCT_EXTENSION_OID {
      matching.push((*extension, parsed));
    }
  }
  if matching.len() > 1 {
    bail!("ct_sct_extension_duplicate");
  }
  let Some((matching_extension, parsed)) = matching.pop() else {
    return Ok(None);
  };
  if parsed.critical {
    bail!("ct_sct_extension_critical");
  }
  let inner = read_single(parsed.value, 0x04).map_err(|_| anyhow!("ct_sct_extension_parse"))?;
  let sct_list = inner.content(parsed.value).to_vec();

  let mut remaining_extensions = Vec::with_capacity(extension_content.len());
  remaining_extensions.extend_from_slice(&extension_content[..matching_extension.start]);
  remaining_extensions.extend_from_slice(&extension_content[matching_extension.end..]);

  let replacement = if remaining_extensions.is_empty() {
    Vec::new()
  } else {
    let sequence = encode_tlv(0x30, &remaining_extensions);
    encode_tlv(0xa3, &sequence)
  };
  let mut rebuilt_tbs_content = Vec::with_capacity(tbs_content.len());
  rebuilt_tbs_content.extend_from_slice(&tbs_content[..extension_field.start]);
  rebuilt_tbs_content.extend_from_slice(&replacement);
  rebuilt_tbs_content.extend_from_slice(&tbs_content[extension_field.end..]);

  Ok(Some(EmbeddedSctMaterial {
    tbs_certificate: encode_tlv(0x30, &rebuilt_tbs_content),
    sct_list,
  }))
}

struct ParsedExtension<'a> {
  oid: &'a [u8],
  critical: bool,
  value: &'a [u8],
}

fn parse_extension(encoded: &[u8]) -> anyhow::Result<ParsedExtension<'_>> {
  let outer = read_single(encoded, 0x30)?;
  let content = outer.content(encoded);
  let fields = children(content)?;
  if !(2..=3).contains(&fields.len()) || fields[0].tag != 0x06 {
    bail!("ct_extension_fields");
  }
  let (critical, value_index) = if fields.len() == 3 {
    if fields[1].tag != 0x01 || fields[1].content(content) != [0xff] {
      bail!("ct_extension_critical_der");
    }
    (true, 2)
  } else {
    (false, 1)
  };
  if fields[value_index].tag != 0x04 {
    bail!("ct_extension_value");
  }
  Ok(ParsedExtension {
    oid: fields[0].content(content),
    critical,
    value: fields[value_index].content(content),
  })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicKeyKind {
  P256,
  Rsa,
}

pub(super) fn signature_public_key(spki_der: &[u8]) -> anyhow::Result<(PublicKeyKind, &[u8])> {
  if let Some(point) = spki_der.strip_prefix(P256_SPKI_PREFIX)
    && point.len() == 65
    && point.first() == Some(&0x04)
  {
    return Ok((PublicKeyKind::P256, point));
  }
  let outer = read_single(spki_der, 0x30).map_err(|_| anyhow!("ct_log_key_spki"))?;
  let content = outer.content(spki_der);
  let fields = children(content)?;
  if fields.len() != 2 || fields[0].encoded(content) != RSA_ALGORITHM_IDENTIFIER {
    bail!("ct_log_key_algorithm");
  }
  if fields[1].tag != 0x03 {
    bail!("ct_log_key_bit_string");
  }
  let bit_string = fields[1].content(content);
  if bit_string.first() != Some(&0) || bit_string.len() < 2 {
    bail!("ct_log_key_bit_string");
  }
  Ok((PublicKeyKind::Rsa, &bit_string[1..]))
}

fn children(input: &[u8]) -> anyhow::Result<Vec<Tlv>> {
  let mut offset = 0;
  let mut values = Vec::new();
  while offset < input.len() {
    let value = read_tlv(input, offset)?;
    if value.end <= offset {
      bail!("ct_der_progress");
    }
    offset = value.end;
    values.push(value);
  }
  if offset != input.len() {
    bail!("ct_der_trailing");
  }
  Ok(values)
}

fn read_single(input: &[u8], tag: u8) -> anyhow::Result<Tlv> {
  let value = read_tlv(input, 0)?;
  if value.tag != tag || value.end != input.len() {
    bail!("ct_der_single");
  }
  Ok(value)
}

fn read_tlv(input: &[u8], start: usize) -> anyhow::Result<Tlv> {
  let tag = *input.get(start).ok_or_else(|| anyhow!("ct_der_short"))?;
  if tag & 0x1f == 0x1f {
    bail!("ct_der_high_tag");
  }
  let first_length = *input
    .get(start.saturating_add(1))
    .ok_or_else(|| anyhow!("ct_der_short"))?;
  let (length, length_bytes) = if first_length & 0x80 == 0 {
    (usize::from(first_length), 1)
  } else {
    let count = usize::from(first_length & 0x7f);
    if count == 0 || count > std::mem::size_of::<usize>() {
      bail!("ct_der_length");
    }
    let bytes = input
      .get(start + 2..start + 2 + count)
      .ok_or_else(|| anyhow!("ct_der_short"))?;
    if bytes.first() == Some(&0) {
      bail!("ct_der_noncanonical_length");
    }
    let mut length = 0_usize;
    for byte in bytes {
      length = length
        .checked_mul(256)
        .and_then(|value| value.checked_add(usize::from(*byte)))
        .ok_or_else(|| anyhow!("ct_der_length"))?;
    }
    if length < 128 {
      bail!("ct_der_noncanonical_length");
    }
    (length, 1 + count)
  };
  let content_start = start
    .checked_add(1 + length_bytes)
    .ok_or_else(|| anyhow!("ct_der_length"))?;
  let end = content_start
    .checked_add(length)
    .ok_or_else(|| anyhow!("ct_der_length"))?;
  if end > input.len() {
    bail!("ct_der_short");
  }
  Ok(Tlv {
    tag,
    start,
    content_start,
    end,
  })
}

fn encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
  let mut output = Vec::with_capacity(content.len() + 10);
  output.push(tag);
  encode_length(content.len(), &mut output);
  output.extend_from_slice(content);
  output
}

fn encode_length(length: usize, output: &mut Vec<u8>) {
  if length < 128 {
    output.push(length as u8);
    return;
  }
  let bytes = length.to_be_bytes();
  let first = bytes
    .iter()
    .position(|byte| *byte != 0)
    .unwrap_or(bytes.len() - 1);
  let encoded = &bytes[first..];
  output.push(0x80 | encoded.len() as u8);
  output.extend_from_slice(encoded);
}

#[cfg(test)]
mod tests {
  use super::*;

  fn extension(oid: &[u8], value: &[u8]) -> Vec<u8> {
    let mut content = encode_tlv(0x06, oid);
    content.extend_from_slice(&encode_tlv(0x04, value));
    encode_tlv(0x30, &content)
  }

  #[test]
  fn removes_only_the_sct_extension_and_preserves_other_tlvs() {
    let other = extension(&[0x55, 0x1d, 0x13], &[0x30, 0x00]);
    let nested_scts = encode_tlv(0x04, &[0, 0]);
    let sct = extension(SCT_EXTENSION_OID, &nested_scts);
    let mut extensions = other.clone();
    extensions.extend_from_slice(&sct);
    let explicit = encode_tlv(0xa3, &encode_tlv(0x30, &extensions));
    let mut tbs_content = encode_tlv(0x02, &[1]);
    tbs_content.extend_from_slice(&explicit);
    let tbs = encode_tlv(0x30, &tbs_content);
    let mut cert_content = tbs;
    cert_content.extend_from_slice(&encode_tlv(0x30, &[]));
    cert_content.extend_from_slice(&encode_tlv(0x03, &[0]));
    let cert = encode_tlv(0x30, &cert_content);

    let material = extract_embedded_sct_material(&cert)
      .expect("valid DER")
      .expect("SCT extension");

    assert_eq!(material.sct_list, [0, 0]);
    assert!(
      material
        .tbs_certificate
        .windows(other.len())
        .any(|window| window == other)
    );
    assert!(
      !material
        .tbs_certificate
        .windows(SCT_EXTENSION_OID.len())
        .any(|window| window == SCT_EXTENSION_OID)
    );
  }

  #[test]
  fn duplicate_sct_extensions_fail_closed() {
    let nested = encode_tlv(0x04, &[0, 0]);
    let sct = extension(SCT_EXTENSION_OID, &nested);
    let mut extensions = sct.clone();
    extensions.extend_from_slice(&sct);
    let explicit = encode_tlv(0xa3, &encode_tlv(0x30, &extensions));
    let tbs = encode_tlv(0x30, &explicit);
    let mut cert_content = tbs;
    cert_content.extend_from_slice(&encode_tlv(0x30, &[]));
    cert_content.extend_from_slice(&encode_tlv(0x03, &[0]));
    let cert = encode_tlv(0x30, &cert_content);
    assert!(extract_embedded_sct_material(&cert).is_err());
  }
}
