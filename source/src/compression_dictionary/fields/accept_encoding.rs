use super::MAX_ACCEPT_ENCODING_BYTES;

#[derive(Clone, Debug)]
pub(super) struct CodingQuality {
  name: String,
  quality: u16,
}

pub(super) fn parse_accept_encoding(value: &str) -> Option<Vec<CodingQuality>> {
  if value.len() > MAX_ACCEPT_ENCODING_BYTES || !value.is_ascii() {
    return None;
  }
  let mut values = Vec::new();
  for raw_coding in value.split(',') {
    let mut fields = raw_coding.trim().split(';');
    let name = fields.next()?.trim().to_ascii_lowercase();
    if name.is_empty() || !name.bytes().all(is_token_byte) {
      return None;
    }
    let mut quality = 1000;
    for parameter in fields {
      let (name, value) = parameter.trim().split_once('=')?;
      if name.trim().eq_ignore_ascii_case("q") {
        quality = parse_quality(value.trim())?;
      }
    }
    values.push(CodingQuality { name, quality });
  }
  Some(values)
}

pub(super) fn coding_quality(values: &[CodingQuality], coding: &str) -> Option<u16> {
  let explicit: Vec<u16> = values
    .iter()
    .filter(|value| value.name == coding)
    .map(|value| value.quality)
    .collect();
  if !explicit.is_empty() {
    return explicit.into_iter().min();
  }
  values
    .iter()
    .filter(|value| value.name == "*")
    .map(|value| value.quality)
    .min()
}

fn parse_quality(value: &str) -> Option<u16> {
  if value == "0" || value == "0." {
    return Some(0);
  }
  if value == "1." {
    return Some(1000);
  }
  if value == "1" || value == "1.0" || value == "1.00" || value == "1.000" {
    return Some(1000);
  }
  let fraction = value.strip_prefix("0.")?;
  if fraction.is_empty()
    || fraction.len() > 3
    || !fraction.bytes().all(|byte| byte.is_ascii_digit())
  {
    return None;
  }
  Some(fraction.parse::<u16>().ok()? * 10_u16.pow((3 - fraction.len()) as u32))
}

fn is_token_byte(byte: u8) -> bool {
  byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte) || byte == b'*'
}
