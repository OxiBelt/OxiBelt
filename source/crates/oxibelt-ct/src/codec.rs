//! Strict TLS-presentation-language vector codecs used by CT v1 and v2.

use super::{CtError, Result};

pub const U24_MAX: usize = 0x00ff_ffff;

#[derive(Clone, Debug)]
pub struct Reader<'a> {
  input: &'a [u8],
  offset: usize,
}

impl<'a> Reader<'a> {
  pub const fn new(input: &'a [u8]) -> Self {
    Self { input, offset: 0 }
  }

  pub fn remaining(&self) -> usize {
    self.input.len().saturating_sub(self.offset)
  }

  pub fn is_empty(&self) -> bool {
    self.remaining() == 0
  }

  pub fn finish(self) -> Result<()> {
    if self.offset == self.input.len() {
      Ok(())
    } else {
      Err(CtError::new("trailing CT wire data"))
    }
  }

  pub fn take(&mut self, length: usize) -> Result<&'a [u8]> {
    let end = self
      .offset
      .checked_add(length)
      .ok_or_else(|| CtError::new("CT length overflow"))?;
    let bytes = self
      .input
      .get(self.offset..end)
      .ok_or_else(|| CtError::new("truncated CT wire data"))?;
    self.offset = end;
    Ok(bytes)
  }

  pub fn u8(&mut self) -> Result<u8> {
    Ok(self.take(1)?[0])
  }

  pub fn u16(&mut self) -> Result<u16> {
    let bytes: [u8; 2] = self
      .take(2)?
      .try_into()
      .map_err(|_| CtError::new("truncated CT u16"))?;
    Ok(u16::from_be_bytes(bytes))
  }

  pub fn u24(&mut self) -> Result<usize> {
    let bytes = self.take(3)?;
    Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
  }

  pub fn u40(&mut self) -> Result<u64> {
    let bytes = self.take(5)?;
    Ok(
      (u64::from(bytes[0]) << 32)
        | (u64::from(bytes[1]) << 24)
        | (u64::from(bytes[2]) << 16)
        | (u64::from(bytes[3]) << 8)
        | u64::from(bytes[4]),
    )
  }

  pub fn u64(&mut self) -> Result<u64> {
    let bytes: [u8; 8] = self
      .take(8)?
      .try_into()
      .map_err(|_| CtError::new("truncated CT u64"))?;
    Ok(u64::from_be_bytes(bytes))
  }

  pub fn vector_u8(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8]> {
    let length = usize::from(self.u8()?);
    bounded_vector(self, length, minimum, maximum)
  }

  pub fn vector_u16(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8]> {
    let length = usize::from(self.u16()?);
    bounded_vector(self, length, minimum, maximum)
  }

  pub fn vector_u24(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8]> {
    let length = self.u24()?;
    bounded_vector(self, length, minimum, maximum.min(U24_MAX))
  }
}

fn bounded_vector<'a>(
  reader: &mut Reader<'a>,
  length: usize,
  minimum: usize,
  maximum: usize,
) -> Result<&'a [u8]> {
  if minimum > maximum || !(minimum..=maximum).contains(&length) {
    return Err(CtError::new(
      "CT vector length is outside its declared bounds",
    ));
  }
  reader.take(length)
}

pub fn push_u24(output: &mut Vec<u8>, value: usize) -> Result<()> {
  if value > U24_MAX {
    return Err(CtError::new("CT u24 value is too large"));
  }
  output.extend_from_slice(&[
    ((value >> 16) & 0xff) as u8,
    ((value >> 8) & 0xff) as u8,
    (value & 0xff) as u8,
  ]);
  Ok(())
}

pub fn push_u40(output: &mut Vec<u8>, value: u64) -> Result<()> {
  if value >= (1_u64 << 40) {
    return Err(CtError::new("CT u40 value is too large"));
  }
  output.extend_from_slice(&value.to_be_bytes()[3..]);
  Ok(())
}

pub fn push_vector_u8(output: &mut Vec<u8>, bytes: &[u8], minimum: usize) -> Result<()> {
  if bytes.len() < minimum || bytes.len() > usize::from(u8::MAX) {
    return Err(CtError::new(
      "CT u8 vector length is outside its declared bounds",
    ));
  }
  output.push(bytes.len() as u8);
  output.extend_from_slice(bytes);
  Ok(())
}

pub fn push_vector_u16(output: &mut Vec<u8>, bytes: &[u8], minimum: usize) -> Result<()> {
  if bytes.len() < minimum || bytes.len() > usize::from(u16::MAX) {
    return Err(CtError::new(
      "CT u16 vector length is outside its declared bounds",
    ));
  }
  output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
  output.extend_from_slice(bytes);
  Ok(())
}

pub fn push_vector_u24(output: &mut Vec<u8>, bytes: &[u8], minimum: usize) -> Result<()> {
  if bytes.len() < minimum || bytes.len() > U24_MAX {
    return Err(CtError::new(
      "CT u24 vector length is outside its declared bounds",
    ));
  }
  push_u24(output, bytes.len())?;
  output.extend_from_slice(bytes);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn integer_and_vector_codecs_are_canonical() {
    let mut bytes = Vec::new();
    push_u24(&mut bytes, U24_MAX).unwrap();
    push_u40(&mut bytes, (1_u64 << 40) - 1).unwrap();
    push_vector_u16(&mut bytes, b"abc", 0).unwrap();
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.u24().unwrap(), U24_MAX);
    assert_eq!(reader.u40().unwrap(), (1_u64 << 40) - 1);
    assert_eq!(reader.vector_u16(0, 3).unwrap(), b"abc");
    reader.finish().unwrap();
  }

  #[test]
  fn malformed_lengths_and_trailing_data_fail_closed() {
    assert!(Reader::new(&[0, 0, 2, 1]).vector_u24(1, 8).is_err());
    assert!(Reader::new(&[0, 2, 1]).vector_u16(0, 8).is_err());
    assert!(Reader::new(&[1]).finish().is_err());
    assert!(push_u24(&mut Vec::new(), U24_MAX + 1).is_err());
    assert!(push_u40(&mut Vec::new(), 1_u64 << 40).is_err());
  }
}
