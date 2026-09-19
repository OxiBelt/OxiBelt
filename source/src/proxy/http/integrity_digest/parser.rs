use std::convert::Infallible;

use http::HeaderMap;
use sfv::visitor::{
  DictionaryVisitor, EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ParameterVisitor,
};
use sfv::{BareItemFromInput, KeyRef, Parser};

use super::{Algorithm, MAX_FIELD_BYTES, MAX_MEMBERS};

pub(super) fn wanted_algorithm(headers: &HeaderMap, name: &'static str) -> Option<Algorithm> {
  let mut input = Vec::new();
  let mut found = false;
  for value in headers.get_all(name) {
    if input
      .len()
      .saturating_add(value.len())
      .saturating_add(usize::from(found) * 2)
      > MAX_FIELD_BYTES
    {
      return None;
    }
    if found {
      input.extend_from_slice(b", ");
    }
    found = true;
    input.extend_from_slice(value.as_bytes());
  }
  if !found {
    return None;
  }
  let mut visitor = WantVisitor::default();
  Parser::new(&input)
    .parse_dictionary_with_visitor(&mut visitor)
    .ok()?;
  visitor.selected()
}

struct WantVisitor {
  members: usize,
  valid: bool,
  sha256: Option<i64>,
  sha512: Option<i64>,
}
struct WantEntry<'a> {
  target: Option<&'a mut Option<i64>>,
  valid: &'a mut bool,
}
impl WantVisitor {
  fn selected(&self) -> Option<Algorithm> {
    if !self.valid || self.members > MAX_MEMBERS {
      return None;
    }
    match (
      self.sha256.filter(|value| *value > 0),
      self.sha512.filter(|value| *value > 0),
    ) {
      (Some(left), Some(right)) => Some(if right > left {
        Algorithm::Sha512
      } else {
        Algorithm::Sha256
      }),
      (Some(_), None) => Some(Algorithm::Sha256),
      (None, Some(_)) => Some(Algorithm::Sha512),
      _ => None,
    }
  }
}
impl Default for WantVisitor {
  fn default() -> Self {
    Self {
      members: 0,
      valid: true,
      sha256: None,
      sha512: None,
    }
  }
}
impl<'de> DictionaryVisitor<'de> for &mut WantVisitor {
  type Out = ();
  type Error = Infallible;
  fn entry(&mut self, key: &'de KeyRef) -> Result<impl EntryVisitor<'de>, Infallible> {
    self.members += 1;
    let target = match key.as_str() {
      "sha-256" => Some(&mut self.sha256),
      "sha-512" => Some(&mut self.sha512),
      _ => None,
    };
    Ok(WantEntry {
      target,
      valid: &mut self.valid,
    })
  }
  fn finish(self) -> Result<Self::Out, Infallible> {
    Ok(())
  }
}
impl<'de> EntryVisitor<'de> for WantEntry<'_> {
  type Error = Infallible;
  fn item(self) -> Result<impl ItemVisitor<'de>, Infallible> {
    Ok(self)
  }
  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Infallible> {
    *self.valid = false;
    Ok(Ignored)
  }
}
impl<'de> ItemVisitor<'de> for WantEntry<'_> {
  type Out = ();
  type Error = Infallible;
  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Infallible> {
    let BareItemFromInput::Integer(value) = item else {
      *self.valid = false;
      return Ok(Ignored);
    };
    let value = i64::from(value);
    if !(0..=10).contains(&value) {
      *self.valid = false;
      return Ok(Ignored);
    }
    if let Some(target) = self.target {
      *target = Some(value);
    }
    Ok(Ignored)
  }
}
