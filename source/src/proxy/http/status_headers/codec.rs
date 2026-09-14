//! Bounded RFC 8941 validation for untrusted diagnostic chains.
use std::fmt;

use http::{HeaderMap, HeaderValue};
use sfv::visitor::{
  EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ListVisitor, ParameterVisitor,
};
use sfv::{BareItemFromInput, KeyRef, Parser};

pub(super) const MAX_BYTES: usize = 4096;
const MAX_MEMBERS: usize = 16;
const MAX_PARAMETERS: usize = 16;

#[derive(Clone, Default)]
pub(super) struct Chain {
  value: Option<HeaderValue>,
  members: usize,
}

impl Chain {
  pub(super) fn read(headers: &HeaderMap, name: &'static str) -> Self {
    let mut joined = Vec::new();
    let mut seen_field = false;
    for value in headers.get_all(name) {
      let separator = usize::from(seen_field) * 2;
      seen_field = true;
      if joined
        .len()
        .saturating_add(separator)
        .saturating_add(value.len())
        > MAX_BYTES
      {
        return Self::default();
      }
      if separator != 0 {
        joined.extend_from_slice(b", ");
      }
      joined.extend_from_slice(value.as_bytes());
    }
    let Ok(members) = Parser::new(&joined)
      .with_version(sfv::Version::Rfc8941)
      .parse_list_with_visitor(CheckList {
        members: 0,
        cache: name == "cache-status",
      })
    else {
      return Self::default();
    };
    if members == 0 {
      return Self::default();
    }
    Self {
      value: HeaderValue::from_bytes(&joined).ok(),
      members,
    }
  }

  pub(super) fn append(&self, local: Option<&str>) -> Option<HeaderValue> {
    let Some(local) = local else {
      return self.value.clone();
    };
    if let Some(value) = &self.value
      && self.members < MAX_MEMBERS
      && value.len() + 2 + local.len() <= MAX_BYTES
    {
      let mut bytes = Vec::with_capacity(value.len() + 2 + local.len());
      bytes.extend_from_slice(value.as_bytes());
      bytes.extend_from_slice(b", ");
      bytes.extend_from_slice(local.as_bytes());
      return HeaderValue::from_bytes(&bytes).ok();
    }
    (local.len() <= MAX_BYTES)
      .then(|| HeaderValue::from_str(local).ok())
      .flatten()
  }
}

#[derive(Debug)]
struct InvalidChain;
impl fmt::Display for InvalidChain {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("invalid diagnostic chain")
  }
}
impl std::error::Error for InvalidChain {}

struct CheckList {
  members: usize,
  cache: bool,
}
struct CheckItem {
  cache: bool,
}
struct CheckParameters {
  count: usize,
  cache: bool,
}
impl<'de> ListVisitor<'de> for CheckList {
  type Out = usize;
  type Error = InvalidChain;
  fn entry(&mut self) -> Result<impl EntryVisitor<'de>, Self::Error> {
    self.members += 1;
    if self.members > MAX_MEMBERS {
      return Err(InvalidChain);
    }
    Ok(CheckItem { cache: self.cache })
  }
  fn finish(self) -> Result<Self::Out, Self::Error> {
    Ok(self.members)
  }
}
impl<'de> EntryVisitor<'de> for CheckItem {
  type Error = InvalidChain;
  fn item(self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(self)
  }
  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Self::Error> {
    Err::<Ignored, _>(InvalidChain)
  }
}
impl<'de> ItemVisitor<'de> for CheckItem {
  type Out = ();
  type Error = InvalidChain;
  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    if !matches!(
      item,
      BareItemFromInput::String(_) | BareItemFromInput::Token(_)
    ) {
      return Err(InvalidChain);
    }
    Ok(CheckParameters {
      count: 0,
      cache: self.cache,
    })
  }
}
impl<'de> ParameterVisitor<'de> for CheckParameters {
  type Out = ();
  type Error = InvalidChain;
  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    self.count += 1;
    if self.count > MAX_PARAMETERS {
      return Err(InvalidChain);
    }
    use sfv::GenericBareItem::{Boolean, ByteSequence, Integer, String, Token};
    let valid = match (self.cache, key.as_str()) {
      (true, "hit" | "stored" | "collapsed") => matches!(value, Boolean(_)),
      (true, "fwd") | (false, "error") => matches!(value, Token(_)),
      (true, "fwd-status" | "ttl") | (false, "received-status") => matches!(value, Integer(_)),
      (true, "key") | (false, "details") => matches!(value, String(_)),
      (true, "detail") | (false, "next-hop") => matches!(value, String(_) | Token(_)),
      (false, "next-protocol") => matches!(value, Token(_) | ByteSequence(_)),
      _ => true,
    };
    if valid { Ok(()) } else { Err(InvalidChain) }
  }
  fn finish(self) -> Result<(), Self::Error> {
    Ok(())
  }
}

pub(super) fn quoted(value: &str) -> String {
  let mut result = String::with_capacity(value.len() + 2);
  result.push('"');
  for c in value.chars() {
    if c == '"' || c == '\\' {
      result.push('\\');
    }
    result.push(c);
  }
  result.push('"');
  result
}
