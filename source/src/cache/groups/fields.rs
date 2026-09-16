//! Bounded RFC 9875 cache-group structured-field parsing.

use std::collections::HashSet;
use std::fmt;

use http::HeaderMap;
use sfv::visitor::{
  EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ListVisitor, ParameterVisitor,
};
use sfv::{BareItemFromInput, Parser};

const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_MEMBERS: usize = 64;
const MAX_MEMBER_BYTES: usize = 256;

/// The fail-closed result of parsing an RFC 9875 group field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GroupField {
  Absent,
  Valid(Vec<String>),
  Invalid,
  Bounded,
}

/// Parses every `Cache-Groups` field line as one RFC 9651 list.
pub(crate) fn parse_groups(headers: &HeaderMap) -> GroupField {
  parse_field(headers, "cache-groups")
}

/// Parses every `Cache-Group-Invalidation` field line as one RFC 9651 list.
pub(crate) fn parse_invalidation(headers: &HeaderMap) -> GroupField {
  parse_field(headers, "cache-group-invalidation")
}

fn parse_field(headers: &HeaderMap, name: &'static str) -> GroupField {
  let mut joined = Vec::new();
  let mut found = false;
  for value in headers.get_all(name) {
    let separator = usize::from(found) * 2;
    if joined
      .len()
      .saturating_add(separator)
      .saturating_add(value.len())
      > MAX_FIELD_BYTES
    {
      return GroupField::Bounded;
    }
    if found {
      joined.extend_from_slice(b", ");
    }
    found = true;
    joined.extend_from_slice(value.as_bytes());
  }
  if !found {
    return GroupField::Absent;
  }

  let mut visitor = GroupList::default();
  if Parser::new(&joined)
    .with_version(sfv::Version::Rfc9651)
    .parse_list_with_visitor(&mut visitor)
    .is_err()
  {
    return if visitor.bounded {
      GroupField::Bounded
    } else {
      GroupField::Invalid
    };
  }
  GroupField::Valid(visitor.groups)
}

#[derive(Default)]
struct GroupList {
  groups: Vec<String>,
  seen: HashSet<String>,
  members: usize,
  bounded: bool,
}

struct GroupItem<'a> {
  groups: &'a mut Vec<String>,
  seen: &'a mut HashSet<String>,
  bounded: &'a mut bool,
}

#[derive(Debug)]
enum GroupFieldError {
  Bounded,
  Invalid,
}

impl fmt::Display for GroupFieldError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("invalid cache group field")
  }
}

impl std::error::Error for GroupFieldError {}

impl<'de> ListVisitor<'de> for &mut GroupList {
  type Out = ();
  type Error = GroupFieldError;

  fn entry(&mut self) -> Result<impl EntryVisitor<'de>, Self::Error> {
    self.members += 1;
    if self.members > MAX_MEMBERS {
      self.bounded = true;
      return Err(GroupFieldError::Bounded);
    }
    Ok(GroupItem {
      groups: &mut self.groups,
      seen: &mut self.seen,
      bounded: &mut self.bounded,
    })
  }

  fn finish(self) -> Result<Self::Out, Self::Error> {
    Ok(())
  }
}

impl<'de> EntryVisitor<'de> for GroupItem<'_> {
  type Error = GroupFieldError;

  fn item(self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(self)
  }

  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Self::Error> {
    Err::<Ignored, _>(GroupFieldError::Invalid)
  }
}

impl<'de> ItemVisitor<'de> for GroupItem<'_> {
  type Out = ();
  type Error = GroupFieldError;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    let BareItemFromInput::String(value) = item else {
      return Err(GroupFieldError::Invalid);
    };
    if value.as_str().len() > MAX_MEMBER_BYTES {
      *self.bounded = true;
      return Err(GroupFieldError::Bounded);
    }
    let value = value.as_str().to_string();
    if self.seen.insert(value.clone()) {
      self.groups.push(value);
    }
    Ok(Ignored)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::HeaderValue;

  fn groups(value: &str) -> GroupField {
    let mut headers = HeaderMap::new();
    headers.insert("cache-groups", HeaderValue::from_str(value).unwrap());
    parse_groups(&headers)
  }

  #[test]
  fn accepts_strings_only_and_deduplicates_opaque_values() {
    assert_eq!(
      groups("\"A\";ignored=?1, \"a\", \"A\", \"\""),
      GroupField::Valid(vec!["A".to_string(), "a".to_string(), String::new()])
    );
    assert_eq!(groups("()"), GroupField::Invalid);
    assert_eq!(groups("\"one\", two"), GroupField::Invalid);
    assert_eq!(groups("\"one\", (\"two\")"), GroupField::Invalid);
  }

  #[test]
  fn ignores_rfc9651_parameters_but_rejects_non_string_members() {
    assert_eq!(
      groups("\"one\";at=@123;label=%\"caf%c3%a9\""),
      GroupField::Valid(vec!["one".to_string()])
    );
    assert_eq!(groups("@123"), GroupField::Invalid);
    assert_eq!(groups("%\"display\""), GroupField::Invalid);
    let mut headers = HeaderMap::new();
    headers.insert(
      "cache-group-invalidation",
      HeaderValue::from_static("\"one\";at=@123;label=%\"display\""),
    );
    assert_eq!(
      parse_invalidation(&headers),
      GroupField::Valid(vec!["one".into()])
    );
  }

  #[test]
  fn combines_field_lines_and_keeps_empty_list_valid() {
    let mut headers = HeaderMap::new();
    headers.append("cache-groups", HeaderValue::from_static("\"one\""));
    headers.append("cache-groups", HeaderValue::from_static("\"two\""));
    assert_eq!(
      parse_groups(&headers),
      GroupField::Valid(vec!["one".to_string(), "two".to_string()])
    );

    headers.clear();
    headers.insert("cache-group-invalidation", HeaderValue::from_static(""));
    assert_eq!(parse_invalidation(&headers), GroupField::Valid(Vec::new()));
  }

  #[test]
  fn bounds_raw_members_decoded_members_and_joined_field() {
    let members = std::iter::repeat_n("\"x\"", MAX_MEMBERS + 1)
      .collect::<Vec<_>>()
      .join(", ");
    assert_eq!(groups(&members), GroupField::Bounded);
    assert_eq!(
      groups(&format!("\"{}\"", "x".repeat(MAX_MEMBER_BYTES + 1))),
      GroupField::Bounded
    );

    let mut headers = HeaderMap::new();
    headers.insert(
      "cache-groups",
      HeaderValue::from_bytes(&vec![b'x'; MAX_FIELD_BYTES + 1]).unwrap(),
    );
    assert_eq!(parse_groups(&headers), GroupField::Bounded);
  }

  #[test]
  fn absent_fields_remain_distinct() {
    assert_eq!(parse_groups(&HeaderMap::new()), GroupField::Absent);
    assert_eq!(parse_invalidation(&HeaderMap::new()), GroupField::Absent);
  }
}
