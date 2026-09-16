//! Bounded draft-09 `No-Vary-Search` parsing and query comparison.
//!
//! This module only models the response field and URI comparison.  It does not
//! choose cache entries or perform storage operations.

use std::cmp::Ordering;
use std::fmt;

use http::{HeaderMap, Uri};
use serde::{Deserialize, Serialize};
use sfv::visitor::{
  DictionaryVisitor, EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ParameterVisitor,
};
use sfv::{BareItemFromInput, KeyRef, Parser};

const MAX_FIELD_BYTES: usize = 4 * 1024;
const MAX_PARAMETER_NAMES: usize = 128;
const MAX_QUERY_PAIRS: usize = 1024;

/// The outcome of parsing a response's `No-Vary-Search` field.
///
/// All outcomes other than [`Self::Valid`] retain exact query matching.  The
/// distinction lets callers record why an origin-provided rule was unavailable
/// without treating malformed fields as an instruction to broaden reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NoVarySearchParse {
  Absent,
  Default,
  Invalid,
  Bounded,
  Valid(NoVarySearch),
}

/// A validated, non-default draft-09 URL variation configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct NoVarySearch {
  /// `key-order` is an opt-in signal that parameter order does not vary the
  /// representation.  Its absence (or `?0`) preserves order.
  ignore_key_order: bool,
  parameter_mode: ParameterMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum ParameterMode {
  /// Named parameters do not vary the representation.
  Ignore(Vec<String>),
  /// Only named parameters vary the representation.
  Keep(Vec<String>),
}

impl NoVarySearch {
  pub(crate) fn is_default(&self) -> bool {
    !self.ignore_key_order
      && matches!(&self.parameter_mode, ParameterMode::Ignore(names) if names.is_empty())
  }

  /// Returns a stable, form-urlencoded query representation under this rule.
  /// `None` is reserved for an over-limit request query; an absent or empty
  /// query is represented by `Some("")`.
  pub(crate) fn canonical_query(&self, uri: &Uri) -> Option<String> {
    let mut pairs = Vec::new();
    if let Some(query) = uri.query() {
      for (index, (name, value)) in url::form_urlencoded::parse(query.as_bytes()).enumerate() {
        if index == MAX_QUERY_PAIRS {
          return None;
        }
        pairs.push(QueryPair {
          name: name.into_owned(),
          value: value.into_owned(),
        });
      }
    }
    pairs.retain(|pair| self.keeps_parameter(&pair.name));
    if self.ignore_key_order {
      // `sort_by` is stable, retaining the received order of duplicate pairs.
      pairs.sort_by(|left, right| utf16_cmp(&left.name, &right.name));
    }
    let mut serialized = url::form_urlencoded::Serializer::new(String::new());
    for pair in pairs {
      serialized.append_pair(&pair.name, &pair.value);
    }
    Some(serialized.finish())
  }

  /// Applies draft-09 query equivalence while keeping every non-query URI
  /// component exact.  Callers with stronger cache namespaces still enforce
  /// those namespaces separately.
  pub(crate) fn equivalent(&self, left: &Uri, right: &Uri) -> bool {
    left.scheme_str() == right.scheme_str()
      && left.authority() == right.authority()
      && left.path() == right.path()
      && matches!(
        (self.canonical_query(left), self.canonical_query(right)),
        (Some(left), Some(right)) if left == right
      )
  }

  fn keeps_parameter(&self, name: &str) -> bool {
    match &self.parameter_mode {
      ParameterMode::Ignore(names) => !names.iter().any(|item| item == name),
      ParameterMode::Keep(names) => names.iter().any(|item| item == name),
    }
  }
}

/// Parses all response field lines as one RFC 9651 dictionary.
pub(crate) fn parse_no_vary_search(headers: &HeaderMap) -> NoVarySearchParse {
  let mut joined = Vec::new();
  let mut found = false;
  for value in headers.get_all("no-vary-search") {
    if found {
      if joined.len().saturating_add(2) > MAX_FIELD_BYTES {
        return NoVarySearchParse::Bounded;
      }
      joined.extend_from_slice(b", ");
    }
    found = true;
    if joined.len().saturating_add(value.len()) > MAX_FIELD_BYTES {
      return NoVarySearchParse::Bounded;
    }
    joined.extend_from_slice(value.as_bytes());
  }
  if !found {
    return NoVarySearchParse::Absent;
  }

  let mut fields = Vec::new();
  if Parser::new(&joined)
    .parse_dictionary_with_visitor(DictionaryFields {
      fields: &mut fields,
    })
    .is_err()
  {
    return NoVarySearchParse::Invalid;
  }

  let mut key_order = None;
  let mut params = None;
  let mut except = None;
  for (kind, value) in fields {
    // RFC 9651 dictionary duplicates are last-wins.
    match kind {
      KnownKey::KeyOrder => key_order = Some(value),
      KnownKey::Params => params = Some(value),
      KnownKey::Except => except = Some(value),
      KnownKey::Unknown => {}
    }
  }
  let key_order = match key_order {
    Some(FieldValue::Boolean(value)) => Some(value),
    Some(FieldValue::Strings(_) | FieldValue::Other) => return NoVarySearchParse::Invalid,
    None => None,
  };
  let params = match params {
    Some(FieldValue::Strings(value)) => Some(value),
    Some(FieldValue::Boolean(_) | FieldValue::Other) => return NoVarySearchParse::Invalid,
    None => None,
  };
  let except = match except {
    Some(FieldValue::Strings(value)) => Some(value),
    Some(FieldValue::Boolean(_) | FieldValue::Other) => return NoVarySearchParse::Invalid,
    None => None,
  };
  if params.is_some() && except.is_some() {
    return NoVarySearchParse::Invalid;
  }
  let ignore_key_order = key_order.unwrap_or(false);
  let parameter_mode = match (params, except) {
    (Some(names), None) => ParameterMode::Ignore(names),
    (None, Some(names)) => ParameterMode::Keep(names),
    (None, None) => ParameterMode::Ignore(Vec::new()),
    (Some(_), Some(_)) => return NoVarySearchParse::Invalid,
  };
  let rule = NoVarySearch {
    ignore_key_order,
    parameter_mode,
  };
  // `params=()` and `key-order=?0` have the draft's default exact behavior.
  if rule.is_default() {
    NoVarySearchParse::Default
  } else {
    NoVarySearchParse::Valid(rule)
  }
}

#[derive(Clone, Copy)]
enum KnownKey {
  KeyOrder,
  Params,
  Except,
  Unknown,
}

enum FieldValue {
  Boolean(bool),
  Strings(Vec<String>),
  Other,
}

struct DictionaryFields<'a> {
  fields: &'a mut Vec<(KnownKey, FieldValue)>,
}

struct FieldEntry<'a> {
  fields: &'a mut Vec<(KnownKey, FieldValue)>,
  kind: KnownKey,
}

struct FieldList<'a> {
  fields: &'a mut Vec<(KnownKey, FieldValue)>,
  kind: KnownKey,
  strings: Vec<String>,
  invalid: bool,
}

struct FieldListItem<'a> {
  strings: Option<&'a mut Vec<String>>,
  invalid: &'a mut bool,
}

#[derive(Debug)]
struct InvalidField;

impl fmt::Display for InvalidField {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str("invalid No-Vary-Search field")
  }
}

impl std::error::Error for InvalidField {}

impl<'de> DictionaryVisitor<'de> for DictionaryFields<'_> {
  type Out = ();
  type Error = InvalidField;

  fn entry(&mut self, key: &'de KeyRef) -> Result<impl EntryVisitor<'de>, Self::Error> {
    let kind = match key.as_str() {
      "key-order" => KnownKey::KeyOrder,
      "params" => KnownKey::Params,
      "except" => KnownKey::Except,
      _ => KnownKey::Unknown,
    };
    Ok(FieldEntry {
      fields: self.fields,
      kind,
    })
  }

  fn finish(self) -> Result<Self::Out, Self::Error> {
    Ok(())
  }
}

impl<'de> ItemVisitor<'de> for FieldEntry<'_> {
  type Out = ();
  type Error = InvalidField;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    match self.kind {
      KnownKey::KeyOrder => match item {
        BareItemFromInput::Boolean(value) => {
          self
            .fields
            .push((KnownKey::KeyOrder, FieldValue::Boolean(value)));
          Ok(Ignored)
        }
        _ => {
          self.fields.push((KnownKey::KeyOrder, FieldValue::Other));
          Ok(Ignored)
        }
      },
      KnownKey::Params | KnownKey::Except => {
        self.fields.push((self.kind, FieldValue::Other));
        Ok(Ignored)
      }
      KnownKey::Unknown => Ok(Ignored),
    }
  }
}

impl<'de> EntryVisitor<'de> for FieldEntry<'_> {
  type Error = InvalidField;

  fn item(self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(self)
  }

  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Self::Error> {
    Ok(FieldList {
      fields: self.fields,
      kind: self.kind,
      strings: Vec::new(),
      invalid: false,
    })
  }
}

impl<'de> InnerListVisitor<'de> for FieldList<'_> {
  type Error = InvalidField;

  fn item(&mut self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(FieldListItem {
      strings: match self.kind {
        KnownKey::Params | KnownKey::Except => Some(&mut self.strings),
        KnownKey::KeyOrder | KnownKey::Unknown => None,
      },
      invalid: &mut self.invalid,
    })
  }

  fn finish(self) -> Result<impl ParameterVisitor<'de>, Self::Error> {
    match self.kind {
      KnownKey::Params | KnownKey::Except if !self.invalid => {
        self
          .fields
          .push((self.kind, FieldValue::Strings(self.strings)));
      }
      KnownKey::Params | KnownKey::Except | KnownKey::KeyOrder => {
        self.fields.push((self.kind, FieldValue::Other));
      }
      KnownKey::Unknown => {}
    }
    Ok(Ignored)
  }
}

impl<'de> ItemVisitor<'de> for FieldListItem<'_> {
  type Out = ();
  type Error = InvalidField;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    let Some(strings) = self.strings else {
      return Ok(Ignored);
    };
    let BareItemFromInput::String(value) = item else {
      *self.invalid = true;
      return Ok(Ignored);
    };
    if strings.len() == MAX_PARAMETER_NAMES {
      *self.invalid = true;
      return Ok(Ignored);
    }
    strings.push(parse_parameter_name(value.as_str()));
    Ok(Ignored)
  }
}

struct QueryPair {
  name: String,
  value: String,
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
  left.encode_utf16().cmp(right.encode_utf16())
}

/// Draft-09 parses configured names as individual form keys.  It deliberately
/// does not treat `&` as a separator because a structured-field string names
/// exactly one parameter.
fn parse_parameter_name(value: &str) -> String {
  let mut bytes = Vec::with_capacity(value.len());
  let raw = value.as_bytes();
  let mut index = 0;
  while index < raw.len() {
    match raw[index] {
      b'+' => {
        bytes.push(b' ');
        index += 1;
      }
      b'%' if index + 2 < raw.len() => {
        let high = hex_value(raw[index + 1]);
        let low = hex_value(raw[index + 2]);
        if let (Some(high), Some(low)) = (high, low) {
          bytes.push((high << 4) | low);
          index += 3;
        } else {
          bytes.push(raw[index]);
          index += 1;
        }
      }
      byte => {
        bytes.push(byte);
        index += 1;
      }
    }
  }
  String::from_utf8_lossy(&bytes).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
  match byte {
    b'0'..=b'9' => Some(byte - b'0'),
    b'a'..=b'f' => Some(byte - b'a' + 10),
    b'A'..=b'F' => Some(byte - b'A' + 10),
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::HeaderValue;

  fn parse(value: &str) -> NoVarySearchParse {
    let mut headers = HeaderMap::new();
    headers.insert("no-vary-search", HeaderValue::from_str(value).unwrap());
    parse_no_vary_search(&headers)
  }

  #[test]
  fn parses_draft_nine_forms_and_uses_last_dictionary_member() {
    let NoVarySearchParse::Valid(rule) =
      parse("params=(\"utm+source\" \"a%26b\"), key-order=?0, key-order, ignored=42")
    else {
      panic!("valid rule expected");
    };
    assert_eq!(
      rule.canonical_query(&Uri::from_static("/search?utm+source=x&a%26b=y&q=z")),
      Some("q=z".to_string())
    );
    assert!(rule.equivalent(
      &Uri::from_static("/search?q=z&utm+source=one&a%26b=two"),
      &Uri::from_static("/search?q=z")
    ));
  }

  #[test]
  fn invalid_and_default_forms_stay_exact_only() {
    assert_eq!(
      parse("params=(\"a\"), except=(\"b\")"),
      NoVarySearchParse::Invalid
    );
    assert_eq!(parse("params=(not-a-string)"), NoVarySearchParse::Invalid);
    assert_eq!(parse("params=()"), NoVarySearchParse::Default);
    assert_eq!(parse("key-order=?0"), NoVarySearchParse::Default);
    assert!(matches!(parse("key-order"), NoVarySearchParse::Valid(_)));
    assert!(matches!(
      parse("params=?0, params=(\"ignored\")"),
      NoVarySearchParse::Valid(_)
    ));
  }

  #[test]
  fn query_order_uses_utf16_and_retains_duplicate_value_order() {
    let NoVarySearchParse::Valid(rule) = parse("key-order, params=()") else {
      panic!("valid wildcard rule expected");
    };
    assert!(rule.equivalent(
      &Uri::from_static("/x?%F0%90%80%80=1&%EE%80%80=2&a=first&a=second"),
      &Uri::from_static("/x?a=first&a=second&%EE%80%80=2&%F0%90%80%80=1")
    ));
    assert!(!rule.equivalent(
      &Uri::from_static("/x?a=first&a=second"),
      &Uri::from_static("/x?a=second&a=first")
    ));
  }

  #[test]
  fn bounds_are_fail_closed_and_nonquery_targets_remain_exact() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "no-vary-search",
      HeaderValue::from_str(&format!("params=(\"{}\")", "a".repeat(4096))).unwrap(),
    );
    assert_eq!(parse_no_vary_search(&headers), NoVarySearchParse::Bounded);
    let NoVarySearchParse::Valid(rule) = parse("params=(\"ignored\")") else {
      panic!("valid rule expected");
    };
    assert!(!rule.equivalent(
      &Uri::from_static("/a?ignored=1"),
      &Uri::from_static("/b?ignored=2")
    ));
    let query = (0..=MAX_QUERY_PAIRS)
      .map(|item| format!("a{item}=1"))
      .collect::<Vec<_>>()
      .join("&");
    let uri: Uri = format!("/x?{query}").parse().unwrap();
    assert_eq!(rule.canonical_query(&uri), None);
    assert!(!rule.equivalent(&uri, &uri));
  }
}
