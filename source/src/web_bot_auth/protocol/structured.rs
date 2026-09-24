//! RFC 8941 structured-field parsing and canonical serialization helpers.
// sfv's visitor callbacks permit broader associated return bounds.
#![allow(refining_impl_trait_internal)]

use std::{collections::BTreeMap, convert::Infallible};

use http::HeaderMap;
use sfv::visitor::{
  DictionaryVisitor, EntryVisitor, InnerListVisitor, ItemVisitor, ParameterVisitor,
};
use sfv::{BareItem, BareItemFromInput, ItemSerializer, KeyRef, Parser, RefBareItem};

use super::MAX_HEADER_BYTES;

#[derive(Clone, Debug)]
pub(super) struct Item {
  pub(super) bare: BareItem,
  pub(super) params: Vec<(String, BareItem)>,
}
#[derive(Clone, Debug)]
pub(super) enum Member {
  Item(Item),
  Inner(Vec<Item>, Vec<(String, BareItem)>),
}
pub(super) type Dict = BTreeMap<String, Member>;

struct DictReader<'a> {
  out: Dict,
  order: Option<&'a mut Vec<String>>,
}
struct EntryReader<'a> {
  key: String,
  out: &'a mut Dict,
}
struct ItemReader<'a> {
  out: &'a mut Member,
}
struct InnerReader<'a> {
  items: Vec<Item>,
  out: &'a mut Member,
}
struct InnerItemReader<'a> {
  out: &'a mut Vec<Item>,
}
struct ItemParams<'a> {
  bare: BareItem,
  params: Vec<(String, BareItem)>,
  out: &'a mut Member,
}
struct InnerItemParams<'a> {
  bare: BareItem,
  params: Vec<(String, BareItem)>,
  out: &'a mut Vec<Item>,
}
struct InnerParams<'a> {
  items: Vec<Item>,
  params: Vec<(String, BareItem)>,
  out: &'a mut Member,
}

impl<'de> DictionaryVisitor<'de> for DictReader<'_> {
  type Out = Dict;
  type Error = Infallible;
  fn entry(
    &mut self,
    key: &'de KeyRef,
  ) -> Result<impl EntryVisitor<'de, Error = Self::Error>, Self::Error> {
    if let Some(order) = &mut self.order {
      order.retain(|entry| entry != key.as_str());
      order.push(key.as_str().into());
    }
    Ok(EntryReader {
      key: key.as_str().into(),
      out: &mut self.out,
    })
  }
  fn finish(self) -> Result<Dict, Self::Error> {
    Ok(self.out)
  }
}
impl<'de> EntryVisitor<'de> for EntryReader<'_> {
  type Error = Infallible;
  fn item(self) -> Result<impl ItemVisitor<'de, Error = Self::Error>, Self::Error> {
    let out = self
      .out
      .entry(self.key)
      .or_insert_with(|| Member::Inner(Vec::new(), Vec::new()));
    Ok(ItemReader { out })
  }
  fn inner_list(self) -> Result<impl InnerListVisitor<'de, Error = Self::Error>, Self::Error> {
    let out = self
      .out
      .entry(self.key)
      .or_insert_with(|| Member::Inner(Vec::new(), Vec::new()));
    Ok(InnerReader {
      items: Vec::new(),
      out,
    })
  }
}
impl<'de> ItemVisitor<'de> for ItemReader<'_> {
  type Out = ();
  type Error = Infallible;
  fn bare_item(
    self,
    bare: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = (), Error = Self::Error>, Self::Error> {
    Ok(ItemParams {
      bare: bare.into(),
      params: Vec::new(),
      out: self.out,
    })
  }
}
impl<'de> InnerListVisitor<'de> for InnerReader<'_> {
  type Error = Infallible;
  fn item(&mut self) -> Result<impl ItemVisitor<'de, Error = Self::Error>, Self::Error> {
    Ok(InnerItemReader {
      out: &mut self.items,
    })
  }
  fn finish(self) -> Result<impl ParameterVisitor<'de, Error = Self::Error>, Self::Error> {
    Ok(InnerParams {
      items: self.items,
      params: Vec::new(),
      out: self.out,
    })
  }
}
impl<'de> ItemVisitor<'de> for InnerItemReader<'_> {
  type Out = ();
  type Error = Infallible;
  fn bare_item(
    self,
    bare: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = (), Error = Self::Error>, Self::Error> {
    Ok(InnerItemParams {
      bare: bare.into(),
      params: Vec::new(),
      out: self.out,
    })
  }
}
pub(super) fn put_param(
  params: &mut Vec<(String, BareItem)>,
  key: &KeyRef,
  value: BareItemFromInput<'_>,
) {
  if let Some((_, old)) = params.iter_mut().find(|(name, _)| name == key.as_str()) {
    *old = value.into();
  } else {
    params.push((key.as_str().into(), value.into()));
  }
}
impl<'de> ParameterVisitor<'de> for ItemParams<'_> {
  type Out = ();
  type Error = Infallible;
  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    put_param(&mut self.params, key, value);
    Ok(())
  }
  fn finish(self) -> Result<(), Self::Error> {
    *self.out = Member::Item(Item {
      bare: self.bare,
      params: self.params,
    });
    Ok(())
  }
}
impl<'de> ParameterVisitor<'de> for InnerItemParams<'_> {
  type Out = ();
  type Error = Infallible;
  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    put_param(&mut self.params, key, value);
    Ok(())
  }
  fn finish(self) -> Result<(), Self::Error> {
    self.out.push(Item {
      bare: self.bare,
      params: self.params,
    });
    Ok(())
  }
}
impl<'de> ParameterVisitor<'de> for InnerParams<'_> {
  type Out = ();
  type Error = Infallible;
  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    put_param(&mut self.params, key, value);
    Ok(())
  }
  fn finish(self) -> Result<(), Self::Error> {
    *self.out = Member::Inner(self.items, self.params);
    Ok(())
  }
}

pub(super) fn field(headers: &HeaderMap, name: &str) -> Result<Option<Vec<u8>>, ()> {
  let mut combined = Vec::new();
  let mut found = false;
  for value in headers.get_all(name) {
    if found {
      combined.extend_from_slice(b", ");
    }
    found = true;
    combined.extend_from_slice(trim_ows(value.as_bytes()));
    if combined.len() > MAX_HEADER_BYTES {
      return Err(());
    }
  }
  Ok(found.then_some(combined))
}
pub(super) fn trim_ows(mut bytes: &[u8]) -> &[u8] {
  while matches!(bytes.first(), Some(b' ' | b'\t')) {
    bytes = &bytes[1..];
  }
  while matches!(bytes.last(), Some(b' ' | b'\t')) {
    bytes = &bytes[..bytes.len() - 1];
  }
  bytes
}
pub(super) fn dictionary(raw: &[u8]) -> Result<Dict, ()> {
  Parser::new(raw)
    .with_version(sfv::Version::Rfc8941)
    .parse_dictionary_with_visitor(DictReader {
      out: BTreeMap::new(),
      order: None,
    })
    .map_err(|_| ())
}
fn ordered_dictionary(raw: &[u8]) -> Result<(Dict, Vec<String>), ()> {
  let mut order = Vec::new();
  let dict = Parser::new(raw)
    .with_version(sfv::Version::Rfc8941)
    .parse_dictionary_with_visitor(DictReader {
      out: BTreeMap::new(),
      order: Some(&mut order),
    })
    .map_err(|_| ())?;
  Ok((dict, order))
}
pub(super) fn bare_string(item: &BareItem) -> Option<&str> {
  if let BareItem::String(value) = item {
    Some(value.as_str())
  } else {
    None
  }
}
pub(super) fn param<'a>(params: &'a [(String, BareItem)], name: &str) -> Option<&'a BareItem> {
  params
    .iter()
    .find(|(key, _)| key == name)
    .map(|(_, value)| value)
}
pub(super) fn sf_item(item: &Item) -> Result<String, ()> {
  let mut ser = ItemSerializer::new().bare_item(RefBareItem::from(&item.bare));
  for (key, value) in &item.params {
    ser = ser.parameter(
      KeyRef::from_str(key).map_err(|_| ())?,
      RefBareItem::from(value),
    );
  }
  Ok(ser.finish())
}
pub(super) fn sf_inner(items: &[Item], params: &[(String, BareItem)]) -> Result<String, ()> {
  let mut text = String::from("(");
  for (i, item) in items.iter().enumerate() {
    if i != 0 {
      text.push(' ');
    }
    text.push_str(&sf_item(item)?);
  }
  text.push(')');
  for (key, value) in params {
    let rendered = ItemSerializer::new()
      .bare_item(RefBareItem::from(value))
      .finish();
    text.push(';');
    text.push_str(key);
    if rendered != "?1" {
      text.push('=');
      text.push_str(&rendered);
    }
  }
  Ok(text)
}
pub(super) fn member_value(member: &Member) -> Result<String, ()> {
  match member {
    Member::Item(item) => sf_item(item),
    Member::Inner(items, params) => sf_inner(items, params),
  }
}
pub(super) fn serialize_dictionary(raw: &[u8]) -> Option<String> {
  let (dict, order) = ordered_dictionary(raw).ok()?;
  let mut output = String::new();
  for key in order {
    if !output.is_empty() {
      output.push_str(", ");
    }
    let member = dict.get(&key)?;
    output.push_str(&key);
    match member {
      Member::Item(Item {
        bare: BareItem::Boolean(true),
        params,
      }) => {
        for (name, value) in params {
          output.push(';');
          output.push_str(name);
          let rendered = ItemSerializer::new()
            .bare_item(RefBareItem::from(value))
            .finish();
          if rendered != "?1" {
            output.push('=');
            output.push_str(&rendered);
          }
        }
      }
      _ => {
        output.push('=');
        output.push_str(&member_value(member).ok()?);
      }
    }
  }
  Some(output)
}
