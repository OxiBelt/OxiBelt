use sfv::{
  BareItemFromInput, KeyRef, Parser,
  visitor::{
    DictionaryVisitor, EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ParameterVisitor,
  },
};

use super::{
  DictionaryType, FieldError, MAX_DICTIONARY_ID_CHARS, MAX_MATCH_DESTINATION_BYTES,
  MAX_MATCH_DESTINATIONS, MAX_MATCH_PATTERN_BYTES, UseAsDictionary,
};

pub(super) fn parse_use_as_dictionary_value(value: &[u8]) -> Result<UseAsDictionary, FieldError> {
  Parser::new(value)
    .with_version(sfv::Version::Rfc8941)
    .parse_dictionary_with_visitor(UseAsDictionaryVisitor::default())
    .map_err(|error| {
      if error.to_string().contains("duplicate") {
        FieldError::DuplicateField
      } else {
        FieldError::InvalidStructuredField
      }
    })
}

#[derive(Default)]
struct UseAsDictionaryVisitor {
  match_pattern: Option<String>,
  match_destinations: Option<Vec<String>>,
  id: Option<String>,
  dictionary_type: Option<DictionaryType>,
}

impl<'de> DictionaryVisitor<'de> for UseAsDictionaryVisitor {
  type Out = UseAsDictionary;
  type Error = FieldError;

  fn entry(&mut self, key: &'de KeyRef) -> Result<impl EntryVisitor<'de>, Self::Error> {
    let slot = match key.as_str() {
      "match" => KnownMember::Match(&mut self.match_pattern),
      "match-dest" => KnownMember::Destinations(&mut self.match_destinations),
      "id" => KnownMember::Id(&mut self.id),
      "type" => KnownMember::Type(&mut self.dictionary_type),
      _ => KnownMember::Ignored,
    };
    Ok(UseAsDictionaryEntry { slot })
  }

  fn finish(self) -> Result<Self::Out, Self::Error> {
    let match_pattern = self.match_pattern.ok_or(FieldError::InvalidMember)?;
    Ok(UseAsDictionary {
      match_pattern,
      match_destinations: self.match_destinations.unwrap_or_default(),
      id: self.id.unwrap_or_default(),
      dictionary_type: self.dictionary_type.unwrap_or(DictionaryType::Raw),
    })
  }
}

enum KnownMember<'a> {
  Match(&'a mut Option<String>),
  Destinations(&'a mut Option<Vec<String>>),
  Id(&'a mut Option<String>),
  Type(&'a mut Option<DictionaryType>),
  Ignored,
}

struct UseAsDictionaryEntry<'a> {
  slot: KnownMember<'a>,
}

impl<'de> EntryVisitor<'de> for UseAsDictionaryEntry<'_> {
  type Error = FieldError;

  fn item(self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(UseAsDictionaryItem { slot: self.slot })
  }

  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Self::Error> {
    match self.slot {
      KnownMember::Destinations(slot) if slot.is_none() => {
        Ok(UseAsDictionaryInnerList { values: Some(slot) })
      }
      KnownMember::Destinations(_)
      | KnownMember::Match(_)
      | KnownMember::Id(_)
      | KnownMember::Type(_) => Err(FieldError::InvalidMember),
      KnownMember::Ignored => Ok(UseAsDictionaryInnerList { values: None }),
    }
  }
}

struct UseAsDictionaryItem<'a> {
  slot: KnownMember<'a>,
}

impl<'de> ItemVisitor<'de> for UseAsDictionaryItem<'_> {
  type Out = ();
  type Error = FieldError;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    match self.slot {
      KnownMember::Match(slot) if slot.is_none() => {
        let value = string_item(item)?;
        if value.len() > MAX_MATCH_PATTERN_BYTES {
          return Err(FieldError::InputTooLong);
        }
        *slot = Some(value);
      }
      KnownMember::Id(slot) if slot.is_none() => {
        let value = string_item(item)?;
        if value.chars().count() > MAX_DICTIONARY_ID_CHARS {
          return Err(FieldError::DictionaryIdTooLong);
        }
        *slot = Some(value);
      }
      KnownMember::Type(slot) if slot.is_none() => {
        let token = token_item(item)?;
        *slot = Some(if token == "raw" {
          DictionaryType::Raw
        } else {
          DictionaryType::Unknown(token)
        });
      }
      KnownMember::Ignored => return Ok(Ignored),
      _ => return Err(FieldError::DuplicateField),
    }
    Ok(Ignored)
  }
}

struct UseAsDictionaryInnerList<'a> {
  values: Option<&'a mut Option<Vec<String>>>,
}

impl<'de> InnerListVisitor<'de> for UseAsDictionaryInnerList<'_> {
  type Error = FieldError;

  fn item(&mut self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(DestinationItem {
      values: self.values.as_deref_mut(),
    })
  }

  fn finish(self) -> Result<impl ParameterVisitor<'de>, Self::Error> {
    if let Some(values) = self.values
      && values.is_none()
    {
      *values = Some(Vec::new());
    }
    Ok(Ignored)
  }
}

struct DestinationItem<'a> {
  values: Option<&'a mut Option<Vec<String>>>,
}

impl<'de> ItemVisitor<'de> for DestinationItem<'_> {
  type Out = ();
  type Error = FieldError;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    let Some(values) = self.values else {
      return Ok(Ignored);
    };
    let value = string_item(item)?;
    if value.len() > MAX_MATCH_DESTINATION_BYTES {
      return Err(FieldError::InputTooLong);
    }
    let values = values.get_or_insert_with(Vec::new);
    if values.len() == MAX_MATCH_DESTINATIONS {
      return Err(FieldError::InputTooLong);
    }
    values.push(value);
    Ok(Ignored)
  }
}

fn string_item(item: BareItemFromInput<'_>) -> Result<String, FieldError> {
  match item {
    BareItemFromInput::String(value) => Ok(value.as_str().to_owned()),
    _ => Err(FieldError::InvalidMember),
  }
}

fn token_item(item: BareItemFromInput<'_>) -> Result<String, FieldError> {
  match item {
    BareItemFromInput::Token(value) => Ok(value.as_str().to_owned()),
    _ => Err(FieldError::InvalidMember),
  }
}
