//! Bounded RFC 9842 header fields and dictionary selection primitives.
//!
//! This module deliberately has no runtime, cache, or configuration dependency.
//! Callers are responsible for retaining dictionary bytes and freshness state.

use std::{borrow::Cow, cmp::Ordering, error::Error, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use sfv::{Parser, StringRef};
use url::Url;
use urlpattern::{UrlPattern, UrlPatternInit, UrlPatternMatchInput};

mod accept_encoding;
mod structured_fields;

use accept_encoding::{coding_quality, parse_accept_encoding};

/// The SHA-256 digest length required by RFC 9842.
pub const SHA256_DIGEST_BYTES: usize = 32;
/// RFC 9842 limits `Dictionary-ID` after structured-field decoding.
pub const MAX_DICTIONARY_ID_CHARS: usize = 1024;
/// Bounds each RFC 9842 structured field before parsing.
pub const MAX_DICTIONARY_FIELD_BYTES: usize = 8 * 1024;
/// Bounds `match` before URL Pattern construction.
pub const MAX_MATCH_PATTERN_BYTES: usize = 4 * 1024;
/// Bounds the number of `match-dest` members retained from one field.
pub const MAX_MATCH_DESTINATIONS: usize = 64;
/// Bounds each retained Fetch destination.
pub const MAX_MATCH_DESTINATION_BYTES: usize = 256;
/// Bounds `Accept-Encoding` before its small, purpose-built parser runs.
pub const MAX_ACCEPT_ENCODING_BYTES: usize = 4 * 1024;

/// A syntactically valid SHA-256 dictionary identifier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DictionaryHash([u8; SHA256_DIGEST_BYTES]);

impl DictionaryHash {
  /// Creates a hash only when its digest has the RFC-required length.
  pub fn from_slice(value: &[u8]) -> Result<Self, FieldError> {
    let value: [u8; SHA256_DIGEST_BYTES] = value
      .try_into()
      .map_err(|_| FieldError::InvalidHashLength)?;
    Ok(Self(value))
  }

  /// Returns the canonical raw digest bytes.
  pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
    &self.0
  }

  /// Returns the canonical Structured Fields byte-sequence representation.
  pub fn to_header_value(self) -> String {
    format!(":{}:", STANDARD.encode(self.0))
  }
}

/// An `Available-Dictionary` request field and its optional paired identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableDictionary {
  /// The single advertised SHA-256 digest.
  pub hash: DictionaryHash,
  /// The server-provided opaque identifier, if the dictionary had one.
  pub id: Option<String>,
}

impl AvailableDictionary {
  /// Produces the canonical request field values.
  pub fn canonical_headers(
    &self,
    encodings: &[DictionaryEncoding],
  ) -> Result<DictionaryRequestHeaders, FieldError> {
    Ok(DictionaryRequestHeaders {
      available_dictionary: self.hash.to_header_value(),
      dictionary_id: self
        .id
        .as_ref()
        .filter(|id| !id.is_empty())
        .map(|id| structured_string(id))
        .transpose()?,
      accept_encoding: dictionary_accept_encoding(Some(self.hash), encodings),
    })
  }
}

/// Canonical fields a client can add when it selected a dictionary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DictionaryRequestHeaders {
  /// Value for `Available-Dictionary`.
  pub available_dictionary: String,
  /// Value for `Dictionary-ID`, when a nonempty identifier was supplied.
  pub dictionary_id: Option<String>,
  /// Value for `Accept-Encoding`, when dictionary encodings are enabled.
  pub accept_encoding: Option<String>,
}

/// The two standardized dictionary-aware content encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DictionaryEncoding {
  /// Dictionary-compressed Brotli.
  Dcb,
  /// Dictionary-compressed Zstandard.
  Dcz,
}

impl DictionaryEncoding {
  /// Lowercase IANA content-coding token.
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Dcb => "dcb",
      Self::Dcz => "dcz",
    }
  }
}

/// A parsed `Use-As-Dictionary` field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UseAsDictionary {
  /// The original URL Pattern string, retained for longest-match selection.
  pub match_pattern: String,
  /// Fetch destinations. An empty list matches every destination.
  pub match_destinations: Vec<String>,
  /// Optional opaque server identifier. The default is the empty string.
  pub id: String,
  /// Declared dictionary representation type. The default is `raw`.
  pub dictionary_type: DictionaryType,
}

impl UseAsDictionary {
  /// Whether this client understands this dictionary's representation.
  pub const fn is_supported(&self) -> bool {
    matches!(self.dictionary_type, DictionaryType::Raw)
  }

  /// Serializes this declaration as a canonical RFC 8941 dictionary value.
  ///
  /// The public type can be constructed without parsing, so serialization
  /// validates all values it places on the wire instead of assuming they were
  /// previously received from a trusted peer.
  pub fn to_header_value(&self) -> Result<String, FieldError> {
    if self.match_pattern.is_empty() || self.match_pattern.len() > MAX_MATCH_PATTERN_BYTES {
      return Err(FieldError::InvalidMatchPattern);
    }
    let mut members = vec![format!(
      "match={}",
      structured_field_string(&self.match_pattern, MAX_MATCH_PATTERN_BYTES)?
    )];
    if !self.match_destinations.is_empty() {
      if self.match_destinations.len() > MAX_MATCH_DESTINATIONS {
        return Err(FieldError::InputTooLong);
      }
      let values = self
        .match_destinations
        .iter()
        .map(|destination| structured_field_string(destination, MAX_MATCH_DESTINATION_BYTES))
        .collect::<Result<Vec<_>, _>>()?;
      members.push(format!("match-dest=({})", values.join(" ")));
    }
    members.push(format!("id={}", structured_string(&self.id)?));
    if !matches!(self.dictionary_type, DictionaryType::Raw) {
      return Err(FieldError::InvalidMember);
    }
    members.push("type=raw".to_owned());
    Ok(members.join(", "))
  }
}

/// The `type` member from `Use-As-Dictionary`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DictionaryType {
  /// The RFC-defined unformatted byte representation.
  Raw,
  /// A syntactically valid token that this implementation does not understand.
  Unknown(String),
}

/// Metadata required to select a dictionary without exposing its bytes.
#[derive(Clone, Debug)]
pub struct StoredDictionary {
  /// The validated digest of the retained dictionary bytes.
  pub hash: DictionaryHash,
  /// HTTPS URL from which the dictionary was fetched.
  pub dictionary_url: Url,
  /// Parsed matching directive received with the dictionary.
  pub use_as_dictionary: UseAsDictionary,
  /// Whether HTTP caching permits this dictionary to be used now.
  pub fresh_or_stale_allowed: bool,
  /// Monotonic fetch sequence; larger values are more recently fetched.
  pub fetched_at: u64,
}

/// An error produced while parsing or applying an RFC 9842 field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldError {
  /// Input exceeded one of this module's explicit bounds.
  InputTooLong,
  /// A field occurred more than once where RFC 9842 requires one value.
  DuplicateField,
  /// Structured Fields syntax was invalid.
  InvalidStructuredField,
  /// A known member had the wrong structured-field type or shape.
  InvalidMember,
  /// The sole advertised byte sequence was not a SHA-256 digest.
  InvalidHashLength,
  /// `Dictionary-ID` exceeded RFC 9842's decoded-character bound.
  DictionaryIdTooLong,
  /// `match` was missing, invalid, or contains URL Pattern regex groups.
  InvalidMatchPattern,
  /// Dictionary transport is only permitted over HTTPS.
  InsecureUrl,
}

impl fmt::Display for FieldError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::InputTooLong => "compression dictionary field exceeds its limit",
      Self::DuplicateField => "ambiguous duplicate compression dictionary field",
      Self::InvalidStructuredField => "invalid compression dictionary structured field",
      Self::InvalidMember => "invalid compression dictionary field member",
      Self::InvalidHashLength => "Available-Dictionary must contain one SHA-256 digest",
      Self::DictionaryIdTooLong => "Dictionary-ID exceeds 1024 characters",
      Self::InvalidMatchPattern => "invalid Use-As-Dictionary match pattern",
      Self::InsecureUrl => "compression dictionary transport requires HTTPS",
    })
  }
}

impl Error for FieldError {}

/// Parses a single `Available-Dictionary` and its optional `Dictionary-ID`.
///
/// An absent pair returns `Ok(None)`. A lone `Dictionary-ID`, multiple field
/// instances, an over-limit value, or any non-byte-sequence hash is rejected.
pub fn parse_available_dictionary(
  headers: &HeaderMap,
) -> Result<Option<AvailableDictionary>, FieldError> {
  let available = single_header(headers, "available-dictionary")?;
  let id = single_header(headers, "dictionary-id")?;
  let Some(available) = available else {
    return if id.is_some() {
      Err(FieldError::InvalidMember)
    } else {
      Ok(None)
    };
  };

  let hash = Parser::new(available)
    .with_version(sfv::Version::Rfc8941)
    .parse_item::<Vec<u8>>()
    .map_err(|_| FieldError::InvalidStructuredField)
    .and_then(|digest| DictionaryHash::from_slice(&digest))?;
  let id = id.map(parse_dictionary_id).transpose()?;
  Ok(Some(AvailableDictionary { hash, id }))
}

/// Parses and validates a `Use-As-Dictionary` field for an HTTPS dictionary URL.
pub fn parse_use_as_dictionary(
  value: &[u8],
  dictionary_url: &Url,
) -> Result<UseAsDictionary, FieldError> {
  if value.len() > MAX_DICTIONARY_FIELD_BYTES {
    return Err(FieldError::InputTooLong);
  }
  if dictionary_url.scheme() != "https" {
    return Err(FieldError::InsecureUrl);
  }
  let parsed = structured_fields::parse_use_as_dictionary_value(value)?;
  validate_match_pattern(&parsed.match_pattern, dictionary_url)?;
  Ok(parsed)
}

/// Parses exactly one `Use-As-Dictionary` response header.
pub fn parse_use_as_dictionary_header(
  headers: &HeaderMap,
  dictionary_url: &Url,
) -> Result<Option<UseAsDictionary>, FieldError> {
  single_header(headers, "use-as-dictionary")?
    .map(|value| parse_use_as_dictionary(value, dictionary_url))
    .transpose()
}

/// Selects the RFC 9842 best dictionary for an HTTPS request.
pub fn select_dictionary<'a>(
  dictionaries: &'a [StoredDictionary],
  request_url: &Url,
  request_destination: Option<&str>,
) -> Option<&'a StoredDictionary> {
  if request_url.scheme() != "https" {
    return None;
  }
  dictionaries
    .iter()
    .filter(|dictionary| dictionary_matches(dictionary, request_url, request_destination))
    .max_by(|left, right| selection_order(left, right, request_destination.is_some()))
}

/// Returns whether the server may use dictionary-aware compression under RFC 9842 section 9.3.3.
pub fn server_dictionary_compression_eligible(
  request_headers: &HeaderMap,
  response_headers: &HeaderMap,
  available_hash: Option<&DictionaryHash>,
) -> bool {
  available_hash.is_some() && fetch_cors_eligible(request_headers, response_headers)
}

/// Selects a dictionary-aware encoding only when the request advertised a hash.
///
/// Explicit `dcb` and `dcz` values win over `*`; an explicit `q=0` disables
/// that encoding even if a wildcard has positive quality.
pub fn negotiate_dictionary_encoding(
  accept_encoding: Option<&str>,
  available_hash: Option<&DictionaryHash>,
  server_supported: &[DictionaryEncoding],
) -> Option<DictionaryEncoding> {
  let _ = available_hash?;
  let parsed = parse_accept_encoding(accept_encoding?)?;
  server_supported
    .iter()
    .copied()
    .find(|encoding| coding_quality(&parsed, encoding.as_str()).is_some_and(|quality| quality > 0))
}

/// Builds a canonical dictionary-only `Accept-Encoding` value when a hash exists.
pub fn dictionary_accept_encoding(
  available_hash: Option<DictionaryHash>,
  encodings: &[DictionaryEncoding],
) -> Option<String> {
  available_hash?;
  let mut output = Vec::with_capacity(encodings.len());
  for encoding in encodings {
    if !output.contains(&encoding.as_str()) {
      output.push(encoding.as_str());
    }
  }
  (!output.is_empty()).then(|| output.join(", "))
}

fn single_header<'a>(
  headers: &'a HeaderMap,
  name: &'static str,
) -> Result<Option<&'a [u8]>, FieldError> {
  let mut values = headers.get_all(name).iter();
  let Some(value) = values.next() else {
    return Ok(None);
  };
  if values.next().is_some() || value.len() > MAX_DICTIONARY_FIELD_BYTES {
    return Err(if value.len() > MAX_DICTIONARY_FIELD_BYTES {
      FieldError::InputTooLong
    } else {
      FieldError::DuplicateField
    });
  }
  Ok(Some(value.as_bytes()))
}

fn parse_dictionary_id(value: &[u8]) -> Result<String, FieldError> {
  if value.len() > MAX_DICTIONARY_FIELD_BYTES {
    return Err(FieldError::InputTooLong);
  }
  let parsed = Parser::new(value)
    .with_version(sfv::Version::Rfc8941)
    .parse_item::<Cow<'_, StringRef>>()
    .map_err(|_| FieldError::InvalidStructuredField)?;
  let id = parsed.as_str().to_owned();
  if id.chars().count() > MAX_DICTIONARY_ID_CHARS {
    return Err(FieldError::DictionaryIdTooLong);
  }
  Ok(id)
}

fn structured_string(value: &str) -> Result<String, FieldError> {
  structured_field_string(value, MAX_DICTIONARY_ID_CHARS).map_err(|error| match error {
    FieldError::InputTooLong => FieldError::DictionaryIdTooLong,
    _ => error,
  })
}

fn structured_field_string(value: &str, maximum_bytes: usize) -> Result<String, FieldError> {
  if value.len() > maximum_bytes {
    return Err(FieldError::InputTooLong);
  }
  if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
    return Err(FieldError::InvalidMember);
  }
  let mut output = String::with_capacity(value.len() + 2);
  output.push('"');
  for character in value.chars() {
    if matches!(character, '"' | '\\') {
      output.push('\\');
    }
    output.push(character);
  }
  output.push('"');
  Ok(output)
}

/// URLPattern normalizes `(.*)` to a wildcard; reject source regex groups
/// before that normalization while allowing escaped literal parentheses.
pub(crate) fn has_regex_group_syntax(pattern: &str) -> bool {
  let mut escaped = false;
  for byte in pattern.bytes() {
    if escaped {
      escaped = false;
      continue;
    }
    if byte == b'\\' {
      escaped = true;
    } else if byte == b'(' {
      return true;
    }
  }
  false
}

fn validate_match_pattern(pattern: &str, dictionary_url: &Url) -> Result<(), FieldError> {
  if pattern.is_empty()
    || pattern.len() > MAX_MATCH_PATTERN_BYTES
    || has_regex_group_syntax(pattern)
  {
    return Err(FieldError::InvalidMatchPattern);
  }
  let init =
    UrlPatternInit::parse_constructor_string::<regex::Regex>(pattern, Some(dictionary_url.clone()))
      .map_err(|_| FieldError::InvalidMatchPattern)?;
  let pattern = UrlPattern::<regex::Regex>::parse(init, Default::default())
    .map_err(|_| FieldError::InvalidMatchPattern)?;
  if pattern.has_regexp_groups() {
    return Err(FieldError::InvalidMatchPattern);
  }
  Ok(())
}

fn dictionary_matches(
  dictionary: &StoredDictionary,
  request_url: &Url,
  request_destination: Option<&str>,
) -> bool {
  if !dictionary.fresh_or_stale_allowed
    || !dictionary.use_as_dictionary.is_supported()
    || dictionary.dictionary_url.scheme() != "https"
    || !same_origin(&dictionary.dictionary_url, request_url)
    || !destination_matches(
      &dictionary.use_as_dictionary.match_destinations,
      request_destination,
    )
  {
    return false;
  }
  let Ok(init) = UrlPatternInit::parse_constructor_string::<regex::Regex>(
    &dictionary.use_as_dictionary.match_pattern,
    Some(dictionary.dictionary_url.clone()),
  ) else {
    return false;
  };
  let Ok(pattern) = UrlPattern::<regex::Regex>::parse(init, Default::default()) else {
    return false;
  };
  !pattern.has_regexp_groups()
    && pattern
      .test(UrlPatternMatchInput::Url(request_url.clone()))
      .unwrap_or(false)
}

fn same_origin(left: &Url, right: &Url) -> bool {
  left.scheme() == "https"
    && right.scheme() == "https"
    && left.scheme() == right.scheme()
    && left.host_str() == right.host_str()
    && left.port_or_known_default() == right.port_or_known_default()
}

fn destination_matches(destinations: &[String], request_destination: Option<&str>) -> bool {
  match request_destination {
    Some(destination) => {
      destinations.is_empty() || destinations.iter().any(|value| value == destination)
    }
    None => true,
  }
}

fn selection_order(
  left: &StoredDictionary,
  right: &StoredDictionary,
  destinations_supported: bool,
) -> Ordering {
  let left_destination =
    destinations_supported && !left.use_as_dictionary.match_destinations.is_empty();
  let right_destination =
    destinations_supported && !right.use_as_dictionary.match_destinations.is_empty();
  left_destination
    .cmp(&right_destination)
    .then_with(|| {
      left
        .use_as_dictionary
        .match_pattern
        .len()
        .cmp(&right.use_as_dictionary.match_pattern.len())
    })
    .then_with(|| left.fetched_at.cmp(&right.fetched_at))
}

fn fetch_cors_eligible(request: &HeaderMap, response: &HeaderMap) -> bool {
  let Ok(site) = optional_text_header(request, "sec-fetch-site") else {
    return false;
  };
  let Some(site) = site else {
    return true;
  };
  if site == "same-origin" {
    return true;
  }
  let Ok(mode) = optional_text_header(request, "sec-fetch-mode") else {
    return false;
  };
  let Some(mode) = mode else {
    return true;
  };
  if matches!(mode.as_str(), "navigate" | "same-origin") {
    return true;
  }
  if mode != "cors" {
    return false;
  }
  let (Ok(origin), Ok(allow_origin)) = (
    optional_text_header(request, "origin"),
    optional_text_header(response, "access-control-allow-origin"),
  ) else {
    return false;
  };
  matches!((origin, allow_origin), (Some(origin), Some(allow_origin)) if allow_origin == "*" || allow_origin == origin)
}

fn optional_text_header(
  headers: &HeaderMap,
  name: &'static str,
) -> Result<Option<String>, FieldError> {
  let Some(value) = single_header(headers, name)? else {
    return Ok(None);
  };
  let header_value = HeaderValue::from_bytes(value).map_err(|_| FieldError::InvalidMember)?;
  let value = header_value
    .to_str()
    .map_err(|_| FieldError::InvalidMember)?;
  Ok(Some(value.to_ascii_lowercase()))
}

#[cfg(test)]
#[path = "fields/tests.rs"]
mod tests;
