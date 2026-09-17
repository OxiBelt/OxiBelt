//! Bounded draft-15 handshake fields, independent of route or Admin authorization.

use std::io;

use http::{HeaderMap, Method, Request, Version};
use sfv::visitor::{
  DictionaryVisitor, EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ParameterVisitor,
  parameter_visitor_with,
};
use sfv::{BareItemFromInput, KeyRef, Parser};

use super::codec::invalid;

/// Initial receive credit advertised by the peer: uni, bidi-local, bidi-remote.
pub(crate) fn peer_stream_limits(headers: &HeaderMap) -> io::Result<Option<[u64; 3]>> {
  let mut joined = Vec::new();
  let mut found = false;
  for value in headers.get_all("webtransport-init") {
    if joined.len().saturating_add(value.len()).saturating_add(2) > 4096 {
      return Err(invalid("WebTransport-Init exceeds 4096 bytes"));
    }
    if found {
      joined.extend_from_slice(b", ");
    }
    found = true;
    joined.extend_from_slice(value.as_bytes());
  }
  if !found {
    return Ok(None);
  }
  let mut result = [Some(0); 3];
  Parser::new(&joined)
    .with_version(sfv::Version::Rfc8941)
    .parse_dictionary_with_visitor(Credits(&mut result))
    .map_err(|_| invalid("invalid WebTransport-Init dictionary"))?;
  Ok(Some([
    result[0].ok_or_else(|| invalid("invalid unidirectional credit"))?,
    result[1].ok_or_else(|| invalid("invalid bidi-local credit"))?,
    result[2].ok_or_else(|| invalid("invalid bidi-remote credit"))?,
  ]))
}

/// RFC 9297 section 3.2 forbids representation framing on a Capsule Protocol leg.
pub(crate) fn validate_capsule_headers(headers: &HeaderMap) -> io::Result<()> {
  if [
    http::header::CONTENT_LENGTH,
    http::header::CONTENT_TYPE,
    http::header::TRANSFER_ENCODING,
  ]
  .iter()
  .any(|name| headers.contains_key(name))
  {
    return Err(invalid(
      "representation framing is forbidden on a capsule stream",
    ));
  }
  // WebTransport itself implies Capsule Protocol use. If explicitly supplied,
  // its Structured Fields boolean must be true, and single-valued.
  let mut values = headers.get_all("capsule-protocol").iter();
  if let Some(value) = values.next() {
    if values.next().is_some() {
      return Err(invalid("duplicate Capsule-Protocol"));
    }
    let enabled = Parser::new(value.as_bytes())
      .with_version(sfv::Version::Rfc8941)
      .parse_item_with_visitor(CapsuleFlag)
      .map_err(|_| invalid("invalid Capsule-Protocol"))?;
    if !enabled {
      return Err(invalid("Capsule-Protocol must be true"));
    }
  }
  Ok(())
}

pub(crate) fn validate_request<B>(request: &Request<B>) -> io::Result<()> {
  if request.version() != Version::HTTP_2
    || request.method() != Method::CONNECT
    || request.uri().scheme_str() != Some("https")
    || request.uri().authority().is_none()
    || request.uri().path().is_empty()
    || request
      .extensions()
      .get::<hyper::ext::Protocol>()
      .map(|protocol| protocol.as_str())
      != Some("webtransport")
  {
    return Err(invalid("invalid HTTP/2 WebTransport extended CONNECT"));
  }
  validate_capsule_headers(request.headers())?;
  peer_stream_limits(request.headers())?;
  let mut origins = request.headers().get_all(http::header::ORIGIN).iter();
  if let Some(origin) = origins.next()
    && (origins.next().is_some() || origin.to_str().is_err())
  {
    return Err(invalid("invalid or duplicate WebTransport Origin"));
  }
  Ok(())
}

struct Credits<'a>(&'a mut [Option<u64>; 3]);
struct Credit<'a>(Option<&'a mut Option<u64>>);
impl<'de> DictionaryVisitor<'de> for Credits<'_> {
  type Out = ();
  type Error = std::convert::Infallible;
  fn entry(&mut self, key: &'de KeyRef) -> Result<impl EntryVisitor<'de>, Self::Error> {
    let index = match key.as_str() {
      "u" => Some(0),
      "bl" => Some(1),
      "br" => Some(2),
      _ => None,
    };
    Ok(Credit(index.map(|index| &mut self.0[index])))
  }
  fn finish(self) -> Result<(), Self::Error> {
    Ok(())
  }
}
impl<'de> EntryVisitor<'de> for Credit<'_> {
  type Error = std::convert::Infallible;
  fn item(self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(self)
  }
  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Self::Error> {
    if let Some(value) = self.0 {
      *value = None;
    }
    Ok(Ignored)
  }
}
impl<'de> ItemVisitor<'de> for Credit<'_> {
  type Out = ();
  type Error = std::convert::Infallible;
  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    if let Some(value) = self.0 {
      *value = match item {
        BareItemFromInput::Integer(integer) => u64::try_from(i64::from(integer)).ok(),
        _ => None,
      };
    }
    Ok(Ignored)
  }
}
struct CapsuleFlag;
impl<'de> ItemVisitor<'de> for CapsuleFlag {
  type Out = bool;
  type Error = std::convert::Infallible;
  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = bool>, Self::Error> {
    let enabled = matches!(item, BareItemFromInput::Boolean(true));
    Ok(parameter_visitor_with(Ignored, move |_| Ok(enabled)))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::HeaderValue;

  #[test]
  fn credit_dictionary_requires_nonnegative_integer_known_members() {
    for value in ["u=-1", "u=?1", "br=(1)", "bl=1.5", "u=", "u=1,"] {
      let mut headers = HeaderMap::new();
      headers.insert("webtransport-init", HeaderValue::from_str(value).unwrap());
      assert!(peer_stream_limits(&headers).is_err(), "{value}");
    }
    let mut headers = HeaderMap::new();
    headers.insert(
      "webtransport-init",
      HeaderValue::from_static("u=12;extra=token, unknown=(1 2)"),
    );
    headers.append(
      "webtransport-init",
      HeaderValue::from_static("bl=34, br=56, u=78"),
    );
    assert_eq!(peer_stream_limits(&headers).unwrap(), Some([78, 34, 56]));
    assert_eq!(peer_stream_limits(&HeaderMap::new()).unwrap(), None);
  }

  #[test]
  fn representation_headers_and_ambiguous_capsule_flags_are_rejected() {
    for name in ["content-length", "content-type", "transfer-encoding"] {
      let mut headers = HeaderMap::new();
      headers.insert(name, HeaderValue::from_static("0"));
      assert!(validate_capsule_headers(&headers).is_err());
    }
    let mut headers = HeaderMap::new();
    headers.insert("capsule-protocol", HeaderValue::from_static("?1;ignored=1"));
    assert!(validate_capsule_headers(&headers).is_ok());
    headers.append("capsule-protocol", HeaderValue::from_static("?1"));
    assert!(validate_capsule_headers(&headers).is_err());
  }

  #[test]
  fn origin_cannot_be_hidden_by_duplicate_or_non_ascii_header_values() {
    let mut request = Request::builder()
      .method(Method::CONNECT)
      .version(Version::HTTP_2)
      .uri("https://example.test/session")
      .body(())
      .unwrap();
    request
      .extensions_mut()
      .insert(hyper::ext::Protocol::from_static("webtransport"));
    assert!(validate_request(&request).is_ok());
    request
      .headers_mut()
      .append("origin", HeaderValue::from_static("https://example.test"));
    assert!(validate_request(&request).is_ok());
    request
      .headers_mut()
      .append("origin", HeaderValue::from_static("https://other.test"));
    assert!(validate_request(&request).is_err());
    request
      .headers_mut()
      .insert("origin", HeaderValue::from_bytes(b"\xff").unwrap());
    assert!(validate_request(&request).is_err());
  }
}
