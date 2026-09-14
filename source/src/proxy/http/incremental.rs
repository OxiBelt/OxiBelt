//! RFC 10036 message-local intent and fail-closed forwarding decisions.

use std::convert::Infallible;

use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
use sfv::visitor::{Ignored, ItemVisitor, ParameterVisitor, parameter_visitor_with};
use sfv::{BareItemFromInput, Parser};

use super::body::ProxyBody;

#[derive(Clone, Copy, Debug)]
pub(crate) struct IncrementalIntent;

/// Records a preceding body inspection so a later mutation cannot claim streaming.
#[derive(Clone, Copy, Debug)]
pub(super) struct BodyWasBuffered;

/// A local terminal response replaced the upstream exchange. Its diagnostic
/// body must not be replaced by the cancelled upload's streaming error.
#[derive(Clone, Copy, Debug)]
pub(super) struct LocalTerminalResponse;

struct BooleanVisitor;

impl<'de> ItemVisitor<'de> for BooleanVisitor {
  type Out = bool;
  type Error = Infallible;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = bool>, Infallible> {
    Ok(parameter_visitor_with(Ignored, move |_| {
      Ok(matches!(item, BareItemFromInput::Boolean(true)))
    }))
  }
}

pub(crate) fn requested(headers: &HeaderMap) -> bool {
  let mut values = headers.get_all("incremental").iter();
  let Some(value) = values.next() else {
    return false;
  };
  // Combining multiple field lines produces a List, never a valid Item.
  if values.next().is_some() {
    return false;
  }
  Parser::new(value.as_bytes())
    .parse_item_with_visitor(BooleanVisitor)
    .unwrap_or(false)
}

pub(crate) fn request_marked<B>(request: &Request<B>) -> bool {
  request.extensions().get::<IncrementalIntent>().is_some() || requested(request.headers())
}

pub(super) fn latch_request<B>(request: &mut Request<B>) {
  if requested(request.headers()) {
    request.extensions_mut().insert(IncrementalIntent);
  }
}

pub(crate) fn response_marked<B>(response: &Response<B>) -> bool {
  response.extensions().get::<IncrementalIntent>().is_some() || requested(response.headers())
}

pub(crate) fn refused(version: Version) -> Response<ProxyBody> {
  let mut response = super::response::text_response(
    StatusCode::NOT_IMPLEMENTED,
    "incremental forwarding is incompatible with the effective body policy",
  );
  response.headers_mut().insert(
    "proxy-status",
    HeaderValue::from_static("oxibelt; error=incremental_refused"),
  );
  response.headers_mut().insert(
    http::header::CACHE_CONTROL,
    HeaderValue::from_static("no-store"),
  );
  if matches!(version, Version::HTTP_10 | Version::HTTP_11) {
    // The rejected upload has deliberately not been consumed.
    response
      .headers_mut()
      .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
  }
  response
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn strict_item_and_ignored_parameters() {
    for value in [
      "?1",
      " ?1 ",
      "?1;x",
      "?1;a=42;b=\"x\";c=?0",
      "?1;a=:YQ==:",
      "?1;a=@123;b=%\"hello%20world\"",
    ] {
      let mut headers = HeaderMap::new();
      headers.insert("Incremental", HeaderValue::from_str(value).unwrap());
      assert!(requested(&headers), "{value}");
    }
    for value in [
      "?0",
      "true",
      "1",
      "\"?1\"",
      "?1, ?1",
      "(?1)",
      "?1;",
      "?1;x=",
      "?1;x=?2",
      "?1 trailing",
      "?1;x=\"unfinished",
      "",
    ] {
      let mut headers = HeaderMap::new();
      headers.insert("incremental", HeaderValue::from_str(value).unwrap());
      assert!(!requested(&headers), "{value}");
    }
  }

  #[test]
  fn duplicate_lines_do_not_activate_and_intent_survives_mutation() {
    let mut request = Request::new(());
    request
      .headers_mut()
      .append("incremental", HeaderValue::from_static("?1"));
    request
      .headers_mut()
      .append("incremental", HeaderValue::from_static("?0"));
    assert!(!request_marked(&request));
    request
      .headers_mut()
      .insert("incremental", HeaderValue::from_static("?1"));
    latch_request(&mut request);
    request.headers_mut().remove("incremental");
    assert!(request_marked(&request));
  }

  #[test]
  fn refusals_are_not_cacheable_and_close_only_http1() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
      let response = refused(version);
      assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
      assert_eq!(
        response.headers()["proxy-status"],
        "oxibelt; error=incremental_refused"
      );
      assert_eq!(response.headers()["cache-control"], "no-store");
      assert_eq!(
        response.headers().contains_key("connection"),
        version == Version::HTTP_11
      );
    }
  }
}
