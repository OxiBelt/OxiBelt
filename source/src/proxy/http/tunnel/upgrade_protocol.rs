//! HTTP Upgrade protocol classification and authorization.

use http::{HeaderMap, header::UPGRADE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UpgradeMode {
  WebSocket,
  Generic,
}

pub(super) fn authorize(
  headers: &HeaderMap,
  websocket_enabled: bool,
  generic_enabled: bool,
  route_generic_enabled: bool,
) -> Option<UpgradeMode> {
  if is_exclusively_websocket(headers) {
    return websocket_enabled.then_some(UpgradeMode::WebSocket);
  }

  (generic_enabled && route_generic_enabled).then_some(UpgradeMode::Generic)
}

pub(super) fn is_websocket_selection(headers: &HeaderMap) -> bool {
  is_exclusively_websocket(headers)
}

fn is_exclusively_websocket(headers: &HeaderMap) -> bool {
  let mut found = false;
  for value in headers.get_all(UPGRADE) {
    let Ok(value) = value.to_str() else {
      return false;
    };
    for token in value.split(',') {
      if !token.trim().eq_ignore_ascii_case("websocket") {
        return false;
      }
      found = true;
    }
  }
  found
}

#[cfg(test)]
mod tests {
  use http::HeaderValue;

  use super::*;

  fn headers(values: &[HeaderValue]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for value in values {
      headers.append(UPGRADE, value.clone());
    }
    headers
  }

  #[test]
  fn exact_websocket_offers_use_websocket_mode() {
    let exact = headers(&[HeaderValue::from_static(" WebSocket\t")]);
    assert_eq!(
      authorize(&exact, true, false, false),
      Some(UpgradeMode::WebSocket)
    );

    let repeated = headers(&[
      HeaderValue::from_static("websocket"),
      HeaderValue::from_static("WEBSOCKET, websocket"),
    ]);
    assert_eq!(
      authorize(&repeated, true, false, false),
      Some(UpgradeMode::WebSocket)
    );
  }

  #[test]
  fn exact_websocket_offer_does_not_fall_back_to_generic_mode() {
    let exact = headers(&[HeaderValue::from_static("websocket")]);
    assert_eq!(authorize(&exact, false, true, true), None);
  }

  #[test]
  fn mixed_and_alternate_offers_require_both_generic_gates() {
    for offer in [
      headers(&[HeaderValue::from_static("h2c, websocket")]),
      headers(&[
        HeaderValue::from_static("h2c"),
        HeaderValue::from_static("websocket"),
      ]),
      headers(&[HeaderValue::from_static("h2c")]),
    ] {
      assert_eq!(authorize(&offer, true, false, false), None);
      assert_eq!(authorize(&offer, true, true, false), None);
      assert_eq!(authorize(&offer, true, false, true), None);
      assert_eq!(
        authorize(&offer, true, true, true),
        Some(UpgradeMode::Generic)
      );
    }
  }

  #[test]
  fn missing_and_malformed_offers_remain_explicitly_gated_generic_upgrades() {
    let missing = HeaderMap::new();
    let empty = headers(&[HeaderValue::from_static("")]);
    let non_utf8 = headers(&[HeaderValue::from_bytes(&[0x80]).unwrap()]);

    for offer in [missing, empty, non_utf8] {
      assert_eq!(authorize(&offer, true, false, false), None);
      assert_eq!(
        authorize(&offer, true, true, true),
        Some(UpgradeMode::Generic)
      );
    }
  }

  #[test]
  fn websocket_response_selection_must_be_unambiguous() {
    assert!(is_websocket_selection(&headers(&[
      HeaderValue::from_static("websocket",)
    ])));
    assert!(is_websocket_selection(&headers(&[
      HeaderValue::from_static("websocket"),
      HeaderValue::from_static("WebSocket"),
    ])));

    for selection in [
      HeaderMap::new(),
      headers(&[HeaderValue::from_static("")]),
      headers(&[HeaderValue::from_static("h2c")]),
      headers(&[HeaderValue::from_static("websocket, h2c")]),
      headers(&[HeaderValue::from_bytes(&[0x80]).unwrap()]),
    ] {
      assert!(!is_websocket_selection(&selection));
    }
  }
}
