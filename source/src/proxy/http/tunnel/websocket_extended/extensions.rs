//! Validate selected WebSocket extensions against the client offer.

pub(super) fn extension_matches_offer(selected: &str, offer: &str) -> bool {
  let selected_name = selected.split(';').next().unwrap_or("").trim();
  let offer_name = offer.split(';').next().unwrap_or("").trim();
  if !selected_name.eq_ignore_ascii_case("permessage-deflate") {
    return selected == offer;
  }
  if !offer_name.eq_ignore_ascii_case("permessage-deflate") {
    return false;
  }
  let Some(selected_params) = parse_permessage_deflate(selected, false) else {
    return false;
  };
  let Some(offer_params) = parse_permessage_deflate(offer, true) else {
    return false;
  };
  // RFC 7692 allows the server to choose different parameters from the offer.
  // client_max_window_bits is the one response parameter requiring an offer.
  if selected_params.client_max_window_bits.is_some()
    && offer_params.client_max_window_bits.is_none()
  {
    return false;
  }
  if let (Some(Some(max)), Some(Some(chosen))) = (
    offer_params.server_max_window_bits,
    selected_params.server_max_window_bits,
  ) && chosen > max
  {
    return false;
  }
  true
}

#[derive(Default)]
struct DeflateParameters {
  client_max_window_bits: Option<Option<u8>>,
  server_max_window_bits: Option<Option<u8>>,
}

fn parse_permessage_deflate(value: &str, is_offer: bool) -> Option<DeflateParameters> {
  let mut parts = value.split(';');
  if !parts
    .next()?
    .trim()
    .eq_ignore_ascii_case("permessage-deflate")
  {
    return None;
  }
  let mut params = DeflateParameters::default();
  let mut seen = std::collections::HashSet::new();
  for part in parts {
    let (name, number) = match part.trim().split_once('=') {
      Some((name, number)) => (name.trim(), Some(number.trim())),
      None => (part.trim(), None),
    };
    let name = name.to_ascii_lowercase();
    if !seen.insert(name.clone()) {
      return None;
    }
    match name.as_str() {
      "client_no_context_takeover" | "server_no_context_takeover" if number.is_none() => {}
      "client_max_window_bits" | "server_max_window_bits" => {
        let parsed = number.and_then(|number| {
          if number.len() > 2 || number.starts_with('0') {
            return None;
          }
          number
            .parse::<u8>()
            .ok()
            .filter(|bits| (8..=15).contains(bits))
        });
        if number.is_some() && parsed.is_none() {
          return None;
        }
        if !is_offer && parsed.is_none() {
          return None;
        }
        if name == "server_max_window_bits" && parsed.is_none() {
          return None;
        }
        if name == "client_max_window_bits" {
          params.client_max_window_bits = Some(parsed);
        } else {
          params.server_max_window_bits = Some(parsed);
        }
      }
      _ => return None,
    }
  }
  Some(params)
}
