//! Request-side HTTP Message Signatures profile from
//! draft-ietf-webbotauth-httpsig-protocol-00 and RFC 9421.
// sfv visitor implementations constrain associated output/error types more
// tightly than the public visitor trait's return-position impl Trait bounds.
#![allow(refining_impl_trait_internal)]

use std::{
  convert::Infallible,
  time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use http::Request;
use sfv::visitor::{ItemVisitor, ParameterVisitor};
use sfv::{BareItem, BareItemFromInput, KeyRef, Parser};
use url::Url;

pub(super) const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CANDIDATES: usize = 8;
const MAX_COMPONENTS: usize = 32;

mod structured;
#[cfg(test)]
mod tests;

use structured::{
  Dict, Item, Member, bare_string, dictionary, field, member_value, param, put_param,
  serialize_dictionary, sf_inner, sf_item, trim_ows,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryKind {
  Directory,
  JwksUri,
  Cimd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryReference {
  pub url: Url,
  pub kind: DiscoveryKind,
}

#[derive(Clone, Debug)]
pub struct Candidate {
  pub reference: DiscoveryReference,
  pub keyid: String,
  pub alg: Option<String>,
  pub signature: Vec<u8>,
  pub signature_base: Vec<u8>,
  pub covers_content_digest: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ParsedSignatures {
  pub absent: bool,
  pub candidates: Vec<Candidate>,
  pub had_invalid: bool,
}

fn reference(member: &Member) -> Option<DiscoveryReference> {
  let Member::Item(item) = member else {
    return None;
  };
  let url = Url::parse(bare_string(&item.bare)?).ok()?;
  if url.scheme() != "https"
    || url.host_str().is_none()
    || !url.username().is_empty()
    || url.password().is_some()
    || url.fragment().is_some()
  {
    return None;
  }
  let kind = match param(&item.params, "type") {
    None => DiscoveryKind::Directory,
    Some(BareItem::Token(value)) if value.as_str() == "directory" => DiscoveryKind::Directory,
    Some(BareItem::Token(value)) if value.as_str() == "jwks_uri" => DiscoveryKind::JwksUri,
    Some(BareItem::Token(value)) if value.as_str() == "cimd" => DiscoveryKind::Cimd,
    _ => return None,
  };
  if url.query().is_some() || (kind == DiscoveryKind::Directory && url.path() != "/") {
    return None;
  }
  Some(DiscoveryReference { url, kind })
}

fn authority<B>(request: &Request<B>) -> Option<String> {
  if let Some(authority) = request.uri().authority() {
    return Some(authority.as_str().to_owned());
  }
  let hosts: Vec<_> = request
    .headers()
    .get_all(http::header::HOST)
    .iter()
    .collect();
  if hosts.len() != 1 {
    return None;
  }
  Some(hosts[0].to_str().ok()?.trim().to_owned())
}
fn derived<B>(request: &Request<B>, scheme: &str, item: &Item) -> Option<String> {
  let name = bare_string(&item.bare)?;
  let authority = authority(request)?;
  let path = request.uri().path();
  let query = request.uri().query();
  let target = format!(
    "{scheme}://{authority}{}",
    request
      .uri()
      .path_and_query()
      .map(|v| v.as_str())
      .unwrap_or("/")
  );
  if !item.params.is_empty() && name != "@query-param" {
    return None;
  }
  match name {
    "@method" => Some(request.method().as_str().to_owned()),
    "@authority" => Some(authority),
    "@scheme" => Some(scheme.to_ascii_lowercase()),
    "@target-uri" => Some(target),
    "@path" => Some(if path.is_empty() {
      "/".into()
    } else {
      path.into()
    }),
    "@query" => Some(query.map(|q| format!("?{q}")).unwrap_or_else(|| "?".into())),
    "@request-target" => Some(request.uri().to_string()),
    "@query-param" => {
      if item.params.len() != 1 {
        return None;
      }
      let key = bare_string(param(&item.params, "name")?)?;
      let mut found = None;
      for (name, value) in url::form_urlencoded::parse(query?.as_bytes()) {
        if encode_query_component(&name) == key {
          if found.is_some() {
            return None;
          }
          found = Some(encode_query_component(&value));
        }
      }
      found
    }
    _ => None,
  }
}
fn encode_query_component(value: &str) -> String {
  const HEX: &[u8; 16] = b"0123456789ABCDEF";
  let mut out = String::with_capacity(value.len());
  for byte in value.bytes() {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
      out.push(char::from(byte));
    } else {
      out.push('%');
      out.push(char::from(HEX[(byte >> 4) as usize]));
      out.push(char::from(HEX[(byte & 15) as usize]));
    }
  }
  out
}
fn component<B>(
  request: &Request<B>,
  scheme: &str,
  item: &Item,
  agent: &Dict,
  signatures: &Dict,
  inputs: &Dict,
) -> Option<String> {
  let name = bare_string(&item.bare)?;
  if name.starts_with('@') {
    return derived(request, scheme, item);
  }
  if name != name.to_ascii_lowercase()
    || http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
  {
    return None;
  }
  let mut key = None;
  let mut sf = false;
  let mut bs = false;
  for (name, value) in &item.params {
    match (name.as_str(), value) {
      ("key", BareItem::String(value)) => key = Some(value.as_str()),
      ("sf", BareItem::Boolean(true)) => sf = true,
      ("bs", BareItem::Boolean(true)) => bs = true,
      _ => return None,
    }
  }
  if key.is_some() && (sf || bs) || sf && bs {
    return None;
  }
  if let Some(key) = key {
    if let Some(dict) = match name {
      "signature-agent" => Some(agent),
      "signature" => Some(signatures),
      "signature-input" => Some(inputs),
      _ => None,
    } {
      return member_value(dict.get(key)?).ok();
    }
    if !matches!(name, "content-digest" | "priority") {
      return None;
    }
    let raw = field(request.headers(), name).ok()??;
    return member_value(dictionary(&raw).ok()?.get(key)?).ok();
  }
  if bs {
    let mut values = Vec::new();
    let mut total = 0usize;
    for value in request.headers().get_all(name) {
      let bytes = trim_ows(value.as_bytes());
      total = total.saturating_add(bytes.len());
      if total > MAX_HEADER_BYTES {
        return None;
      }
      values.push(format!(
        ":{}:",
        base64::engine::general_purpose::STANDARD.encode(bytes)
      ));
    }
    return (!values.is_empty()).then(|| values.join(", "));
  }
  let raw = field(request.headers(), name).ok()??;
  if sf {
    if !matches!(
      name,
      "signature-agent" | "signature" | "signature-input" | "content-digest" | "priority"
    ) {
      return None;
    }
    return serialize_dictionary(&raw);
  }
  let raw = std::str::from_utf8(&raw).ok()?;
  Some(raw.to_owned())
}

/// Parse bounded request headers into independent candidate signatures.
pub fn parse_request<B>(
  request: &Request<B>,
  scheme: &str,
  max_lifetime_secs: u64,
  skew_secs: u64,
) -> ParsedSignatures {
  let headers = request.headers();
  let any = ["signature", "signature-input", "signature-agent"]
    .iter()
    .any(|n| headers.contains_key(*n));
  if !any {
    return ParsedSignatures {
      absent: true,
      ..Default::default()
    };
  }
  let mut result = ParsedSignatures {
    absent: false,
    ..Default::default()
  };
  let fields = [
    field(headers, "signature"),
    field(headers, "signature-input"),
    field(headers, "signature-agent"),
  ];
  let [
    Ok(Some(signatures_raw)),
    Ok(Some(inputs_raw)),
    Ok(Some(agent_raw)),
  ] = fields
  else {
    result.had_invalid = true;
    return result;
  };
  if signatures_raw
    .len()
    .saturating_add(inputs_raw.len())
    .saturating_add(agent_raw.len())
    > MAX_HEADER_BYTES
  {
    result.had_invalid = true;
    return result;
  }
  let (Ok(signatures), Ok(inputs)) = (dictionary(&signatures_raw), dictionary(&inputs_raw)) else {
    result.had_invalid = true;
    return result;
  };
  let legacy = agent_raw
    .iter()
    .copied()
    .find(|byte| !matches!(byte, b' ' | b'\t'))
    == Some(b'"');
  let agents = if legacy {
    Parser::new(&agent_raw)
      .with_version(sfv::Version::Rfc8941)
      .parse_item_with_visitor(LegacyReader)
      .ok()
  } else {
    None
  };
  let agents_dict = if legacy {
    Dict::new()
  } else {
    match dictionary(&agent_raw) {
      Ok(v) => v,
      Err(_) => {
        result.had_invalid = true;
        return result;
      }
    }
  };
  if legacy && agents.is_none() {
    result.had_invalid = true;
    return result;
  }
  if inputs.len() > MAX_CANDIDATES
    || signatures.len() > MAX_CANDIDATES
    || agents_dict.len() > MAX_CANDIDATES
  {
    result.had_invalid = true;
    return result;
  }
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_or(0, |d| d.as_secs());
  for (label, input) in &inputs {
    let Some(Member::Inner(covered, params)) = Some(input) else {
      result.had_invalid = true;
      continue;
    };
    if covered.is_empty() || covered.len() > MAX_COMPONENTS {
      result.had_invalid = true;
      continue;
    }
    let Some(created) = param(params, "created").and_then(|v| {
      if let BareItem::Integer(n) = v {
        u64::try_from(i64::from(*n)).ok()
      } else {
        None
      }
    }) else {
      result.had_invalid = true;
      continue;
    };
    let Some(expires) = param(params, "expires").and_then(|v| {
      if let BareItem::Integer(n) = v {
        u64::try_from(i64::from(*n)).ok()
      } else {
        None
      }
    }) else {
      result.had_invalid = true;
      continue;
    };
    let Some(keyid) = param(params, "keyid").and_then(bare_string) else {
      result.had_invalid = true;
      continue;
    };
    if param(params, "tag").and_then(bare_string) != Some("web-bot-auth")
      || keyid.is_empty()
      || (param(params, "alg").is_some() && param(params, "alg").and_then(bare_string).is_none())
      || expires <= created
      || expires - created > max_lifetime_secs
      || created > now.saturating_add(skew_secs)
      || expires.saturating_add(skew_secs) < now
    {
      result.had_invalid = true;
      continue;
    }
    let Some(Member::Item(sig)) = signatures.get(label) else {
      result.had_invalid = true;
      continue;
    };
    let BareItem::ByteSequence(signature) = &sig.bare else {
      result.had_invalid = true;
      continue;
    };
    if !sig.params.is_empty() || signature.is_empty() {
      result.had_invalid = true;
      continue;
    }
    let reference = if legacy {
      agents.as_ref().and_then(reference)
    } else {
      agents_dict.get(label).and_then(reference)
    };
    let Some(reference) = reference else {
      result.had_invalid = true;
      continue;
    };
    let owns_agent = covered.iter().any(|item| {
      bare_string(&item.bare) == Some("signature-agent")
        && if legacy {
          item.params.is_empty()
        } else {
          item.params.len() == 1 && param(&item.params, "key").and_then(bare_string) == Some(label)
        }
    });
    let binds_authority = covered
      .iter()
      .any(|item| matches!(bare_string(&item.bare), Some("@authority" | "@target-uri")));
    if !owns_agent || !binds_authority {
      result.had_invalid = true;
      continue;
    }
    // The draft requires an outer signature covering another signature to also
    // bind its input and every component named by that input.
    let chain_valid = covered.iter().all(|item| {
      if bare_string(&item.bare) != Some("signature") {
        return true;
      }
      let Some(inner_label) = param(&item.params, "key").and_then(bare_string) else {
        return false;
      };
      let Some(Member::Inner(inner_components, _)) = inputs.get(inner_label) else {
        return false;
      };
      covered.iter().any(|other| {
        bare_string(&other.bare) == Some("signature-input")
          && param(&other.params, "key").and_then(bare_string) == Some(inner_label)
      }) && inner_components.iter().all(|inner| {
        sf_item(inner).ok().is_some_and(|identity| {
          covered
            .iter()
            .any(|outer| sf_item(outer).ok().as_ref() == Some(&identity))
        })
      })
    });
    if !chain_valid {
      result.had_invalid = true;
      continue;
    }
    let mut base = String::new();
    let mut valid = true;
    for item in covered {
      let (Ok(identifier), Some(value)) = (
        sf_item(item),
        component(request, scheme, item, &agents_dict, &signatures, &inputs),
      ) else {
        valid = false;
        break;
      };
      base.push_str(&identifier);
      base.push_str(": ");
      base.push_str(&value);
      base.push('\n');
      if base.len() > MAX_HEADER_BYTES {
        valid = false;
        break;
      }
    }
    if !valid {
      result.had_invalid = true;
      continue;
    }
    let Ok(params_value) = sf_inner(covered, params) else {
      result.had_invalid = true;
      continue;
    };
    base.push_str("\"@signature-params\": ");
    base.push_str(&params_value);
    if base.len() > MAX_HEADER_BYTES {
      result.had_invalid = true;
      continue;
    }
    result.candidates.push(Candidate {
      reference,
      keyid: keyid.into(),
      alg: param(params, "alg")
        .and_then(bare_string)
        .map(str::to_owned),
      signature: signature.clone(),
      signature_base: base.into_bytes(),
      covers_content_digest: covered
        .iter()
        .any(|item| bare_string(&item.bare) == Some("content-digest")),
    });
  }
  result
}

struct LegacyReader;
struct LegacyParams {
  bare: BareItem,
  params: Vec<(String, BareItem)>,
}
impl<'de> ItemVisitor<'de> for LegacyReader {
  type Out = Member;
  type Error = Infallible;
  fn bare_item(
    self,
    bare: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = Member, Error = Self::Error>, Self::Error> {
    Ok(LegacyParams {
      bare: bare.into(),
      params: Vec::new(),
    })
  }
}
impl<'de> ParameterVisitor<'de> for LegacyParams {
  type Out = Member;
  type Error = Infallible;
  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    put_param(&mut self.params, key, value);
    Ok(())
  }
  fn finish(self) -> Result<Member, Self::Error> {
    Ok(Member::Item(Item {
      bare: self.bare,
      params: self.params,
    }))
  }
}
