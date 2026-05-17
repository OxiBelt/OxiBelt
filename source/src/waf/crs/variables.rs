use anyhow::bail;
use regex::Regex;

use super::super::WafResponseInput;
use super::compatibility::SUPPORTED_VARIABLES;
use super::model::CrsTransaction;
use super::syntax::unquote_selector;
use super::utils::{header_values, select_pairs};

#[derive(Clone)]
pub(super) enum CrsSelector {
  Any,
  Exact(String),
  Regex(Regex),
}

impl CrsSelector {
  fn parse(selector: Option<&str>) -> anyhow::Result<Self> {
    let Some(selector) = selector else {
      return Ok(Self::Any);
    };
    if selector.starts_with('/') && selector.ends_with('/') && selector.len() > 2 {
      Ok(Self::Regex(Regex::new(&selector[1..selector.len() - 1])?))
    } else {
      Ok(Self::Exact(unquote_selector(selector)))
    }
  }
}

#[derive(Clone)]
pub(super) enum CrsVariable {
  RequestUri,
  RequestUriRaw,
  RequestFilename,
  RequestBasename,
  RequestMethod,
  RequestProtocol,
  RequestHeaders(CrsSelector),
  RequestHeadersNames,
  Args,
  ArgsGet,
  RequestCookies(Option<String>),
  RequestBody,
  ResponseStatus,
  ResponseProtocol,
  ResponseHeaders(CrsSelector),
  ResponseHeadersNames,
  ResponseBody,
  Tx(String),
  TxRegex(Regex),
  MatchedVar,
}

impl CrsVariable {
  pub(super) fn parse(raw: &str) -> anyhow::Result<Self> {
    let (name, selector) = raw
      .split_once(':')
      .map(|(name, selector)| (name.trim(), Some(selector.trim())))
      .unwrap_or((raw.trim(), None));
    let upper = name.to_ascii_uppercase();
    if !SUPPORTED_VARIABLES.contains(&upper.as_str()) {
      bail!("unsupported CRS variable {raw}");
    }
    match upper.as_str() {
      "REQUEST_URI" => Ok(Self::RequestUri),
      "REQUEST_URI_RAW" => Ok(Self::RequestUriRaw),
      "REQUEST_FILENAME" => Ok(Self::RequestFilename),
      "REQUEST_BASENAME" => Ok(Self::RequestBasename),
      "REQUEST_METHOD" => Ok(Self::RequestMethod),
      "REQUEST_PROTOCOL" => Ok(Self::RequestProtocol),
      "REQUEST_HEADERS" => Ok(Self::RequestHeaders(CrsSelector::parse(selector)?)),
      "REQUEST_HEADERS_NAMES" => Ok(Self::RequestHeadersNames),
      "ARGS" => Ok(Self::Args),
      "ARGS_GET" | "QUERY_STRING" => Ok(Self::ArgsGet),
      "REQUEST_COOKIES" => Ok(Self::RequestCookies(selector.map(unquote_selector))),
      "REQUEST_BODY" => Ok(Self::RequestBody),
      "RESPONSE_STATUS" => Ok(Self::ResponseStatus),
      "RESPONSE_PROTOCOL" => Ok(Self::ResponseProtocol),
      "RESPONSE_HEADERS" => Ok(Self::ResponseHeaders(CrsSelector::parse(selector)?)),
      "RESPONSE_HEADERS_NAMES" => Ok(Self::ResponseHeadersNames),
      "RESPONSE_BODY" => Ok(Self::ResponseBody),
      "MATCHED_VAR" => Ok(Self::MatchedVar),
      "TX" => {
        let Some(selector) = selector else {
          bail!("TX variable requires a selector")
        };
        if selector.starts_with('/') && selector.ends_with('/') && selector.len() > 2 {
          Ok(Self::TxRegex(Regex::new(&selector[1..selector.len() - 1])?))
        } else {
          Ok(Self::Tx(unquote_selector(selector).to_ascii_lowercase()))
        }
      }
      _ => bail!("CRS compatibility matrix lists unimplemented variable {raw}"),
    }
  }

  pub(super) fn requires_request_body(&self) -> bool {
    matches!(self, Self::Args | Self::RequestBody)
  }

  pub(super) fn requires_response_body(&self) -> bool {
    matches!(self, Self::ResponseBody)
  }

  pub(super) fn values(
    &self,
    tx: &mut CrsTransaction<'_>,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<Vec<String>> {
    match self {
      Self::RequestUri | Self::RequestUriRaw => Ok(vec![tx.request_uri()]),
      Self::RequestFilename => Ok(vec![tx.request_path()]),
      Self::RequestBasename => Ok(
        tx.request
          .uri
          .path()
          .rsplit('/')
          .next()
          .map(|value| vec![value.to_string()])
          .unwrap_or_default(),
      ),
      Self::RequestMethod => Ok(vec![tx.request.method.as_str().to_string()]),
      Self::RequestProtocol => Ok(vec![tx.request_protocol()]),
      Self::RequestHeaders(selector) => Ok(header_values(tx.request.headers, selector)),
      Self::RequestHeadersNames => Ok(tx.request_header_names()),
      Self::Args => {
        let mut pairs = tx.query_pairs();
        pairs.extend(tx.form_body_pairs());
        Ok(pairs.into_iter().map(|(_, value)| value).collect())
      }
      Self::ArgsGet => Ok(
        tx.query_pairs()
          .into_iter()
          .map(|(_, value)| value)
          .collect(),
      ),
      Self::RequestCookies(selector) => {
        let pairs = tx.cookie_pairs();
        Ok(select_pairs(pairs, selector.as_deref()))
      }
      Self::RequestBody => Ok(tx.request_body_text().into_iter().collect()),
      Self::ResponseStatus => Ok(vec![
        response
          .map(|input| input.status.as_u16().to_string())
          .or_else(|| {
            tx.response
              .as_ref()
              .map(|view| view.status.as_u16().to_string())
          })
          .unwrap_or_default(),
      ]),
      Self::ResponseProtocol => Ok(vec![tx.response_protocol()]),
      Self::ResponseHeaders(selector) => {
        let headers = response
          .map(|input| input.headers)
          .or_else(|| tx.response.as_ref().map(|view| view.headers));
        Ok(
          headers
            .map(|headers| header_values(headers, selector))
            .unwrap_or_default(),
        )
      }
      Self::ResponseHeadersNames => Ok(tx.response_header_names()),
      Self::ResponseBody => Ok(tx.response_body_text().into_iter().collect()),
      Self::Tx(name) => Ok(tx.tx.get(name).cloned().into_iter().collect()),
      Self::TxRegex(regex) => Ok(
        tx.tx
          .iter()
          .filter(|(name, _)| regex.is_match(name))
          .map(|(_, value)| value.clone())
          .collect(),
      ),
      Self::MatchedVar => Ok(tx.matched_var.clone().into_iter().collect()),
    }
  }
}
