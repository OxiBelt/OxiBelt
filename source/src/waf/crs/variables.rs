//! CRS variable parser and selector validation.
//! Invalid selectors fail during rule loading rather than during request handling.

use anyhow::bail;

use super::super::{HybridRegex, WafLimits};
use super::compatibility::SUPPORTED_VARIABLES;
use super::model::CrsTransaction;
use super::syntax::unquote_selector;
use super::utils::{header_values, select_pairs};

#[derive(Clone)]
pub(super) enum CrsSelector {
  Any,
  Exact(String),
  Regex(HybridRegex),
}

impl CrsSelector {
  fn parse(selector: Option<&str>, limits: &WafLimits) -> anyhow::Result<Self> {
    let Some(selector) = selector else {
      return Ok(Self::Any);
    };
    if selector.starts_with('/') && selector.ends_with('/') && selector.len() > 2 {
      Ok(Self::Regex(HybridRegex::compile(
        &selector[1..selector.len() - 1],
        false,
        limits,
      )?))
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
  TxRegex(HybridRegex),
  MatchedVar,
}

impl CrsVariable {
  pub(super) fn parse(raw: &str, limits: &WafLimits) -> anyhow::Result<Self> {
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
      "REQUEST_HEADERS" => Ok(Self::RequestHeaders(CrsSelector::parse(selector, limits)?)),
      "REQUEST_HEADERS_NAMES" => Ok(Self::RequestHeadersNames),
      "ARGS" => Ok(Self::Args),
      "ARGS_GET" | "QUERY_STRING" => Ok(Self::ArgsGet),
      "REQUEST_COOKIES" => Ok(Self::RequestCookies(selector.map(unquote_selector))),
      "REQUEST_BODY" => Ok(Self::RequestBody),
      "RESPONSE_STATUS" => Ok(Self::ResponseStatus),
      "RESPONSE_PROTOCOL" => Ok(Self::ResponseProtocol),
      "RESPONSE_HEADERS" => Ok(Self::ResponseHeaders(CrsSelector::parse(selector, limits)?)),
      "RESPONSE_HEADERS_NAMES" => Ok(Self::ResponseHeadersNames),
      "RESPONSE_BODY" => Ok(Self::ResponseBody),
      "MATCHED_VAR" => Ok(Self::MatchedVar),
      "TX" => {
        let Some(selector) = selector else {
          bail!("TX variable requires a selector")
        };
        if selector.starts_with('/') && selector.ends_with('/') && selector.len() > 2 {
          Ok(Self::TxRegex(HybridRegex::compile(
            &selector[1..selector.len() - 1],
            false,
            limits,
          )?))
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

  pub(super) fn visit_values<F>(
    &self,
    tx: &mut CrsTransaction<'_>,
    mut visit: F,
  ) -> anyhow::Result<bool>
  where
    F: FnMut(String, &mut CrsTransaction<'_>) -> anyhow::Result<bool>,
  {
    match self {
      Self::RequestUri | Self::RequestUriRaw => visit(tx.request_uri(), tx),
      Self::RequestFilename => visit(tx.request_path(), tx),
      Self::RequestBasename => {
        let Some(value) = tx.request.uri.path().rsplit('/').next() else {
          return Ok(false);
        };
        visit(value.to_string(), tx)
      }
      Self::RequestMethod => visit(tx.request.method.as_str().to_string(), tx),
      Self::RequestProtocol => visit(tx.request_protocol(), tx),
      Self::RequestHeaders(selector) => {
        for value in header_values(tx.request.headers, selector)? {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::RequestHeadersNames => {
        for value in tx.request_header_names() {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::Args => {
        let mut pairs = tx.query_pairs();
        pairs.extend(tx.form_body_pairs());
        for (_, value) in pairs {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::ArgsGet => {
        for (_, value) in tx.query_pairs() {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::RequestCookies(selector) => {
        let pairs = tx.cookie_pairs();
        for value in select_pairs(pairs, selector.as_deref()) {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::RequestBody => {
        let Some(value) = tx.request_body_text() else {
          return Ok(false);
        };
        visit(value, tx)
      }
      Self::ResponseStatus => {
        let value = tx
          .response
          .as_ref()
          .map(|view| view.status.as_u16().to_string())
          .unwrap_or_default();
        visit(value, tx)
      }
      Self::ResponseProtocol => visit(tx.response_protocol(), tx),
      Self::ResponseHeaders(selector) => {
        let Some(headers) = tx.response.as_ref().map(|view| view.headers) else {
          return Ok(false);
        };
        for value in header_values(headers, selector)? {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::ResponseHeadersNames => {
        for value in tx.response_header_names() {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::ResponseBody => {
        let Some(value) = tx.response_body_text() else {
          return Ok(false);
        };
        visit(value, tx)
      }
      Self::Tx(name) => {
        let Some(value) = tx.tx_value(name) else {
          return Ok(false);
        };
        visit(value.into_owned(), tx)
      }
      Self::TxRegex(regex) => {
        for value in tx.tx_values_matching(regex)? {
          if visit(value, tx)? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::MatchedVar => {
        let Some(value) = tx.matched_var.clone() else {
          return Ok(false);
        };
        visit(value, tx)
      }
    }
  }
}
