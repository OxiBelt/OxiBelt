//! Object-model helpers exposed to OxiRule expressions.
//! Callers receive normalized read-only views of request and response metadata.

use anyhow::{Context, bail};
use http::HeaderMap;
use http::header::{COOKIE, SET_COOKIE};

use super::{
  CachedRegexArgs, EvalContext, ObjectRef, Value, WafTransportNetwork, eval_pair_map_call,
};

pub(super) fn eval_response_transport_member(
  ctx: &EvalContext<'_>,
  field: &str,
) -> anyhow::Result<Value> {
  let response = ctx.response.context("missing response context")?;
  match field {
    "Network" => Ok(Value::String(
      response.request.transport_network.as_str().to_string(),
    )),
    "RemoteIp" => Ok(Value::String(response.request.peer_addr.ip().to_string())),
    "RemotePort" => Ok(Value::Int(response.request.peer_addr.port().into())),
    "IsEncrypted" => Ok(Value::Bool(response.request.tls.enabled)),
    "Tcp" => {
      if response.request.transport_network == WafTransportNetwork::Tcp {
        Ok(Value::Object(ObjectRef::RequestTransportTcp))
      } else {
        Ok(Value::Null)
      }
    }
    "Udp" => {
      if response.request.transport_network == WafTransportNetwork::Udp {
        Ok(Value::Object(ObjectRef::RequestTransportUdp))
      } else {
        Ok(Value::Null)
      }
    }
    _ => bail!("unknown WAF object property ResponseTransport.{field}"),
  }
}

pub(super) fn eval_request_tls_member(ctx: &EvalContext<'_>, field: &str) -> anyhow::Result<Value> {
  match field {
    "Enabled" => Ok(Value::Bool(ctx.request.tls.enabled)),
    "Version" => Ok(optional_string_value(&ctx.request.tls.version)),
    "CipherSuite" => Ok(optional_string_value(&ctx.request.tls.cipher_suite)),
    "Sni" => Ok(optional_string_value(&ctx.request.tls.sni)),
    "Alpn" => Ok(optional_string_value(&ctx.request.tls.alpn)),
    "Fingerprint" => Ok(optional_string_value(&ctx.request.tls.fingerprint)),
    "FingerprintScheme" => Ok(optional_string_value(&ctx.request.tls.fingerprint_scheme)),
    "ClientCertificatePresent" => Ok(Value::Bool(ctx.request.tls.client_certificate.is_some())),
    _ => bail!("unknown WAF object property RequestTls.{field}"),
  }
}

pub(super) fn eval_request_cookie_call(
  ctx: &EvalContext<'_>,
  method: &str,
  args: &[Value],
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  let pairs = request_cookie_pairs(ctx.request.headers, ctx.limits.max_helper_items);
  eval_pair_map_call(&pairs, method, args, ctx, regex_args)
}

pub(super) fn eval_response_cookie_call(
  ctx: &EvalContext<'_>,
  method: &str,
  args: &[Value],
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  let pairs = response_cookie_pairs(
    ctx.response.context("missing response context")?.headers,
    ctx.limits.max_helper_items,
  );
  eval_pair_map_call(&pairs, method, args, ctx, regex_args)
}

fn optional_string_value(value: &Option<String>) -> Value {
  value
    .as_ref()
    .map(|value| Value::String(value.clone()))
    .unwrap_or(Value::Null)
}

fn request_cookie_pairs(headers: &HeaderMap, max_items: usize) -> Vec<(String, String)> {
  headers
    .get_all(COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .take(max_items)
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect()
}

pub(super) fn response_cookie_pairs(
  headers: &HeaderMap,
  max_items: usize,
) -> Vec<(String, String)> {
  headers
    .get_all(SET_COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .filter_map(|value| value.split(';').next())
    .filter_map(|part| part.trim().split_once('='))
    .take(max_items)
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect()
}
