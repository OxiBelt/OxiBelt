//! Structured WAF access-log records.
//! Records carry rule context without retaining request or response bodies.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::Write as _;

use anyhow::{Context, bail};
use http::header::COOKIE;
use http::{HeaderMap, Uri};
use tracing::warn;

use super::object_model::response_cookie_pairs;
use super::{
  BoundedStringList, CompiledAccessLogField, EvalContext, ObjectRef, TransactionBudget, Value,
  WafLimits, current_unix_ms, eval_member, normalize_cookie_pairs, normalize_header_pairs,
  normalize_query_pairs,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccessLogRecord {
  timestamp_unix_ms: u64,
  fields: Vec<AccessLogFieldValue>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct AccessLogFieldValue {
  name: String,
  value: AccessLogJsonValue,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum AccessLogJsonValue {
  Bool(bool),
  Int(i64),
  String(String),
  Array(Vec<AccessLogJsonValue>),
  Object(Vec<(String, AccessLogJsonValue)>),
  Null,
}

impl AccessLogRecord {
  pub const EVENT: &'static str = "oxibelt.access";

  pub(super) fn from_fields(
    fields: &[CompiledAccessLogField],
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
    scope: &str,
  ) -> anyhow::Result<Self> {
    let values = fields
      .iter()
      .map(|field| {
        let value = field
          .expression
          .eval(ctx, tx)
          .with_context(|| format!("failed to evaluate emit_access_log field {}", field.name))?;
        Ok(AccessLogFieldValue {
          name: field.name.clone(),
          value: AccessLogJsonValue::from_value(value, ctx)?,
        })
      })
      .collect::<anyhow::Result<Vec<_>>>()?;
    let mut values = values;
    if !values.iter().any(|field| field.name == "scope") {
      values.insert(
        0,
        AccessLogFieldValue {
          name: "scope".to_string(),
          value: AccessLogJsonValue::String(scope.to_string()),
        },
      );
    }

    Ok(Self {
      timestamp_unix_ms: current_unix_ms(),
      fields: values,
    })
  }

  pub fn timestamp_unix_ms(&self) -> u64 {
    self.timestamp_unix_ms
  }

  pub fn to_json_line(&self) -> String {
    let mut out = String::new();
    out.push('{');
    let mut first = true;

    push_json_string_field(&mut out, &mut first, "event", Self::EVENT);
    push_json_u64_field(
      &mut out,
      &mut first,
      "timestamp_unix_ms",
      self.timestamp_unix_ms,
    );
    for field in &self.fields {
      push_json_value_field(&mut out, &mut first, &field.name, &field.value);
    }

    out.push('}');
    out
  }

  pub fn emit_stdout(&self) {
    let mut stdout = std::io::stdout().lock();
    if let Err(error) = writeln!(stdout, "{}", self.to_json_line()) {
      warn!(error = %error, "failed to write OxiRule access log to stdout");
    }
  }
}

impl AccessLogJsonValue {
  pub(super) fn from_value(value: Value, ctx: &EvalContext<'_>) -> anyhow::Result<Self> {
    match value {
      Value::Bool(value) => Ok(Self::Bool(value)),
      Value::Int(value) => Ok(Self::Int(value)),
      Value::String(value) => Ok(Self::String(truncate_log_string(
        &value,
        ctx.limits.max_helper_result_bytes,
      ))),
      Value::StringList(list) => Ok(Self::bounded_string_list(list, ctx.limits)),
      Value::BodyScanResult(result) => Ok(Self::Object(vec![
        ("matched".to_string(), Self::Bool(result.matched)),
        (
          "pattern".to_string(),
          result.pattern.map(Self::String).unwrap_or(Self::Null),
        ),
        (
          "offset".to_string(),
          result
            .offset
            .map(|offset| Self::Int(offset as i64))
            .unwrap_or(Self::Null),
        ),
        (
          "match".to_string(),
          result.matched_text.map(Self::String).unwrap_or(Self::Null),
        ),
        ("is_truncated".to_string(), Self::Bool(result.is_truncated)),
      ])),
      Value::Object(object) => Self::from_object(object, ctx),
      Value::Null => Ok(Self::Null),
      Value::Bytes(_) => bail!("emit_access_log fields cannot write raw Bytes"),
    }
  }

  fn bounded_string_list(list: BoundedStringList, limits: &WafLimits) -> Self {
    Self::Object(vec![
      (
        "values".to_string(),
        Self::Array(
          list
            .values
            .into_iter()
            .map(|value| Self::String(truncate_log_string(&value, limits.max_helper_result_bytes)))
            .collect(),
        ),
      ),
      ("is_truncated".to_string(), Self::Bool(list.is_truncated)),
    ])
  }

  fn from_object(object: ObjectRef, ctx: &EvalContext<'_>) -> anyhow::Result<Self> {
    match object {
      ObjectRef::RequestHeaders => Ok(header_map_json(ctx.request.headers, ctx.limits)),
      ObjectRef::ResponseHeaders => Ok(header_map_json(
        ctx.response.context("missing response context")?.headers,
        ctx.limits,
      )),
      ObjectRef::RequestQueryParams => Ok(pair_map_json(
        query_pairs(ctx.request.uri, ctx.limits),
        ctx.limits,
      )),
      ObjectRef::RequestCookies => Ok(pair_map_json(
        cookie_pairs(ctx.request.headers, ctx.limits),
        ctx.limits,
      )),
      ObjectRef::RequestTags => Ok(string_map_json(ctx.request.tags, ctx.limits)),
      ObjectRef::ContextRuleTags => Ok(Self::Array(
        ctx
          .rule_tags
          .iter()
          .take(ctx.limits.max_helper_items)
          .map(|tag| Self::String(truncate_log_string(tag, ctx.limits.max_helper_result_bytes)))
          .collect(),
      )),
      ObjectRef::RequestHttp => object_members_json(
        object,
        &[
          "Version", "Method", "Scheme", "Host", "Path", "Query", "Uri",
        ],
        ctx,
      ),
      ObjectRef::RequestNormalized => {
        object_members_json(object, &["Http", "Headers", "QueryParams", "Cookies"], ctx)
      }
      ObjectRef::RequestNormalizedHttp => {
        object_members_json(object, &["Path", "Query", "Uri"], ctx)
      }
      ObjectRef::RequestNormalizedHeaders => Ok(pair_map_json(
        normalize_header_pairs(ctx.request.headers),
        ctx.limits,
      )),
      ObjectRef::RequestNormalizedQueryParams => Ok(pair_map_json(
        normalize_query_pairs(ctx.request.uri),
        ctx.limits,
      )),
      ObjectRef::RequestNormalizedCookies => Ok(pair_map_json(
        normalize_cookie_pairs(ctx.request.headers),
        ctx.limits,
      )),
      ObjectRef::RequestClient => object_members_json(
        object,
        &[
          "Kind",
          "Ip",
          "Port",
          "SourceAddress",
          "UserAgent",
          "GeoCountry",
          "Asn",
        ],
        ctx,
      ),
      ObjectRef::RequestTransport => object_members_json(
        object,
        &[
          "Network",
          "RemoteIp",
          "RemotePort",
          "IsEncrypted",
          "Tcp",
          "Udp",
        ],
        ctx,
      ),
      ObjectRef::RequestTransportTcp => {
        object_members_json(object, &["Sni", "Alpn", "MaxHop", "Mss", "RttMs"], ctx)
      }
      ObjectRef::RequestTransportUdp => object_members_json(
        object,
        &["DatagramSize", "QuicDetected", "ConnectionId"],
        ctx,
      ),
      ObjectRef::RequestTls | ObjectRef::ResponseTls => object_members_json(
        object,
        &[
          "Enabled",
          "Version",
          "CipherSuite",
          "Sni",
          "Alpn",
          "Fingerprint",
          "FingerprintScheme",
          "ClientCertificatePresent",
        ],
        ctx,
      ),
      ObjectRef::RequestBody | ObjectRef::ResponseBody => {
        object_members_json(object, &["Size", "IsTruncated", "Text"], ctx)
      }
      ObjectRef::StreamPayload => {
        object_members_json(object, &["Size", "IsTruncated", "Text"], ctx)
      }
      ObjectRef::StreamWebSocket => object_members_json(
        object,
        &[
          "Opcode",
          "Fin",
          "IsControl",
          "MessageOpcode",
          "FramePayloadSize",
        ],
        ctx,
      ),
      ObjectRef::StreamWebTransport => {
        object_members_json(object, &["StreamKind", "StreamId", "DatagramSize"], ctx)
      }
      ObjectRef::RequestClientPersonProof => object_members_json(
        object,
        &[
          "State",
          "Method",
          "Difficulty",
          "IssuedAtUnixMs",
          "ExpiresAtUnixMs",
        ],
        ctx,
      ),
      ObjectRef::RequestClientAgent => object_members_json(
        object,
        &["Verified", "Kind", "Provider", "Model", "AuthMethod"],
        ctx,
      ),
      ObjectRef::RequestClientBot => object_members_json(
        object,
        &["Disposition", "Malicious", "Score", "Reason"],
        ctx,
      ),
      ObjectRef::ResponseHttp => object_members_json(object, &["Version", "Status", "Reason"], ctx),
      ObjectRef::ResponseTransport => object_members_json(
        object,
        &[
          "Network",
          "RemoteIp",
          "RemotePort",
          "IsEncrypted",
          "Tcp",
          "Udp",
        ],
        ctx,
      ),
      ObjectRef::ResponseUpstream => object_members_json(
        object,
        &[
          "Name",
          "Pool",
          "Scheme",
          "ConnectTimeMs",
          "FirstByteTimeMs",
          "Error",
        ],
        ctx,
      ),
      ObjectRef::ResponseUpstreamError => object_members_json(object, &["Code", "Message"], ctx),
      ObjectRef::ResponseCookies => Ok(pair_map_json(
        response_cookie_pairs(
          ctx.response.context("missing response context")?.headers,
          ctx.limits.max_helper_items,
        ),
        ctx.limits,
      )),
      ObjectRef::ResponseTags => Ok(string_map_json(
        ctx
          .response
          .context("missing response context")?
          .request
          .tags,
        ctx.limits,
      )),
      ObjectRef::RequestTokenBindings => object_members_json(
        object,
        &[
          "UserAgent",
          "TlsFingerprint",
          "Route",
          "DirectPeerIpNetworkPrefix",
          "TcpMaxHop",
        ],
        ctx,
      ),
      ObjectRef::DynamicPolicy => {
        object_members_json(object, &["Matched", "Action", "Name", "Reason"], ctx)
      }
      ObjectRef::Context | ObjectRef::Request | ObjectRef::Response | ObjectRef::Stream => {
        bail!("top-level OxiRule objects cannot be written as access-log fields")
      }
    }
  }
}

fn object_members_json(
  object: ObjectRef,
  fields: &[&str],
  ctx: &EvalContext<'_>,
) -> anyhow::Result<AccessLogJsonValue> {
  let mut values = Vec::new();
  for field in fields {
    let value = eval_member(Value::Object(object), field, ctx)?;
    values.push((
      field.to_ascii_lowercase(),
      AccessLogJsonValue::from_value(value, ctx)?,
    ));
  }
  Ok(AccessLogJsonValue::Object(values))
}

fn header_map_json(headers: &HeaderMap, limits: &WafLimits) -> AccessLogJsonValue {
  let mut fields: BTreeMap<String, Vec<AccessLogJsonValue>> = BTreeMap::new();
  for (name, value) in headers.iter().take(limits.max_helper_items) {
    let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
    fields
      .entry(name.as_str().to_ascii_lowercase())
      .or_default()
      .push(AccessLogJsonValue::String(truncate_log_string(
        &value,
        limits.max_header_value_bytes,
      )));
  }
  AccessLogJsonValue::Object(collapse_json_map(fields))
}

fn pair_map_json(pairs: Vec<(String, String)>, limits: &WafLimits) -> AccessLogJsonValue {
  let mut fields: BTreeMap<String, Vec<AccessLogJsonValue>> = BTreeMap::new();
  for (name, value) in pairs.into_iter().take(limits.max_helper_items) {
    fields
      .entry(truncate_log_string(&name, limits.max_helper_result_bytes))
      .or_default()
      .push(AccessLogJsonValue::String(truncate_log_string(
        &value,
        limits.max_helper_result_bytes,
      )));
  }
  AccessLogJsonValue::Object(collapse_json_map(fields))
}

fn string_map_json(values: &HashMap<String, String>, limits: &WafLimits) -> AccessLogJsonValue {
  let mut fields = values
    .iter()
    .take(limits.max_helper_items)
    .map(|(name, value)| {
      (
        truncate_log_string(name, limits.max_helper_result_bytes),
        AccessLogJsonValue::String(truncate_log_string(value, limits.max_helper_result_bytes)),
      )
    })
    .collect::<Vec<_>>();
  fields.sort_by(|left, right| left.0.cmp(&right.0));
  AccessLogJsonValue::Object(fields)
}

fn collapse_json_map(
  fields: BTreeMap<String, Vec<AccessLogJsonValue>>,
) -> Vec<(String, AccessLogJsonValue)> {
  fields
    .into_iter()
    .map(|(name, mut values)| {
      let value = if values.len() == 1 {
        values.pop().expect("single value is present")
      } else {
        AccessLogJsonValue::Array(values)
      };
      (name, value)
    })
    .collect()
}

fn query_pairs(uri: &Uri, limits: &WafLimits) -> Vec<(String, String)> {
  url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
    .take(limits.max_helper_items)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect()
}

fn cookie_pairs(headers: &HeaderMap, limits: &WafLimits) -> Vec<(String, String)> {
  headers
    .get_all(COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .take(limits.max_helper_items)
    .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
    .collect()
}

fn truncate_log_string(value: &str, max_bytes: usize) -> String {
  if value.len() <= max_bytes {
    return value.to_string();
  }

  let mut end = 0usize;
  for (index, character) in value.char_indices() {
    let next = index + character.len_utf8();
    if next > max_bytes {
      break;
    }
    end = next;
  }
  value[..end].to_string()
}

fn push_json_field_name(out: &mut String, first: &mut bool, name: &str) {
  if *first {
    *first = false;
  } else {
    out.push(',');
  }
  push_json_string(out, name);
  out.push(':');
}

fn push_json_string_field(out: &mut String, first: &mut bool, name: &str, value: &str) {
  push_json_field_name(out, first, name);
  push_json_string(out, value);
}

fn push_json_value_field(
  out: &mut String,
  first: &mut bool,
  name: &str,
  value: &AccessLogJsonValue,
) {
  push_json_field_name(out, first, name);
  match value {
    AccessLogJsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
    AccessLogJsonValue::Int(value) => {
      let _ = write!(out, "{value}");
    }
    AccessLogJsonValue::String(value) => push_json_string(out, value),
    AccessLogJsonValue::Array(values) => {
      out.push('[');
      let mut first = true;
      for value in values {
        if first {
          first = false;
        } else {
          out.push(',');
        }
        push_json_value(out, value);
      }
      out.push(']');
    }
    AccessLogJsonValue::Object(fields) => {
      out.push('{');
      let mut first = true;
      for (name, value) in fields {
        push_json_value_field(out, &mut first, name, value);
      }
      out.push('}');
    }
    AccessLogJsonValue::Null => out.push_str("null"),
  }
}

fn push_json_value(out: &mut String, value: &AccessLogJsonValue) {
  match value {
    AccessLogJsonValue::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
    AccessLogJsonValue::Int(value) => {
      let _ = write!(out, "{value}");
    }
    AccessLogJsonValue::String(value) => push_json_string(out, value),
    AccessLogJsonValue::Array(values) => {
      out.push('[');
      let mut first = true;
      for value in values {
        if first {
          first = false;
        } else {
          out.push(',');
        }
        push_json_value(out, value);
      }
      out.push(']');
    }
    AccessLogJsonValue::Object(fields) => {
      out.push('{');
      let mut first = true;
      for (name, value) in fields {
        push_json_value_field(out, &mut first, name, value);
      }
      out.push('}');
    }
    AccessLogJsonValue::Null => out.push_str("null"),
  }
}

fn push_json_u64_field(out: &mut String, first: &mut bool, name: &str, value: u64) {
  push_json_field_name(out, first, name);
  let _ = write!(out, "{value}");
}

fn push_json_string(out: &mut String, value: &str) {
  out.push('"');
  for character in value.chars() {
    match character {
      '"' => out.push_str("\\\""),
      '\\' => out.push_str("\\\\"),
      '\u{08}' => out.push_str("\\b"),
      '\u{0c}' => out.push_str("\\f"),
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\t' => out.push_str("\\t"),
      character if character <= '\u{1f}' => {
        let _ = write!(out, "\\u{:04x}", character as u32);
      }
      character => out.push(character),
    }
  }
  out.push('"');
}
