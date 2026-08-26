//! Bounded evaluator values, object references, and cached regex arguments.

use super::*;

#[derive(Debug, Clone)]
pub(super) enum Value {
  Bool(bool),
  Int(i64),
  String(String),
  Bytes(Vec<u8>),
  StringList(BoundedStringList),
  BodyScanResult(body_scan::BodyScanResult),
  Null,
  Object(ObjectRef),
}

#[derive(Debug, Clone)]
pub(super) struct BoundedStringList {
  pub(super) values: Vec<String>,
  pub(super) is_truncated: bool,
}

impl Value {
  pub(super) fn as_bool(&self) -> anyhow::Result<bool> {
    match self {
      Self::Bool(value) => Ok(*value),
      _ => bail!("expected Bool, got {:?}", self),
    }
  }

  pub(super) fn as_string(&self) -> anyhow::Result<&str> {
    match self {
      Self::String(value) => Ok(value),
      _ => bail!("expected String, got {:?}", self),
    }
  }

  pub(super) fn is_null(&self) -> bool {
    matches!(self, Self::Null)
  }
}

#[derive(Clone, Copy, Default)]
pub(super) struct CachedRegexArgs<'a> {
  default: [Option<&'a HybridRegex>; 2],
  header_name: [Option<&'a HybridRegex>; 2],
}

impl<'a> CachedRegexArgs<'a> {
  pub(super) fn for_verified_args(
    args: &[VerifiedExpression],
    cache: Option<&'a CompiledRegexCache>,
  ) -> Self {
    let Some(cache) = cache else {
      return Self::default();
    };
    let mut regex_args = Self::default();
    for (index, arg) in args.iter().enumerate().take(regex_args.default.len()) {
      if let Some(pattern) = expression::verified_string_literal(arg) {
        regex_args.default[index] = cache.get(RegexFlavor::Default, pattern);
        regex_args.header_name[index] = cache.get(RegexFlavor::HeaderName, pattern);
      }
    }
    regex_args
  }

  pub(super) fn get(self, flavor: RegexFlavor, index: usize) -> Option<&'a HybridRegex> {
    match flavor {
      RegexFlavor::Default => self.default.get(index).copied().flatten(),
      RegexFlavor::HeaderName => self.header_name.get(index).copied().flatten(),
    }
  }
}

pub(super) enum RegexSource<'a> {
  Borrowed(&'a HybridRegex),
  Owned(Regex),
}

impl RegexSource<'_> {
  pub(super) fn is_match(&self, value: &str) -> anyhow::Result<bool> {
    match self {
      Self::Borrowed(regex) => regex.is_match(value),
      Self::Owned(regex) => Ok(regex.is_match(value)),
    }
  }
}

pub(super) fn regex_arg<'a>(
  args: &[Value],
  index: usize,
  cached: Option<&'a HybridRegex>,
) -> anyhow::Result<RegexSource<'a>> {
  if let Some(regex) = cached {
    return Ok(RegexSource::Borrowed(regex));
  }
  Ok(RegexSource::Owned(Regex::new(expect_string_arg(
    args, index,
  )?)?))
}

pub(super) fn header_name_regex_arg<'a>(
  args: &[Value],
  index: usize,
  cached: Option<&'a HybridRegex>,
) -> anyhow::Result<RegexSource<'a>> {
  if let Some(regex) = cached {
    return Ok(RegexSource::Borrowed(regex));
  }
  Ok(RegexSource::Owned(header_name_regex(expect_string_arg(
    args, index,
  )?)?))
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ObjectRef {
  Context,
  ContextRuleTags,
  Request,
  RequestNormalized,
  RequestNormalizedHttp,
  RequestNormalizedHeaders,
  RequestNormalizedQueryParams,
  RequestNormalizedCookies,
  RequestClient,
  RequestClientPersonProof,
  RequestClientAgent,
  RequestClientBot,
  RequestTransport,
  RequestTransportTcp,
  RequestTransportUdp,
  RequestHttp,
  RequestHeaders,
  RequestQueryParams,
  RequestCookies,
  RequestBody,
  RequestTags,
  RequestTls,
  RequestTokenBindings,
  DynamicPolicy,
  Response,
  ResponseHttp,
  ResponseHeaders,
  ResponseCookies,
  ResponseBody,
  ResponseTags,
  ResponseTls,
  ResponseTransport,
  ResponseUpstream,
  ResponseUpstreamError,
  Stream,
  StreamPayload,
  StreamWebSocket,
  StreamWebTransport,
}

pub(super) fn eval_ident(name: &str, ctx: &EvalContext<'_>) -> anyhow::Result<Value> {
  if let Some((_, value)) = ctx
    .locals
    .iter()
    .find(|(local_name, _)| *local_name == name)
  {
    return Ok((*value).clone());
  }
  match name {
    "Context" => Ok(Value::Object(ObjectRef::Context)),
    "Request" => Ok(Value::Object(ObjectRef::Request)),
    "DynamicPolicy" => Ok(Value::Object(ObjectRef::DynamicPolicy)),
    "Response" if ctx.phase == WafPhase::Response => Ok(Value::Object(ObjectRef::Response)),
    "Response" => bail!("Response is unavailable in this phase"),
    "Stream" if ctx.phase == WafPhase::Stream => Ok(Value::Object(ObjectRef::Stream)),
    "Stream" => bail!("Stream is available only in stream phase"),
    _ => bail!("unknown identifier {name}"),
  }
}
