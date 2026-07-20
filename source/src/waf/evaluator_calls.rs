//! OxiRule method-call evaluation.

use super::*;

pub(super) fn optional_string_value(value: &Option<String>) -> Value {
  value
    .as_ref()
    .map(|value| Value::String(value.clone()))
    .unwrap_or(Value::Null)
}

pub(super) fn eval_call(
  value: Value,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  tx: &mut TransactionBudget,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match value {
    Value::String(text) => eval_string_call(&text, method, args, ctx, tx, regex_args),
    Value::Bytes(bytes) => eval_bytes_call(&bytes, method, args),
    Value::StringList(list) => eval_string_list_call(&list, method, args, ctx),
    Value::Object(ObjectRef::ContextRuleTags) => {
      eval_rule_tag_call(ctx.rule_tags, method, args, regex_args)
    }
    Value::Object(ObjectRef::RequestHeaders) => {
      eval_header_call(ctx.request.headers, method, args, ctx, regex_args)
    }
    Value::Object(ObjectRef::RequestNormalizedHeaders) => eval_pair_map_call(
      &normalize_header_pairs(ctx.request.headers),
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::ResponseHeaders) => eval_header_call(
      ctx.response.context("missing response context")?.headers,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestQueryParams) => eval_query_call(ctx, method, args, regex_args),
    Value::Object(ObjectRef::RequestNormalizedQueryParams) => eval_pair_map_call(
      &normalize_query_pairs(ctx.request.uri),
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestCookies) => {
      eval_request_cookie_call(ctx, method, args, regex_args)
    }
    Value::Object(ObjectRef::ResponseCookies) => {
      eval_response_cookie_call(ctx, method, args, regex_args)
    }
    Value::Object(ObjectRef::RequestNormalizedCookies) => eval_pair_map_call(
      &normalize_cookie_pairs(ctx.request.headers),
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestTags) => {
      eval_tag_call(ctx.request.tags, method, args, ctx, regex_args)
    }
    Value::Object(ObjectRef::ResponseTags) => eval_tag_call(
      ctx
        .response
        .context("missing response context")?
        .request
        .tags,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::RequestTokenBindings) => eval_token_binding_call(ctx, method, args),
    Value::Object(ObjectRef::RequestBody) => eval_body_call(
      ctx.request.body,
      BodyTextSlot::Request,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::ResponseBody) => eval_body_call(
      ctx.response.and_then(|response| response.body),
      BodyTextSlot::Response,
      method,
      args,
      ctx,
      regex_args,
    ),
    Value::Object(ObjectRef::StreamPayload) => eval_body_call(
      ctx.stream.map(|stream| stream.payload),
      BodyTextSlot::Stream,
      method,
      args,
      ctx,
      regex_args,
    ),
    _ => bail!("method {method} is not available on {:?}", value),
  }
}

pub(super) fn eval_string_call(
  text: &str,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  _tx: &mut TransactionBudget,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "contains" => Ok(Value::Bool(text.contains(expect_string_arg(args, 0)?))),
    "startsWith" => Ok(Value::Bool(text.starts_with(expect_string_arg(args, 0)?))),
    "endsWith" => Ok(Value::Bool(text.ends_with(expect_string_arg(args, 0)?))),
    "matches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(regex.is_match(text)))
    }
    "lowerAscii" => Ok(Value::String(text.to_ascii_lowercase())),
    "upperAscii" => Ok(Value::String(text.to_ascii_uppercase())),
    "size" => Ok(Value::Int(text.len() as i64)),
    "inCidr" => Ok(Value::Bool(ip_in_cidr(text, expect_string_arg(args, 0)?)?)),
    "containsAny" => Ok(Value::Bool(pattern_set_matches(
      ctx.pattern_sets,
      expect_string_arg(args, 0)?,
      text,
    )?)),
    "matchesAny" => Ok(Value::Bool(pattern_set_matches(
      ctx.pattern_sets,
      expect_string_arg(args, 0)?,
      text,
    )?)),
    "anomalyScore" => Ok(Value::Int(mi_score::anomaly_score(
      text,
      expect_string_arg(args, 0)?,
    )?)),
    "malformedScore" => Ok(Value::Int(mi_score::malformed_score(
      text,
      expect_string_arg(args, 0)?,
    )?)),
    "promptInjectionScore" => Ok(Value::Int(mi_score::prompt_injection_score(text))),
    _ => bail!("unknown String method {method}"),
  }
}

pub(super) fn eval_bytes_call(bytes: &[u8], method: &str, args: &[Value]) -> anyhow::Result<Value> {
  match method {
    "size" => Ok(Value::Int(bytes.len() as i64)),
    "isFormat" | "isBinaryFormat" | "matchesFormat" => Ok(Value::Bool(bytes_match_format(
      bytes,
      expect_string_arg(args, 0)?,
    ))),
    _ => bail!("unknown Bytes method {method}"),
  }
}

pub(super) fn eval_header_call(
  headers: &HeaderMap,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(headers.len() as i64)),
    "has" => Ok(Value::Bool(
      header_name(expect_string_arg(args, 0)?)
        .map(|name| headers.contains_key(name))
        .unwrap_or(false),
    )),
    "get" => Ok(header_single(
      headers,
      header_name(expect_string_arg(args, 0)?)?,
      ctx,
    )?),
    "getAll" => Ok(Value::StringList(bounded_string_list(
      headers
        .get_all(header_name(expect_string_arg(args, 0)?)?)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| truncate_to_bytes(value, ctx.limits.max_header_value_bytes)),
      ctx.limits,
    ))),
    "anyNameMatches" => {
      let regex = header_name_regex_arg(args, 0, regex_args.get(RegexFlavor::HeaderName, 0))?;
      Ok(Value::Bool(
        headers
          .keys()
          .take(ctx.limits.max_helper_items)
          .any(|name| regex.is_match(name.as_str())),
      ))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        headers
          .values()
          .take(ctx.limits.max_helper_items)
          .filter_map(|value| value.to_str().ok())
          .any(|value| value.contains(needle)),
      ))
    }
    "anyValueMatches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(
        headers
          .values()
          .take(ctx.limits.max_helper_items)
          .filter_map(|value| value.to_str().ok())
          .any(|value| regex.is_match(value)),
      ))
    }
    "anyEntryMatches" => {
      let name_regex = header_name_regex_arg(args, 0, regex_args.get(RegexFlavor::HeaderName, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(
        headers
          .iter()
          .take(ctx.limits.max_helper_items)
          .filter_map(|(name, value)| value.to_str().ok().map(|value| (name, value)))
          .any(|(name, value)| name_regex.is_match(name.as_str()) && value_regex.is_match(value)),
      ))
    }
    "allEntriesMatch" => {
      let name_regex = header_name_regex_arg(args, 0, regex_args.get(RegexFlavor::HeaderName, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(
        headers
          .iter()
          .take(ctx.limits.max_helper_items)
          .filter_map(|(name, value)| value.to_str().ok().map(|value| (name, value)))
          .all(|(name, value)| name_regex.is_match(name.as_str()) && value_regex.is_match(value)),
      ))
    }
    _ => bail!("unknown HeaderMap method {method}"),
  }
}

pub(super) fn header_name_regex(pattern: &str) -> anyhow::Result<Regex> {
  Ok(RegexBuilder::new(pattern).case_insensitive(true).build()?)
}

pub(super) fn eval_query_call(
  ctx: &EvalContext<'_>,
  method: &str,
  args: &[Value],
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  let query = ctx.request.uri.query().unwrap_or_default();
  let pairs = url::form_urlencoded::parse(query.as_bytes())
    .take(ctx.limits.max_helper_items)
    .map(|(name, value)| (name.into_owned(), value.into_owned()))
    .collect::<Vec<_>>();
  eval_pair_map_call(&pairs, method, args, ctx, regex_args)
}

pub(super) fn eval_tag_call(
  tags: &HashMap<String, String>,
  method: &str,
  args: &[Value],
  _ctx: &EvalContext<'_>,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(tags.len() as i64)),
    "has" => Ok(Value::Bool(tags.contains_key(expect_string_arg(args, 0)?))),
    "get" => Ok(
      tags
        .get(expect_string_arg(args, 0)?)
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    "anyKeyMatches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(tags.keys().any(|key| regex.is_match(key))))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        tags.values().any(|value| value.contains(needle)),
      ))
    }
    "anyEntryMatches" => {
      let key_regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(tags.iter().any(|(key, value)| {
        key_regex.is_match(key) && value_regex.is_match(value)
      })))
    }
    _ => bail!("unknown TagMap method {method}"),
  }
}

pub(super) fn eval_rule_tag_call(
  tags: &[String],
  method: &str,
  args: &[Value],
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(tags.len() as i64)),
    "has" => {
      let expected = expect_string_arg(args, 0)?;
      Ok(Value::Bool(tags.iter().any(|tag| tag == expected)))
    }
    "anyMatches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(tags.iter().any(|tag| regex.is_match(tag))))
    }
    _ => bail!("unknown RuleTagSet method {method}"),
  }
}

pub(super) fn eval_string_list_member(
  list: BoundedStringList,
  field: &str,
) -> anyhow::Result<Value> {
  match field {
    "Count" => Ok(Value::Int(list.values.len() as i64)),
    "IsTruncated" => Ok(Value::Bool(list.is_truncated)),
    "First" => Ok(
      list
        .values
        .first()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null),
    ),
    _ => bail!("unknown BoundedStringList property {field}"),
  }
}

pub(super) fn eval_body_scan_result_member(
  result: body_scan::BodyScanResult,
  field: &str,
) -> anyhow::Result<Value> {
  match field {
    "Matched" => Ok(Value::Bool(result.matched)),
    "Pattern" => Ok(result.pattern.map(Value::String).unwrap_or(Value::Null)),
    "Offset" => Ok(
      result
        .offset
        .map(|offset| Value::Int(offset as i64))
        .unwrap_or(Value::Null),
    ),
    "Match" => Ok(
      result
        .matched_text
        .map(Value::String)
        .unwrap_or(Value::Null),
    ),
    "IsTruncated" => Ok(Value::Bool(result.is_truncated)),
    _ => bail!("unknown BodyScanResult property {field}"),
  }
}

pub(super) fn eval_string_list_call(
  list: &BoundedStringList,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  match method {
    "contains" => {
      let expected = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        list.values.iter().any(|value| value == expected),
      ))
    }
    "containsAny" => {
      let pattern_set = expect_string_arg(args, 0)?;
      for value in &list.values {
        if pattern_set_matches(ctx.pattern_sets, pattern_set, value)? {
          return Ok(Value::Bool(true));
        }
      }
      Ok(Value::Bool(false))
    }
    "matchesAny" => {
      let pattern_set = expect_string_arg(args, 0)?;
      for value in &list.values {
        if pattern_set_matches(ctx.pattern_sets, pattern_set, value)? {
          return Ok(Value::Bool(true));
        }
      }
      Ok(Value::Bool(false))
    }
    _ => bail!("unknown BoundedStringList method {method}"),
  }
}

pub(super) fn eval_token_binding_call(
  ctx: &EvalContext<'_>,
  method: &str,
  args: &[Value],
) -> anyhow::Result<Value> {
  match method {
    "directPeerIpNetworkPrefix" => {
      let ipv4_prefix_bits = expect_u8_arg(args, 0, 32, "IPv4 prefix bits")?;
      let ipv6_prefix_bits = expect_u8_arg(args, 1, 128, "IPv6 prefix bits")?;
      Ok(Value::String(person_proof::direct_peer_ip_network_prefix(
        ctx.request.peer_addr.ip(),
        ipv4_prefix_bits,
        ipv6_prefix_bits,
      )))
    }
    "tcpMaxHop" => {
      let configured = expect_u8_arg(args, 0, 255, "configured TCP max-hop")?;
      Ok(Value::String(person_proof::tcp_max_hop_binding_value(
        Some(configured),
        ctx.request.tcp_max_hop,
      )))
    }
    _ => bail!("unknown PersonProofTokenBindings method {method}"),
  }
}

pub(super) fn request_token_binding_value(
  input: WafRequestInput<'_>,
  binding: PersonProofTokenBinding,
) -> String {
  match binding {
    PersonProofTokenBinding::UserAgent => input
      .headers
      .get(USER_AGENT)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default()
      .to_string(),
    PersonProofTokenBinding::TlsFingerprint => input
      .tls
      .fingerprint
      .as_deref()
      .unwrap_or("unavailable")
      .to_string(),
    PersonProofTokenBinding::Route => input.route_name.to_string(),
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix => {
      person_proof::direct_peer_ip_network_prefix(
        input.peer_addr.ip(),
        default_person_proof_direct_peer_ipv4_prefix_bits(),
        default_person_proof_direct_peer_ipv6_prefix_bits(),
      )
    }
    PersonProofTokenBinding::TcpMaxHop => {
      person_proof::tcp_max_hop_binding_value(None, input.tcp_max_hop)
    }
  }
}

pub(super) fn eval_pair_map_call(
  pairs: &[(String, String)],
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "count" => Ok(Value::Int(pairs.len() as i64)),
    "has" => {
      let name = expect_string_arg(args, 0)?;
      Ok(Value::Bool(pairs.iter().any(|(key, _)| key == name)))
    }
    "get" => {
      let name = expect_string_arg(args, 0)?;
      single_pair_value(pairs, name, ctx.duplicate_metadata_policy)
    }
    "getAll" => {
      let name = expect_string_arg(args, 0)?;
      Ok(Value::StringList(bounded_string_list(
        pairs
          .iter()
          .filter(|(key, _)| key == name)
          .map(|(_, value)| value.clone()),
        ctx.limits,
      )))
    }
    "anyNameMatches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(
        pairs.iter().any(|(key, _)| regex.is_match(key)),
      ))
    }
    "anyValueContains" => {
      let needle = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        pairs.iter().any(|(_, value)| value.contains(needle)),
      ))
    }
    "anyValueMatches" => {
      let regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      Ok(Value::Bool(
        pairs.iter().any(|(_, value)| regex.is_match(value)),
      ))
    }
    "anyEntryMatches" => {
      let key_regex = regex_arg(args, 0, regex_args.get(RegexFlavor::Default, 0))?;
      let value_regex = regex_arg(args, 1, regex_args.get(RegexFlavor::Default, 1))?;
      Ok(Value::Bool(pairs.iter().any(|(key, value)| {
        key_regex.is_match(key) && value_regex.is_match(value)
      })))
    }
    _ => bail!("unknown bounded map method {method}"),
  }
}
