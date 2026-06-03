//! Body-related OxiRule function evaluation.
//! Body access is mediated through cached slots so size limits remain enforceable.

use anyhow::{anyhow, bail};

use super::binary_format::bytes_match_format;
use super::body_cache::BodyTextSlot;
use super::{
  CachedRegexArgs, EvalContext, RegexFlavor, Value, WafBodyInput, body_scan, expect_string_arg,
  malicious_intelligence_score,
};

pub(super) fn eval_body_call(
  body: Option<WafBodyInput<'_>>,
  text_slot: BodyTextSlot,
  method: &str,
  args: &[Value],
  ctx: &EvalContext<'_>,
  regex_args: CachedRegexArgs<'_>,
) -> anyhow::Result<Value> {
  match method {
    "isFormat" | "isBinaryFormat" | "matchesFormat" => {
      let format = expect_string_arg(args, 0)?;
      Ok(Value::Bool(
        body
          .map(|body| bytes_match_format(body.bytes, format))
          .unwrap_or(false),
      ))
    }
    "contains" => Ok(Value::Bool(if let Some(body) = body {
      body_scan::contains_text_maybe_offloaded(
        ctx.body_text_caches.text_arc(text_slot, body),
        expect_string_arg(args, 0)?,
      )
    } else {
      false
    })),
    "matches" => {
      let Some(body) = body else {
        return Ok(Value::Bool(false));
      };
      let text = ctx.body_text_caches.text_arc(text_slot, body);
      if let Some(regex) = regex_args.get(RegexFlavor::Default, 0) {
        Ok(Value::Bool(body_scan::matches_regex_text_maybe_offloaded(
          text, regex,
        )))
      } else {
        Ok(Value::Bool(body_scan::matches_text_maybe_offloaded(
          text,
          expect_string_arg(args, 0)?,
        )?))
      }
    }
    "containsAny" | "matchesAny" => {
      let pattern_set_name = expect_string_arg(args, 0)?;
      let Some(body) = body else {
        return Ok(Value::Bool(false));
      };
      let pattern_set = ctx
        .pattern_sets
        .get(pattern_set_name)
        .ok_or_else(|| anyhow!("unknown WAF pattern set {pattern_set_name}"))?;
      Ok(Value::Bool(
        ctx
          .body_text_caches
          .scan_pattern_set(text_slot, body, pattern_set_name, pattern_set)
          .matched,
      ))
    }
    "scan" => {
      let pattern_set_name = expect_string_arg(args, 0)?;
      let Some(body) = body else {
        return Ok(Value::BodyScanResult(body_scan::BodyScanResult::no_match(
          false,
        )));
      };
      let pattern_set = ctx
        .pattern_sets
        .get(pattern_set_name)
        .ok_or_else(|| anyhow!("unknown WAF pattern set {pattern_set_name}"))?;
      Ok(Value::BodyScanResult(
        ctx
          .body_text_caches
          .scan_pattern_set(text_slot, body, pattern_set_name, pattern_set),
      ))
    }
    "anomalyScore" => {
      let profile = expect_string_arg(args, 0)?;
      let text = body.map(|body| ctx.body_text_caches.text(text_slot, body));
      Ok(Value::Int(
        malicious_intelligence_score::body_anomaly_score(body, text, profile)?,
      ))
    }
    "malformedScore" => {
      let profile = expect_string_arg(args, 0)?;
      let text = body.map(|body| ctx.body_text_caches.text(text_slot, body));
      Ok(Value::Int(
        malicious_intelligence_score::body_malformed_score(body, text, profile)?,
      ))
    }
    "promptInjectionScore" => {
      let text = body.map(|body| ctx.body_text_caches.text(text_slot, body));
      Ok(Value::Int(
        malicious_intelligence_score::body_prompt_injection_score(body, text),
      ))
    }
    _ => bail!("unknown BodyView method {method}"),
  }
}

pub(super) fn body_content_method(method: &str) -> bool {
  matches!(
    method,
    "isFormat"
      | "isBinaryFormat"
      | "matchesFormat"
      | "contains"
      | "matches"
      | "containsAny"
      | "matchesAny"
      | "scan"
      | "anomalyScore"
      | "malformedScore"
      | "promptInjectionScore"
  )
}
