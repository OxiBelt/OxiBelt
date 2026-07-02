//! Mitigation action compilation for HTTP and stream decisions.
//! Actions are validated before they can mutate responses or emit enforcement events.

use std::fmt::Write as _;
use std::net::IpAddr;

use anyhow::{Context, bail};
use http::StatusCode;
use http::header::USER_AGENT;
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use crate::config::MitigationFailurePolicy;
use crate::mitigation::{MitigationDefaults, MitigationEvent, MitigationSink};

mod validation;
use validation::{validate_mitigation_expression, validate_mitigation_fields};

use super::{
  AccessLogJsonValue, CompiledAccessLogField, CompiledRule, EvalContext, Expr, FunctionMap,
  HeaderMutation, ObjectRef, Parser, WafActionConfig, WafStreamClose, WafStreamInput,
  WafTerminalResponse, WafUpstreamError, current_unix_ms, new_access_log_id, validate_status,
  validate_websocket_close_code,
};

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MitigationIntent {
  Dots,
  Flowspec,
  Rtbh,
  Blackhole,
  Vendor,
  Observe,
}

impl MitigationIntent {
  fn as_str(self) -> &'static str {
    match self {
      Self::Dots => "dots",
      Self::Flowspec => "flowspec",
      Self::Rtbh => "rtbh",
      Self::Blackhole => "blackhole",
      Self::Vendor => "vendor",
      Self::Observe => "observe",
    }
  }
}

#[derive(Clone)]
pub(super) struct CompiledMitigationAction {
  intent: MitigationIntent,
  provider: Option<String>,
  reason: Option<String>,
  target: Option<Expr>,
  target_prefix: Option<Expr>,
  ttl_seconds: Option<u64>,
  dedupe_window_ms: Option<u64>,
  min_count: Option<u64>,
  failure_policy: Option<MitigationFailurePolicy>,
  fail_closed_status: u16,
  fail_closed_body: Option<String>,
  fail_closed_websocket_code: u16,
  fail_closed_webtransport_code: u32,
  fail_closed_stream_reason: String,
  fields: Vec<CompiledAccessLogField>,
}

pub(super) fn validate_mitigation_action(
  rule: &super::WafRuleConfig,
  action: &WafActionConfig,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  let WafActionConfig::EmitMitigation {
    provider,
    reason,
    target,
    target_prefix,
    ttl_seconds,
    dedupe_window_ms,
    min_count,
    fail_closed_status,
    fail_closed_body,
    fail_closed_websocket_code,
    fail_closed_stream_reason,
    fields,
    ..
  } = action
  else {
    unreachable!("validate_mitigation_action requires emit_mitigation action");
  };

  validate_optional_label("provider", provider.as_deref(), 128, &rule.name)?;
  validate_optional_label("reason", reason.as_deref(), 1024, &rule.name)?;
  if let Some(ttl_seconds) = ttl_seconds
    && *ttl_seconds == 0
  {
    bail!(
      "WAF rule {} emit_mitigation ttl_seconds must be greater than 0",
      rule.name
    );
  }
  if let Some(dedupe_window_ms) = dedupe_window_ms
    && *dedupe_window_ms == 0
  {
    bail!(
      "WAF rule {} emit_mitigation dedupe_window_ms must be greater than 0",
      rule.name
    );
  }
  if let Some(min_count) = min_count
    && *min_count == 0
  {
    bail!(
      "WAF rule {} emit_mitigation min_count must be greater than 0",
      rule.name
    );
  }
  validate_status(*fail_closed_status, &rule.name)?;
  if let Some(body) = fail_closed_body
    && body.len() > 8192
  {
    bail!(
      "WAF rule {} emit_mitigation fail_closed_body exceeds 8192 bytes",
      rule.name
    );
  }
  validate_websocket_close_code(*fail_closed_websocket_code, &rule.name)?;
  if fail_closed_stream_reason.len() > 123 {
    bail!(
      "WAF rule {} emit_mitigation fail_closed_stream_reason exceeds 123 bytes",
      rule.name
    );
  }

  for (label, expression) in [
    ("target", target.as_deref()),
    ("target_prefix", target_prefix.as_deref()),
  ] {
    if let Some(expression) = expression {
      validate_mitigation_expression(
        &format!("WAF rule {} emit_mitigation {label}", rule.name),
        expression,
        rule.phase,
        global_functions,
        route_functions,
      )?;
    }
  }
  validate_mitigation_fields(
    &format!("WAF rule {} emit_mitigation", rule.name),
    fields,
    rule.phase,
    global_functions,
    route_functions,
  )?;
  Ok(())
}

pub(super) fn compile_mitigation_action(
  rule: &super::WafRuleConfig,
  action: &WafActionConfig,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<CompiledMitigationAction> {
  let WafActionConfig::EmitMitigation {
    intent,
    provider,
    reason,
    target,
    target_prefix,
    ttl_seconds,
    dedupe_window_ms,
    min_count,
    failure_policy,
    fail_closed_status,
    fail_closed_body,
    fail_closed_websocket_code,
    fail_closed_webtransport_code,
    fail_closed_stream_reason,
    fields,
    ..
  } = action
  else {
    unreachable!("compile_mitigation_action requires emit_mitigation action");
  };
  Ok(CompiledMitigationAction {
    intent: *intent,
    provider: provider.clone(),
    reason: reason.clone(),
    target: target
      .as_deref()
      .map(|expression| {
        Parser::new(expression).parse().and_then(|expression| {
          expression.analyze_for_mitigation_field(rule.phase, global_functions, route_functions)
        })
      })
      .transpose()
      .with_context(|| {
        format!(
          "failed to compile WAF rule {} emit_mitigation target",
          rule.name
        )
      })?,
    target_prefix: target_prefix
      .as_deref()
      .map(|expression| {
        Parser::new(expression).parse().and_then(|expression| {
          expression.analyze_for_mitigation_field(rule.phase, global_functions, route_functions)
        })
      })
      .transpose()
      .with_context(|| {
        format!(
          "failed to compile WAF rule {} emit_mitigation target_prefix",
          rule.name
        )
      })?,
    ttl_seconds: *ttl_seconds,
    dedupe_window_ms: *dedupe_window_ms,
    min_count: *min_count,
    failure_policy: *failure_policy,
    fail_closed_status: *fail_closed_status,
    fail_closed_body: fail_closed_body.clone(),
    fail_closed_websocket_code: *fail_closed_websocket_code,
    fail_closed_webtransport_code: *fail_closed_webtransport_code,
    fail_closed_stream_reason: fail_closed_stream_reason.clone(),
    fields: fields
      .iter()
      .map(|field| {
        Ok(CompiledAccessLogField {
          name: field.name.clone(),
          expression: Parser::new(&field.value)
            .parse()
            .and_then(|expression| {
              expression.analyze_for_mitigation_field(rule.phase, global_functions, route_functions)
            })
            .with_context(|| {
              format!(
                "failed to compile WAF rule {} emit_mitigation field {}",
                rule.name, field.name
              )
            })?,
        })
      })
      .collect::<anyhow::Result<_>>()?,
  })
}

pub(super) fn apply_mitigation_http_action(
  action: &CompiledMitigationAction,
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  _response: Option<super::WafResponseInput<'_>>,
  sink: &MitigationSink,
  tx: &mut super::TransactionBudget,
) -> anyhow::Result<Option<WafTerminalResponse>> {
  let event = build_event(action, rule, ctx, None, sink.defaults(), tx)?;
  match sink.emit(event) {
    Ok(()) => Ok(None),
    Err(error) => {
      warn_mitigation_emit_error(error);
      if failure_policy(action, sink.defaults()) == MitigationFailurePolicy::Closed {
        sink.record_fail_closed();
        let mut terminal = WafTerminalResponse::new(
          StatusCode::from_u16(action.fail_closed_status)?,
          action
            .fail_closed_body
            .clone()
            .unwrap_or_else(|| "mitigation queue unavailable".to_string()),
        );
        terminal.headers = Vec::<HeaderMutation>::new();
        Ok(Some(terminal))
      } else {
        Ok(None)
      }
    }
  }
}

pub(super) fn apply_mitigation_stream_action(
  action: &CompiledMitigationAction,
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  input: WafStreamInput<'_>,
  sink: &MitigationSink,
  tx: &mut super::TransactionBudget,
) -> anyhow::Result<Option<WafStreamClose>> {
  let event = build_event(action, rule, ctx, Some(input), sink.defaults(), tx)?;
  match sink.emit(event) {
    Ok(()) => Ok(None),
    Err(error) => {
      warn_mitigation_emit_error(error);
      if failure_policy(action, sink.defaults()) == MitigationFailurePolicy::Closed {
        sink.record_fail_closed();
        Ok(Some(WafStreamClose {
          websocket_code: action.fail_closed_websocket_code,
          webtransport_code: action.fail_closed_webtransport_code,
          reason: action.fail_closed_stream_reason.clone(),
        }))
      } else {
        Ok(None)
      }
    }
  }
}

fn build_event(
  action: &CompiledMitigationAction,
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  stream: Option<WafStreamInput<'_>>,
  defaults: MitigationDefaults,
  tx: &mut super::TransactionBudget,
) -> anyhow::Result<MitigationEvent> {
  let now = current_unix_ms();
  let ttl_seconds = action.ttl_seconds.unwrap_or(defaults.ttl_seconds);
  let dedupe_window_ms = action.dedupe_window_ms.unwrap_or(defaults.dedupe_window_ms);
  let expires_at_unix_ms = now.saturating_add(ttl_seconds.saturating_mul(1000));
  let target_value = match &action.target {
    Some(expression) => value_to_required_string(expression.eval(ctx, tx)?, "target")?,
    None => ctx.request.peer_addr.ip().to_string(),
  };
  let target = if let Some(expression) = &action.target_prefix {
    value_to_required_string(expression.eval(ctx, tx)?, "target_prefix")?
  } else {
    target_value
  };
  let (target_ip, target_cidr) = classify_target(&target)
    .with_context(|| format!("WAF rule {} emit_mitigation target is invalid", rule.name))?;
  let custom = evaluate_custom_fields(action, ctx, tx)?;
  let record = build_record(
    action,
    rule,
    ctx,
    MitigationRecordParts {
      stream,
      now,
      expires_at_unix_ms,
      target: &target,
      target_ip,
      target_cidr: target_cidr.as_deref(),
      custom,
    },
  );
  let dedupe_key = mitigation_dedupe_key(
    action,
    rule,
    ctx,
    &target,
    dedupe_window_ms,
    now / dedupe_window_ms,
  );

  Ok(MitigationEvent {
    intent: action.intent.as_str().to_string(),
    provider: action.provider.clone(),
    target,
    target_ip,
    target_cidr,
    transport_network: ctx.request.transport_network.as_str().to_string(),
    remote_ip: ctx.request.peer_addr.ip(),
    remote_port: ctx.request.peer_addr.port(),
    dedupe_key,
    occurred_at_unix_ms: now,
    expires_at_unix_ms,
    min_count: action.min_count.unwrap_or(1),
    record,
  })
}

struct MitigationRecordParts<'a, 'stream> {
  stream: Option<WafStreamInput<'stream>>,
  now: u64,
  expires_at_unix_ms: u64,
  target: &'a str,
  target_ip: Option<IpAddr>,
  target_cidr: Option<&'a str>,
  custom: JsonValue,
}

fn build_record(
  action: &CompiledMitigationAction,
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  parts: MitigationRecordParts<'_, '_>,
) -> JsonValue {
  let request = ctx.request;
  let MitigationRecordParts {
    stream,
    now,
    expires_at_unix_ms,
    target,
    target_ip,
    target_cidr,
    custom,
  } = parts;
  let user_agent = request
    .headers
    .get(USER_AGENT)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string);
  let tcp = if request.transport_network == super::WafTransportNetwork::Tcp {
    json!({
      "sni": request.tls.sni.as_deref(),
      "alpn": request.tls.alpn.as_deref(),
      "max_hop": request.tcp_max_hop,
      "mss": request.transport_metadata.tcp_mss,
      "rtt_ms": request.transport_metadata.tcp_rtt_ms,
    })
  } else {
    JsonValue::Null
  };
  let udp = if request.transport_network == super::WafTransportNetwork::Udp {
    json!({
      "datagram_size": request.transport_metadata.udp_datagram_size,
      "quic_detected": true,
      "connection_id": request.transport_metadata.udp_connection_id,
    })
  } else {
    JsonValue::Null
  };
  let response = ctx.response.map(|response| {
    json!({
      "id": response.response_id,
      "received_at_unix_ms": response.received_at_unix_ms,
      "status": response.status.as_u16(),
      "upstream": {
        "name": response.upstream_name,
        "pool": response.upstream_pool,
        "scheme": response.upstream_scheme,
        "connect_time_ms": response.upstream_connect_time_ms,
        "first_byte_time_ms": response.upstream_first_byte_time_ms,
        "error": upstream_error_json(response.upstream_error),
      }
    })
  });
  let stream = stream.map(|stream| {
    json!({
      "protocol": stream.protocol.as_str(),
      "direction": stream.direction.as_str(),
      "unit": stream.unit.as_str(),
      "payload_size": stream.payload.bytes.len(),
      "payload_is_truncated": stream.payload.is_truncated,
      "websocket": stream.websocket.map(|metadata| json!({
        "opcode": metadata.opcode,
        "fin": metadata.fin,
        "is_control": metadata.is_control,
        "message_opcode": metadata.message_opcode,
        "frame_payload_size": metadata.frame_payload_size,
      })),
      "webtransport": stream.webtransport.map(|metadata| json!({
        "stream_kind": metadata.stream_kind.map(|kind| kind.as_str()),
        "stream_id": metadata.stream_id,
        "datagram_size": metadata.datagram_size,
      })),
    })
  });

  json!({
    "event": "oxibelt.mitigation",
    "event_id": new_access_log_id(),
    "timestamp_unix_ms": now,
    "expires_at_unix_ms": expires_at_unix_ms,
    "intent": action.intent.as_str(),
    "provider": action.provider.as_deref(),
    "reason": action.reason.as_deref(),
    "target": target,
    "target_ip": target_ip.map(|ip| ip.to_string()),
    "target_cidr": target_cidr,
    "phase": ctx.phase.as_str(),
    "rule": {
      "scope": &rule.scope,
      "route": rule.route.as_deref(),
      "name": &rule.name,
      "id": rule.id.as_deref(),
      "tags": &rule.tags,
      "mode": rule.mode.as_str(),
    },
    "request": {
      "id": request.request_id,
      "transaction_id": request.transaction_id,
      "received_at_unix_ms": request.received_at_unix_ms,
      "method": request.method.as_str(),
      "version": super::version_string(request.version),
      "scheme": request.downstream_scheme,
      "host": request.downstream_host,
      "path": request.uri.path(),
      "route": request.route_name,
      "protocol": request.protocol.as_str(),
      "user_agent": user_agent,
    },
    "transport": {
      "network": request.transport_network.as_str(),
      "remote_ip": request.peer_addr.ip().to_string(),
      "remote_port": request.peer_addr.port(),
      "tcp": tcp,
      "udp": udp,
    },
    "tls": {
      "enabled": request.tls.enabled,
      "version": request.tls.version.as_deref(),
      "cipher_suite": request.tls.cipher_suite.as_deref(),
      "sni": request.tls.sni.as_deref(),
      "alpn": request.tls.alpn.as_deref(),
      "fingerprint": request.tls.fingerprint.as_deref(),
      "fingerprint_scheme": request.tls.fingerprint_scheme.as_deref(),
    },
    "response": response,
    "stream": stream,
    "custom": custom,
  })
}

fn upstream_error_json(error: Option<WafUpstreamError<'_>>) -> JsonValue {
  error
    .map(|error| {
      json!({
        "code": error.code,
        "message": error.message,
      })
    })
    .unwrap_or(JsonValue::Null)
}

fn evaluate_custom_fields(
  action: &CompiledMitigationAction,
  ctx: &EvalContext<'_>,
  tx: &mut super::TransactionBudget,
) -> anyhow::Result<JsonValue> {
  let mut object = JsonMap::new();
  for field in &action.fields {
    let value = field
      .expression
      .eval(ctx, tx)
      .with_context(|| format!("failed to evaluate emit_mitigation field {}", field.name))?;
    object.insert(field.name.clone(), value_to_json(value, ctx)?);
  }
  Ok(JsonValue::Object(object))
}

fn value_to_json(value: super::Value, ctx: &EvalContext<'_>) -> anyhow::Result<JsonValue> {
  if matches!(
    value,
    super::Value::Object(
      ObjectRef::RequestBody | ObjectRef::ResponseBody | ObjectRef::StreamPayload
    )
  ) {
    bail!("emit_mitigation fields cannot write request, response, or stream body bytes");
  }
  let value = AccessLogJsonValue::from_value(value, ctx)?;
  Ok(access_log_json_to_serde(value))
}

fn access_log_json_to_serde(value: AccessLogJsonValue) -> JsonValue {
  match value {
    AccessLogJsonValue::Bool(value) => JsonValue::Bool(value),
    AccessLogJsonValue::Int(value) => JsonValue::Number(value.into()),
    AccessLogJsonValue::String(value) => JsonValue::String(value),
    AccessLogJsonValue::Array(values) => {
      JsonValue::Array(values.into_iter().map(access_log_json_to_serde).collect())
    }
    AccessLogJsonValue::Object(values) => JsonValue::Object(
      values
        .into_iter()
        .map(|(name, value)| (name, access_log_json_to_serde(value)))
        .collect(),
    ),
    AccessLogJsonValue::Null => JsonValue::Null,
  }
}

fn value_to_required_string(value: super::Value, label: &str) -> anyhow::Result<String> {
  match value {
    super::Value::String(value) => Ok(value),
    super::Value::Int(value) => Ok(value.to_string()),
    super::Value::Bool(value) => Ok(value.to_string()),
    super::Value::Null => bail!("emit_mitigation {label} evaluated to null"),
    other => bail!("emit_mitigation {label} must evaluate to String, Int, or Bool, got {other:?}"),
  }
}

fn classify_target(target: &str) -> anyhow::Result<(Option<IpAddr>, Option<String>)> {
  if target.contains('/') {
    validate_cidr(target)?;
    return Ok((None, Some(target.to_string())));
  }
  Ok((Some(target.parse()?), None))
}

fn validate_cidr(value: &str) -> anyhow::Result<()> {
  let Some((ip, prefix)) = value.split_once('/') else {
    bail!("CIDR target must contain /");
  };
  let ip: IpAddr = ip.parse()?;
  let prefix: u8 = prefix.parse()?;
  match ip {
    IpAddr::V4(_) if prefix <= 32 => Ok(()),
    IpAddr::V6(_) if prefix <= 128 => Ok(()),
    IpAddr::V4(_) => bail!("IPv4 CIDR prefix must be <= 32"),
    IpAddr::V6(_) => bail!("IPv6 CIDR prefix must be <= 128"),
  }
}

fn mitigation_dedupe_key(
  action: &CompiledMitigationAction,
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  target: &str,
  dedupe_window_ms: u64,
  bucket: u64,
) -> String {
  let material = format!(
    "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
    ctx.phase.as_str(),
    rule.scope,
    rule.route.as_deref().unwrap_or_default(),
    rule.id.as_deref().unwrap_or(&rule.name),
    action.intent.as_str(),
    action.provider.as_deref().unwrap_or_default(),
    target,
    ctx.request.transport_network.as_str(),
    dedupe_window_ms,
    bucket,
    ctx.request.route_name
  );
  let digest = crate::crypto::sha256(material.as_bytes());
  let mut out = String::with_capacity(64);
  for byte in digest {
    write!(&mut out, "{byte:02x}").expect("hex write should succeed");
  }
  out
}

fn failure_policy(
  action: &CompiledMitigationAction,
  defaults: MitigationDefaults,
) -> MitigationFailurePolicy {
  action.failure_policy.unwrap_or(defaults.failure_policy)
}

fn warn_mitigation_emit_error(error: crate::mitigation::MitigationEmitError) {
  tracing::warn!(?error, "failed to enqueue mitigation event");
}

fn validate_optional_label(
  field: &str,
  value: Option<&str>,
  max_len: usize,
  rule_name: &str,
) -> anyhow::Result<()> {
  if let Some(value) = value
    && (value.trim().is_empty() || value.len() > max_len)
  {
    bail!("WAF rule {rule_name} emit_mitigation {field} is empty or too long");
  }
  Ok(())
}
