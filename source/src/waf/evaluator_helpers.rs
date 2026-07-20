//! Evaluator comparison, argument, metadata, and truncation helpers.

use super::*;

pub(super) fn values_equal(left: &Value, right: &Value) -> anyhow::Result<bool> {
  match (left, right) {
    (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
    (Value::Int(left), Value::Int(right)) => Ok(left == right),
    (Value::String(left), Value::String(right)) => Ok(left == right),
    (Value::Bytes(left), Value::Bytes(right)) => Ok(left == right),
    (Value::StringList(left), Value::StringList(right)) => {
      Ok(left.values == right.values && left.is_truncated == right.is_truncated)
    }
    (Value::Null, Value::Null) => Ok(true),
    (Value::Null, other) | (other, Value::Null) => Ok(other.is_null()),
    (Value::Object(_), Value::Object(_)) => Ok(true),
    _ => Ok(false),
  }
}

pub(super) fn expect_string_arg(args: &[Value], index: usize) -> anyhow::Result<&str> {
  args
    .get(index)
    .ok_or_else(|| anyhow!("missing string argument {index}"))?
    .as_string()
}

pub(super) fn expect_int_arg(args: &[Value], index: usize) -> anyhow::Result<i64> {
  match args
    .get(index)
    .ok_or_else(|| anyhow!("missing integer argument {index}"))?
  {
    Value::Int(value) => Ok(*value),
    value => bail!("expected Int argument {index}, got {:?}", value),
  }
}

pub(super) fn expect_u8_arg(
  args: &[Value],
  index: usize,
  max: i64,
  label: &str,
) -> anyhow::Result<u8> {
  let value = expect_int_arg(args, index)?;
  if !(0..=max).contains(&value) {
    bail!("{label} must be between 0 and {max}");
  }
  Ok(value as u8)
}

pub(super) fn header_name(name: &str) -> anyhow::Result<HeaderName> {
  HeaderName::from_bytes(name.as_bytes()).context("invalid header name")
}

pub(super) fn header_single(
  headers: &HeaderMap,
  name: HeaderName,
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  let values = headers
    .get_all(name)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .collect::<Vec<_>>();
  single_string_value(
    values
      .into_iter()
      .map(|value| truncate_to_bytes(value, ctx.limits.max_header_value_bytes)),
    ctx.duplicate_metadata_policy,
  )
}

pub(super) fn single_pair_value(
  pairs: &[(String, String)],
  name: &str,
  policy: WafDuplicateMetadataPolicy,
) -> anyhow::Result<Value> {
  single_string_value(
    pairs
      .iter()
      .filter(|(key, _)| key == name)
      .map(|(_, value)| value.clone()),
    policy,
  )
}

pub(super) fn single_string_value<I>(
  values: I,
  policy: WafDuplicateMetadataPolicy,
) -> anyhow::Result<Value>
where
  I: IntoIterator<Item = String>,
{
  let mut values = values.into_iter();
  let Some(first) = values.next() else {
    return Ok(Value::Null);
  };
  if values.next().is_some() {
    return match policy {
      WafDuplicateMetadataPolicy::FailClosed | WafDuplicateMetadataPolicy::RejectRequest => {
        bail!("duplicate request metadata value")
      }
      WafDuplicateMetadataPolicy::NullOnDuplicate => Ok(Value::Null),
    };
  }
  Ok(Value::String(first))
}

pub(super) fn bounded_string_list<I>(values: I, limits: &WafLimits) -> BoundedStringList
where
  I: IntoIterator<Item = String>,
{
  let mut result = Vec::new();
  let mut total_bytes = 0usize;
  let mut is_truncated = false;
  for value in values {
    if result.len() >= limits.max_helper_items {
      is_truncated = true;
      break;
    }
    let next_total = total_bytes.saturating_add(value.len());
    if next_total > limits.max_helper_result_bytes {
      is_truncated = true;
      break;
    }
    total_bytes = next_total;
    result.push(value);
  }
  BoundedStringList {
    values: result,
    is_truncated,
  }
}

pub(super) fn truncate_to_bytes(value: &str, max_bytes: usize) -> String {
  if value.len() <= max_bytes {
    return value.to_string();
  }
  let mut end = max_bytes;
  while !value.is_char_boundary(end) {
    end = end.saturating_sub(1);
  }
  value[..end].to_string()
}
