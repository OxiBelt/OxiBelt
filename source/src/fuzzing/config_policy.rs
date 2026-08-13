use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(feature = "admin-runtime")]
use serde_json::{Map, Number, Value, json};

#[cfg(feature = "admin-runtime")]
use crate::admin_list::{AdminListQuery, AdminListSpec};
use crate::config::{
  LbPolicyCompatProfile, normalize_field_path, normalize_route_action_header_name,
  normalize_sni_pattern, normalize_toml_with_profile, validate_sni_server_name,
};
use crate::identity::{Cidr, TrustedCidrs};
use crate::limits::parse_rate;
use crate::routes::normalize_host;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 8 * 1024;
#[cfg(feature = "admin-runtime")]
const MAX_JSON_NODES: usize = 96;

#[cfg(feature = "admin-runtime")]
const ADMIN_LIST_SPEC: AdminListSpec = AdminListSpec {
  endpoint: "/admin/v1/fuzz",
  default_sort: "name",
  allowed_sorts: &["name", "enabled", "source"],
  allowed_filters: &["enabled", "source"],
};

/// Exercises bounded, in-memory configuration and operator normalizers.
///
/// This intentionally keeps filesystem, runtime, network, and secret-bearing paths out of the
/// fuzz contract. The compatibility normalizer's values are stable after normalization, but its
/// diagnostics describe the current pass and are therefore not required to be identical on a
/// second pass.
pub fn exercise_config_policy_normalization(data: &[u8]) {
  let data = &data[..data.len().min(MAX_INPUT_BYTES)];
  let mut input = FuzzInput::new(data);

  exercise_lb_policy_compat(&mut input);
  exercise_field_and_protocol_normalizers(&mut input);
  exercise_identity_and_rate_parsers(&mut input);
  #[cfg(feature = "admin-runtime")]
  exercise_admin_query(&mut input);
  #[cfg(feature = "admin-runtime")]
  exercise_canonical_json(&mut input);
}

fn exercise_lb_policy_compat(input: &mut FuzzInput<'_>) {
  let mut value = bounded_toml_value(input);
  let original = value.clone();
  let profile = match input.byte() % 3 {
    0 => LbPolicyCompatProfile::Strict,
    1 => LbPolicyCompatProfile::Nginx,
    _ => LbPolicyCompatProfile::Caddy,
  };

  let first_diagnostics = normalize_toml_with_profile(&mut value, profile);
  let mut repeat = original;
  let repeat_diagnostics = normalize_toml_with_profile(&mut repeat, profile);
  assert_eq!(
    value, repeat,
    "compatibility normalization must be deterministic for identical input"
  );
  let _ = (first_diagnostics, repeat_diagnostics);

  let normalized = value.clone();
  let _ = normalize_toml_with_profile(&mut value, profile);
  assert_eq!(
    value, normalized,
    "compatibility-normalized TOML values must remain stable on re-normalization"
  );
}

fn exercise_field_and_protocol_normalizers(input: &mut FuzzInput<'_>) {
  let text = input.text(MAX_TEXT_BYTES);
  let host = normalize_host(&text);
  assert_eq!(host, normalize_host(&text));

  let field_path = normalize_field_path(&text);
  assert_eq!(field_path, normalize_field_path(&text));

  let sni_pattern = normalize_sni_pattern(&text);
  assert_eq!(sni_pattern, normalize_sni_pattern(&text));
  let _ = validate_sni_server_name(&text);

  let _ = normalize_route_action_header_name(&text);
  let _ = normalize_route_action_header_name(&text.to_ascii_uppercase());
}

fn exercise_identity_and_rate_parsers(input: &mut FuzzInput<'_>) {
  let raw_cidr = match input.byte() % 4 {
    0 => format!("192.0.2.{}/{}", input.byte(), input.byte() % 33),
    1 => format!("2001:db8::{:x}/{}", input.u16(), input.byte() % 129),
    2 => input.text(256),
    _ => input.text(256),
  };
  if let Ok(cidr) = Cidr::parse(&raw_cidr) {
    let canonical = cidr.canonical();
    assert_eq!(
      Cidr::parse(&canonical).ok().map(|value| value.canonical()),
      Some(canonical)
    );
    let candidate = if cidr.prefix() <= 32 {
      IpAddr::V4(Ipv4Addr::new(192, 0, 2, input.byte()))
    } else {
      IpAddr::V6(Ipv6Addr::from([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
      ]))
    };
    let _ = cidr.contains(candidate);
  }

  let mut cidrs = Vec::new();
  for _ in 0..input.usize(5) {
    cidrs.push(match input.byte() % 2 {
      0 => format!("198.51.100.{}/32", input.byte()),
      _ => format!("2001:db8::{:x}/128", input.u16()),
    });
  }
  let _ = TrustedCidrs::parse(&cidrs);

  let raw_rate = match input.byte() % 4 {
    0 => format!(
      "{}r/{}",
      input.usize(10_000).saturating_add(1),
      ["s", "m", "h"][input.usize(3)]
    ),
    1 => input.text(128),
    2 => "NaNr/s".to_string(),
    _ => "0r/s".to_string(),
  };
  if let Ok(rate) = parse_rate(&raw_rate) {
    let _ = rate.per_second();
  }
}

#[cfg(feature = "admin-runtime")]
fn exercise_admin_query(input: &mut FuzzInput<'_>) {
  let query = match input.byte() % 4 {
    0 => format!(
      "limit={}&sort={}&order={}&filter%5Bsource%5D={}",
      input.usize(1_001).saturating_add(1),
      ["name", "enabled", "source"][input.usize(3)],
      ["asc", "desc", "invalid"][input.usize(3)],
      input.text(128)
    ),
    1 => format!("filter%5Benabled%5D={}", input.text(128)),
    _ => input.text(MAX_TEXT_BYTES.min(2_048)),
  };
  let _ = crate::admin_list::parse_bool(&query);
  let Ok(Some(parsed)) = AdminListQuery::parse(Some(&query), &ADMIN_LIST_SPEC) else {
    return;
  };
  let position = json!({
    "offset": input.usize(4_096),
    "marker": input.text(64),
  });
  let _ = parsed.pagination(true, Some(position));
  let _ = parsed.pagination(false, None);
}

#[cfg(feature = "admin-runtime")]
fn exercise_canonical_json(input: &mut FuzzInput<'_>) {
  let value = bounded_json(input, 0, MAX_JSON_NODES);
  let Ok(first) = crate::admin_audit::fuzz_canonical_json_bytes(&value) else {
    return;
  };
  let Ok(second) = crate::admin_audit::fuzz_canonical_json_bytes(&value) else {
    return;
  };
  assert_eq!(first, second, "canonical JSON must be deterministic");
}

fn bounded_toml_value(input: &mut FuzzInput<'_>) -> toml::Value {
  let mut root = toml::map::Map::new();

  let mut sticky_cookie = toml::map::Map::new();
  sticky_cookie.insert(
    "fallback_algorithm".to_string(),
    toml::Value::String(input.policy_name()),
  );
  let mut upstream_pool = toml::map::Map::new();
  upstream_pool.insert(
    "algorithm".to_string(),
    toml::Value::String(input.policy_name()),
  );
  upstream_pool.insert(
    "sticky_cookie".to_string(),
    toml::Value::Table(sticky_cookie),
  );
  root.insert(
    "upstream_pools".to_string(),
    toml::Value::Array(vec![toml::Value::Table(upstream_pool)]),
  );

  let mut turn_pool = toml::map::Map::new();
  turn_pool.insert(
    "algorithm".to_string(),
    toml::Value::String(input.policy_name()),
  );
  root.insert(
    "turn_upstream_pools".to_string(),
    toml::Value::Array(vec![toml::Value::Table(turn_pool)]),
  );

  let mut action = toml::map::Map::new();
  action.insert(
    "type".to_string(),
    toml::Value::String("set_load_balancing_policy".to_string()),
  );
  action.insert(
    "policy".to_string(),
    toml::Value::String(input.policy_name()),
  );
  let mut rule = toml::map::Map::new();
  rule.insert(
    "actions".to_string(),
    toml::Value::Array(vec![toml::Value::Table(action)]),
  );
  let mut waf = toml::map::Map::new();
  waf.insert(
    "rules".to_string(),
    toml::Value::Array(vec![toml::Value::Table(rule)]),
  );
  root.insert("waf".to_string(), toml::Value::Table(waf));
  toml::Value::Table(root)
}

fn bounded_json(input: &mut FuzzInput<'_>, depth: usize, remaining: usize) -> Value {
  if depth >= 4 || remaining <= 1 {
    return match input.byte() % 5 {
      0 => Value::Null,
      1 => Value::Bool(input.bool()),
      2 => Value::String(input.text(96)),
      3 => Value::Number(Number::from(input.u16())),
      _ => Value::Number(Number::from(i64::from(input.u16()))),
    };
  }
  match input.byte() % 5 {
    0 => Value::Null,
    1 => Value::Bool(input.bool()),
    2 => Value::String(input.text(256)),
    3 => {
      let mut object = Map::new();
      for index in 0..input.usize(4) {
        object.insert(
          format!("k{}{}", index, input.byte()),
          bounded_json(input, depth + 1, remaining.saturating_sub(1)),
        );
      }
      Value::Object(object)
    }
    _ => {
      let mut array = Vec::new();
      for _ in 0..input.usize(4) {
        array.push(bounded_json(input, depth + 1, remaining.saturating_sub(1)));
      }
      Value::Array(array)
    }
  }
}

struct FuzzInput<'a> {
  data: &'a [u8],
  offset: usize,
}

impl<'a> FuzzInput<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self { data, offset: 0 }
  }

  fn byte(&mut self) -> u8 {
    if self.data.is_empty() {
      return 0;
    }
    let byte = self.data[self.offset % self.data.len()];
    self.offset = self.offset.wrapping_add(1);
    byte
  }

  fn bool(&mut self) -> bool {
    self.byte() & 1 == 1
  }

  fn u16(&mut self) -> u16 {
    u16::from_be_bytes([self.byte(), self.byte()])
  }

  fn usize(&mut self, modulo: usize) -> usize {
    if modulo == 0 {
      0
    } else {
      (usize::from(self.u16()) ^ usize::from(self.byte())) % modulo
    }
  }

  fn text(&mut self, max: usize) -> String {
    const ALPHABET: &[u8] =
      b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .:/_-[]%?&=\n\r\t";
    let length = self.usize(max.saturating_add(1));
    (0..length)
      .map(|_| char::from(ALPHABET[self.usize(ALPHABET.len())]))
      .collect()
  }

  fn policy_name(&mut self) -> String {
    match self.byte() % 8 {
      0 => "least_conn".to_string(),
      1 => "least_connections".to_string(),
      2 => "ip_hash".to_string(),
      3 => "round_robin".to_string(),
      4 => "random".to_string(),
      5 => "hash".to_string(),
      _ => self.text(32),
    }
  }
}
