use anyhow::bail;

use super::{
  RouteClientCertMatchConfig, RouteConfig, RouteNamedValueMatchConfig, RouteValueMatchConfig,
};

pub(super) fn validate_route_match_conflicts(routes: &[RouteConfig]) -> anyhow::Result<()> {
  for (left_index, left) in routes.iter().enumerate() {
    for right in routes.iter().skip(left_index + 1) {
      if route_order_tie_can_match_same_request(left, right)? {
        bail!(
          "routes {} and {} have overlapping route matchers with equal precedence",
          left.name,
          right.name
        );
      }
    }
  }
  Ok(())
}

fn route_order_tie_can_match_same_request(
  left: &RouteConfig,
  right: &RouteConfig,
) -> anyhow::Result<bool> {
  if left.r#match.priority != right.r#match.priority {
    return Ok(false);
  }
  if !host_score_tie_can_overlap(left, right) {
    return Ok(false);
  }
  if left.effective_path_prefix().len() != right.effective_path_prefix().len()
    || !path_domains_overlap(left, right)?
  {
    return Ok(false);
  }
  if route_matcher_specificity(left) != route_matcher_specificity(right) {
    return Ok(false);
  }
  Ok(route_predicates_can_overlap(left, right)?)
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum RouteHostPattern {
  Any,
  Exact(String),
  Wildcard(String),
}

impl RouteHostPattern {
  fn parse(raw: &str) -> Self {
    let normalized = crate::routes::normalize_host(raw);
    if normalized == "*" {
      Self::Any
    } else if let Some(suffix) = normalized.strip_prefix("*.") {
      Self::Wildcard(suffix.to_string())
    } else {
      Self::Exact(normalized)
    }
  }

  fn tie_overlaps(&self, other: &Self) -> bool {
    match (self, other) {
      (Self::Any, Self::Any) => true,
      (Self::Exact(left), Self::Exact(right)) => left == right,
      (Self::Wildcard(left), Self::Wildcard(right)) => left == right,
      _ => false,
    }
  }
}

fn host_score_tie_can_overlap(left: &RouteConfig, right: &RouteConfig) -> bool {
  left
    .hosts
    .iter()
    .map(|host| RouteHostPattern::parse(host))
    .any(|left_host| {
      right
        .hosts
        .iter()
        .map(|host| RouteHostPattern::parse(host))
        .any(|right_host| left_host.tie_overlaps(&right_host))
    })
}

fn path_domains_overlap(left: &RouteConfig, right: &RouteConfig) -> anyhow::Result<bool> {
  if left.effective_path_prefix() != right.effective_path_prefix() {
    return Ok(false);
  }
  match (&left.r#match.path.exact, &right.r#match.path.exact) {
    (Some(left_exact), Some(right_exact)) => Ok(left_exact == right_exact),
    (Some(left_exact), None) => path_matches_route_path_constraints(right, left_exact),
    (None, Some(right_exact)) => path_matches_route_path_constraints(left, right_exact),
    (None, None) => Ok(true),
  }
}

fn path_matches_route_path_constraints(route: &RouteConfig, path: &str) -> anyhow::Result<bool> {
  if !route_path_prefix_matches(route.effective_path_prefix(), path) {
    return Ok(false);
  }
  if let Some(exact) = &route.r#match.path.exact {
    return Ok(path == exact);
  }
  if let Some(regex) = &route.r#match.path.regex {
    return Ok(regex::Regex::new(regex)?.is_match(path));
  }
  Ok(true)
}

fn route_path_prefix_matches(prefix: &str, path: &str) -> bool {
  if prefix == "/" || path == prefix {
    return true;
  }
  path
    .strip_prefix(prefix)
    .is_some_and(|rest| rest.starts_with('/'))
}

fn route_matcher_specificity(route: &RouteConfig) -> usize {
  route.r#match.methods.len()
    + route.r#match.headers.len() * 2
    + route.r#match.queries.len() * 2
    + usize::from(route.r#match.path.exact.is_some()) * 4
    + usize::from(route.r#match.path.regex.is_some()) * 3
    + route.r#match.source_cidrs.len()
    + route.r#match.protocols.len()
    + client_cert_matcher_specificity(&route.r#match.tls.client_cert)
}

fn client_cert_matcher_specificity(client_cert: &RouteClientCertMatchConfig) -> usize {
  usize::from(client_cert.present.is_some())
    + usize::from(client_cert.fingerprint_sha256.has_conditions()) * 3
    + usize::from(client_cert.subject_cn.has_conditions()) * 2
    + usize::from(client_cert.san_dns.has_conditions()) * 2
    + usize::from(client_cert.san_ip.has_conditions()) * 2
}

fn route_predicates_can_overlap(left: &RouteConfig, right: &RouteConfig) -> anyhow::Result<bool> {
  Ok(
    methods_overlap(&left.r#match.methods, &right.r#match.methods)
      && protocols_overlap(&left.r#match.protocols, &right.r#match.protocols)
      && source_cidrs_overlap(&left.r#match.source_cidrs, &right.r#match.source_cidrs)?
      && named_matchers_overlap(&left.r#match.headers, &right.r#match.headers, true)
      && named_matchers_overlap(&left.r#match.queries, &right.r#match.queries, false)
      && client_cert_matchers_overlap(
        &left.r#match.tls.client_cert,
        &right.r#match.tls.client_cert,
      ),
  )
}

fn methods_overlap(left: &[String], right: &[String]) -> bool {
  left.is_empty()
    || right.is_empty()
    || left
      .iter()
      .any(|left_method| right.iter().any(|right_method| left_method == right_method))
}

fn protocols_overlap(left: &[String], right: &[String]) -> bool {
  let left_mask = protocol_mask(left);
  let right_mask = protocol_mask(right);
  left_mask & right_mask != 0
}

fn protocol_mask(protocols: &[String]) -> u8 {
  if protocols.is_empty() {
    return 0b11_1111;
  }
  protocols.iter().fold(0, |mask, protocol| {
    mask
      | match protocol.as_str() {
        "http" => 0b00_0111,
        "http1" => 0b00_0001,
        "http2" => 0b00_0010,
        "http3" => 0b00_0100,
        "websocket" => 0b00_1000,
        "webtransport" => 0b01_0000,
        _ => 0,
      }
  })
}

fn source_cidrs_overlap(left: &[String], right: &[String]) -> anyhow::Result<bool> {
  if left.is_empty() || right.is_empty() {
    return Ok(true);
  }
  let left = parse_cidrs(left)?;
  let right = parse_cidrs(right)?;
  Ok(left.iter().any(|left_cidr| {
    right
      .iter()
      .any(|right_cidr| left_cidr.overlaps(right_cidr))
  }))
}

fn parse_cidrs(cidrs: &[String]) -> anyhow::Result<Vec<crate::identity::Cidr>> {
  cidrs
    .iter()
    .map(|cidr| crate::identity::Cidr::parse(cidr))
    .collect()
}

fn named_matchers_overlap(
  left: &[RouteNamedValueMatchConfig],
  right: &[RouteNamedValueMatchConfig],
  header_name: bool,
) -> bool {
  for left_matcher in left {
    for right_matcher in right {
      if normalized_matcher_name(&left_matcher.name, header_name)
        != normalized_matcher_name(&right_matcher.name, header_name)
      {
        continue;
      }
      if !repeated_metadata_matchers_overlap(&left_matcher.value, &right_matcher.value) {
        return false;
      }
    }
  }
  true
}

fn normalized_matcher_name(name: &str, header_name: bool) -> String {
  if header_name {
    name.to_ascii_lowercase()
  } else {
    name.to_string()
  }
}

fn client_cert_matchers_overlap(
  left: &RouteClientCertMatchConfig,
  right: &RouteClientCertMatchConfig,
) -> bool {
  optional_presence_overlaps(left.present, right.present)
    && value_matchers_overlap(&left.fingerprint_sha256, &right.fingerprint_sha256)
    && repeated_metadata_matchers_overlap(&left.subject_cn, &right.subject_cn)
    && repeated_metadata_matchers_overlap(&left.san_dns, &right.san_dns)
    && repeated_metadata_matchers_overlap(&left.san_ip, &right.san_ip)
}

fn optional_presence_overlaps(left: Option<bool>, right: Option<bool>) -> bool {
  !matches!(
    (left, right),
    (Some(true), Some(false)) | (Some(false), Some(true))
  )
}

fn value_matchers_overlap(left: &RouteValueMatchConfig, right: &RouteValueMatchConfig) -> bool {
  if !optional_presence_overlaps(left.present, right.present) {
    return false;
  }
  match (exact_match_value(left), exact_match_value(right)) {
    (Some(left_exact), Some(right_exact)) => left_exact == right_exact,
    (Some(exact), None) => value_matcher_accepts_exact(right, exact),
    (None, Some(exact)) => value_matcher_accepts_exact(left, exact),
    (None, None) => non_exact_value_matchers_can_overlap(left, right),
  }
}

fn repeated_metadata_matchers_overlap(
  left: &RouteValueMatchConfig,
  right: &RouteValueMatchConfig,
) -> bool {
  if left.present == Some(false) || right.present == Some(false) {
    return left.present == Some(false) && right.present == Some(false);
  }
  true
}

fn exact_match_value(matcher: &RouteValueMatchConfig) -> Option<&str> {
  matcher.exact.as_deref()
}

fn value_matcher_accepts_exact(matcher: &RouteValueMatchConfig, exact: &str) -> bool {
  if let Some(present) = matcher.present {
    return present;
  }
  if let Some(prefix) = &matcher.prefix
    && !exact.starts_with(prefix)
  {
    return false;
  }
  if let Some(suffix) = &matcher.suffix
    && !exact.ends_with(suffix)
  {
    return false;
  }
  if let Some(contains) = &matcher.contains
    && !exact.contains(contains)
  {
    return false;
  }
  if let Some(regex) = &matcher.regex {
    return regex::Regex::new(regex).is_ok_and(|regex| regex.is_match(exact));
  }
  true
}

fn non_exact_value_matchers_can_overlap(
  left: &RouteValueMatchConfig,
  right: &RouteValueMatchConfig,
) -> bool {
  if !left.has_conditions() || !right.has_conditions() {
    return true;
  }
  if matches!(
    (left.present, right.present),
    (Some(false), _) | (_, Some(false))
  ) {
    return left.present == Some(false) && right.present == Some(false);
  }
  if let (Some(left_prefix), Some(right_prefix)) = (&left.prefix, &right.prefix)
    && !left_prefix.starts_with(right_prefix)
    && !right_prefix.starts_with(left_prefix)
  {
    return false;
  }
  if let (Some(left_suffix), Some(right_suffix)) = (&left.suffix, &right.suffix)
    && !left_suffix.ends_with(right_suffix)
    && !right_suffix.ends_with(left_suffix)
  {
    return false;
  }
  true
}
