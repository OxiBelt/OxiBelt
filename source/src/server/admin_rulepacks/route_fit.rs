use std::collections::BTreeSet;

use crate::config::Config;
use crate::waf::{RulepackBinding, RulepackBindingKind, RulepackInputMetadata};

use super::{AdminRulepackRouteCandidate, AdminRulepackRouteCandidateSet, RouteInventory};

pub(super) fn route_candidates(
  config: &Config,
  inputs: &RulepackInputMetadata,
) -> Vec<AdminRulepackRouteCandidateSet> {
  let routes = route_inventory(config);
  let default_tokens = default_discovery_tokens(inputs);
  inputs
    .bindings
    .iter()
    .filter(|binding| binding.kind == RulepackBindingKind::Route)
    .map(|binding| AdminRulepackRouteCandidateSet {
      binding: binding.name.clone(),
      candidates: score_route_candidates(binding, &routes, &default_tokens),
    })
    .collect()
}

fn route_inventory(config: &Config) -> Vec<RouteInventory> {
  config
    .routes
    .iter()
    .map(|route| {
      let upstream = route
        .upstream
        .clone()
        .or_else(|| route.upstream_pool.clone());
      let mut upstream_text = Vec::new();
      if let Some(upstream) = &upstream {
        upstream_text.push(upstream.clone());
      }
      RouteInventory {
        name: route.name.clone(),
        hosts: route.hosts.clone(),
        path_prefix: route.effective_path_prefix().to_string(),
        upstream,
        upstream_text,
      }
    })
    .collect()
}

fn score_route_candidates(
  binding: &RulepackBinding,
  routes: &[RouteInventory],
  default_tokens: &[String],
) -> Vec<AdminRulepackRouteCandidate> {
  let mut candidates = routes
    .iter()
    .filter_map(|route| score_route_candidate(binding, route, default_tokens))
    .collect::<Vec<_>>();
  candidates.sort_by(|left, right| {
    right
      .score
      .cmp(&left.score)
      .then_with(|| left.name.cmp(&right.name))
  });
  candidates.truncate(10);
  candidates
}

fn score_route_candidate(
  binding: &RulepackBinding,
  route: &RouteInventory,
  default_tokens: &[String],
) -> Option<AdminRulepackRouteCandidate> {
  let discovery = &binding.discovery;
  let name_tokens = tokens_or_default(&discovery.name_any, default_tokens);
  let host_tokens = tokens_or_default(&discovery.host_contains_any, default_tokens);
  let upstream_tokens = tokens_or_default(&discovery.upstream_contains_any, default_tokens);
  let mut score = 0;
  let mut reason = Vec::new();
  if let Some(token) = first_contains(std::slice::from_ref(&route.name), &name_tokens) {
    score += 50;
    reason.push(format!("route name contains {token}"));
  }
  if let Some((value, token)) = first_contains_value(&route.hosts, &host_tokens) {
    score += 30;
    reason.push(format!("host {value} contains {token}"));
  }
  if let Some((value, token)) = first_contains_value(&route.upstream_text, &upstream_tokens) {
    score += 25;
    reason.push(format!("route inventory value {value} contains {token}"));
  }
  if discovery
    .path_prefix_any
    .iter()
    .any(|prefix| prefix == &route.path_prefix)
  {
    score += 5;
    reason.push(format!("path_prefix is {}", route.path_prefix));
  }
  (score > 0).then(|| AdminRulepackRouteCandidate {
    name: route.name.clone(),
    score,
    reason,
    hosts: route.hosts.clone(),
    path_prefix: route.path_prefix.clone(),
    upstream: route.upstream.clone(),
  })
}

fn tokens_or_default<'a>(tokens: &'a [String], default_tokens: &'a [String]) -> Vec<&'a str> {
  let values = if tokens.is_empty() {
    default_tokens
  } else {
    tokens
  };
  values
    .iter()
    .map(String::as_str)
    .filter(|token| !token.trim().is_empty())
    .collect()
}

fn first_contains(values: &[String], tokens: &[&str]) -> Option<String> {
  first_contains_value(values, tokens).map(|(_, token)| token)
}

fn first_contains_value(values: &[String], tokens: &[&str]) -> Option<(String, String)> {
  for value in values {
    let lower = value.to_ascii_lowercase();
    for token in tokens {
      let token = token.to_ascii_lowercase();
      if !token.is_empty() && lower.contains(&token) {
        return Some((value.clone(), token));
      }
    }
  }
  None
}

fn default_discovery_tokens(inputs: &RulepackInputMetadata) -> Vec<String> {
  let mut tokens = BTreeSet::new();
  for value in inputs
    .summary
    .targets
    .iter()
    .chain(std::iter::once(&inputs.summary.name))
  {
    for token in value
      .split(['-', '_', '.', ':'])
      .map(str::trim)
      .filter(|token| !token.is_empty())
    {
      tokens.insert(token.to_ascii_lowercase());
    }
  }
  tokens.into_iter().collect()
}

pub(super) fn route_warnings(
  inputs: &RulepackInputMetadata,
  route_candidates: &[AdminRulepackRouteCandidateSet],
) -> Vec<String> {
  inputs
    .bindings
    .iter()
    .filter(|binding| binding.kind == RulepackBindingKind::Route)
    .filter(|binding| {
      route_candidates
        .iter()
        .find(|set| set.binding == binding.name)
        .is_some_and(|set| set.candidates.is_empty())
    })
    .map(|binding| format!("no route candidates matched binding {}", binding.name))
    .collect()
}
