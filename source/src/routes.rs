//! Route lookup and per-route execution planning.
//! Host and path matching stay deterministic because routing decides which policy boundary applies.

use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use crate::bandwidth::{BandwidthPolicy, BandwidthRate, RouteBandwidthLimiter};
use crate::config::{Config, RouteConfig, UpstreamConfig};
use crate::waf::WafEngine;

mod matchers;
mod plan;
use self::matchers::{CompiledRouteMatcher, RouteMatcherResult};
pub use self::matchers::{RouteMatchContext, RouteRequestProtocol};
use self::plan::route_execution_plan;
pub use self::plan::{FastPathPlan, RouteExecutionPlan, RouteWafExecutionPlan, WafExecutionPlan};

/// Immutable route index built from validated configuration.
#[derive(Debug, Clone)]
pub struct RouteTable {
  routes: Vec<RouteEntry>,
  exact_hosts: HashMap<String, Vec<usize>>,
  simple_exact_hosts: HashMap<String, Vec<usize>>,
  wildcard_hosts: WildcardHostTrie,
  catch_all_hosts: Vec<usize>,
  static_sendfile_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
  route: RouteConfig,
  matcher: CompiledRouteMatcher,
  execution_plan: RouteExecutionPlan,
  upstream_index: Option<usize>,
  bandwidth: Arc<RouteBandwidthLimiter>,
  staged_bandwidth_policy: BandwidthPolicy,
}

#[derive(Debug, Clone, Copy)]
struct WildcardHostEntry {
  suffix_len: usize,
  route_index: usize,
}

#[derive(Debug, Clone, Default)]
struct WildcardHostTrie {
  root: WildcardHostTrieNode,
}

#[derive(Debug, Clone, Default)]
struct WildcardHostTrieNode {
  routes: Vec<WildcardHostEntry>,
  children: HashMap<String, WildcardHostTrieNode>,
}

impl WildcardHostTrie {
  fn insert(&mut self, suffix: &str, route_index: usize) {
    let mut node = &mut self.root;
    for label in suffix.rsplit('.') {
      node = node.children.entry(label.to_string()).or_default();
    }
    node.routes.push(WildcardHostEntry {
      suffix_len: suffix.len(),
      route_index,
    });
  }

  fn for_each_match(&self, host: &str, mut visit: impl FnMut(WildcardHostEntry)) {
    if host.split('.').any(str::is_empty) {
      return;
    }

    let host_label_count = host.split('.').count();
    let mut node = &self.root;
    for (depth, label) in host.rsplit('.').enumerate() {
      let Some(child) = node.children.get(label) else {
        break;
      };
      node = child;

      if depth + 1 < host_label_count {
        for &route in &node.routes {
          visit(route);
        }
      }
    }
  }

  fn is_empty(&self) -> bool {
    self.root.routes.is_empty() && self.root.children.is_empty()
  }
}

/// Borrowed route resolution result used by request handlers.
#[derive(Debug, Clone)]
pub struct ResolvedRoute<'a> {
  pub route_index: usize,
  pub route: &'a RouteConfig,
  pub upstream: Option<&'a UpstreamConfig>,
  pub upstream_index: Option<usize>,
  pub execution_plan: &'a RouteExecutionPlan,
  pub bandwidth: &'a Arc<RouteBandwidthLimiter>,
  pub path_captures: Vec<String>,
}

impl RouteTable {
  pub fn new(config: &Config) -> Self {
    Self::new_with_waf_plan(config, |_| RouteWafExecutionPlan::disabled(), None)
  }

  pub fn new_with_waf(config: &Config, waf: &WafEngine) -> Self {
    Self::new_with_waf_and_previous(config, waf, None)
  }

  pub(crate) fn new_with_waf_and_previous(
    config: &Config,
    waf: &WafEngine,
    previous: Option<&Self>,
  ) -> Self {
    Self::new_with_waf_plan(
      config,
      |route| RouteWafExecutionPlan::from_waf(&route.name, waf),
      previous,
    )
  }

  fn new_with_waf_plan(
    config: &Config,
    mut waf_plan_for_route: impl FnMut(&RouteConfig) -> RouteWafExecutionPlan,
    previous: Option<&Self>,
  ) -> Self {
    let upstream_indices: HashMap<&str, usize> = config
      .upstreams
      .iter()
      .enumerate()
      .map(|(index, upstream)| (upstream.name.as_str(), index))
      .collect();
    let mut table = Self::empty();
    for route in &config.routes {
      let waf = waf_plan_for_route(route);
      let execution_plan = route_execution_plan(config, route, waf);
      let upstream_index = route
        .upstream
        .as_deref()
        .and_then(|name| upstream_indices.get(name).copied());
      let staged_bandwidth_policy = route_bandwidth_policy(route);
      let bandwidth = previous
        .and_then(|previous| previous.bandwidth_for_route_name(&route.name))
        .cloned()
        .unwrap_or_else(|| RouteBandwidthLimiter::new(staged_bandwidth_policy));
      table.push_route(
        route.clone(),
        execution_plan,
        upstream_index,
        bandwidth,
        staged_bandwidth_policy,
      );
    }
    table.rebuild_simple_exact_hosts();
    table
  }

  #[cfg(test)]
  fn from_routes_for_tests(routes: Vec<RouteConfig>) -> Self {
    Self::from_routes_with_previous_for_tests(routes, None)
  }

  #[cfg(test)]
  fn from_routes_with_previous_for_tests(
    routes: Vec<RouteConfig>,
    previous: Option<&Self>,
  ) -> Self {
    let mut table = Self::empty();
    for route in routes {
      let staged_bandwidth_policy = route_bandwidth_policy(&route);
      let bandwidth = previous
        .and_then(|previous| previous.bandwidth_for_route_name(&route.name))
        .cloned()
        .unwrap_or_else(|| RouteBandwidthLimiter::new(staged_bandwidth_policy));
      table.push_route(
        route,
        RouteExecutionPlan::default(),
        None,
        bandwidth,
        staged_bandwidth_policy,
      );
    }
    table.rebuild_simple_exact_hosts();
    table
  }

  fn empty() -> Self {
    Self {
      routes: Vec::new(),
      exact_hosts: HashMap::new(),
      simple_exact_hosts: HashMap::new(),
      wildcard_hosts: WildcardHostTrie::default(),
      catch_all_hosts: Vec::new(),
      static_sendfile_prefixes: Vec::new(),
    }
  }

  fn push_route(
    &mut self,
    route: RouteConfig,
    execution_plan: RouteExecutionPlan,
    upstream_index: Option<usize>,
    bandwidth: Arc<RouteBandwidthLimiter>,
    staged_bandwidth_policy: BandwidthPolicy,
  ) {
    let route_index = self.routes.len();
    let matcher = CompiledRouteMatcher::from_route(&route).unwrap_or_else(|error| {
      tracing::warn!(
        error = %error,
        route = %route.name,
        "route matcher compilation failed after validation"
      );
      CompiledRouteMatcher::never()
    });
    for pattern in &route.hosts {
      let pattern = normalize_host(pattern);
      if pattern == "*" {
        self.catch_all_hosts.push(route_index);
      } else if let Some(suffix) = pattern.strip_prefix("*.") {
        self.wildcard_hosts.insert(suffix, route_index);
      } else {
        self
          .exact_hosts
          .entry(pattern)
          .or_default()
          .push(route_index);
      }
    }
    if route.static_root.is_some()
      && route
        .compression
        .as_deref()
        .is_none_or(|value| value == "off")
    {
      self
        .static_sendfile_prefixes
        .push(route.effective_path_prefix().to_string());
    }
    self.routes.push(RouteEntry {
      route,
      matcher,
      execution_plan,
      upstream_index,
      bandwidth,
      staged_bandwidth_policy,
    });
  }

  fn bandwidth_for_route_name(&self, route_name: &str) -> Option<&Arc<RouteBandwidthLimiter>> {
    self
      .routes
      .iter()
      .find(|entry| entry.route.name == route_name)
      .map(|entry| &entry.bandwidth)
  }

  /// Applies staged policy in the final, infallible publication phase.
  /// Reused handles make the change visible to already-active route traffic.
  pub(crate) fn activate_bandwidth(&self) {
    for entry in &self.routes {
      if let Err(error) = entry.bandwidth.update(entry.staged_bandwidth_policy) {
        tracing::error!(
          route = %entry.route.name,
          error = %error,
          "failed to activate validated route bandwidth policy"
        );
      }
    }
  }

  fn rebuild_simple_exact_hosts(&mut self) {
    self.simple_exact_hosts.clear();
    if !self.wildcard_hosts.is_empty() || !self.catch_all_hosts.is_empty() {
      return;
    }
    for (host, route_indices) in &self.exact_hosts {
      if route_indices
        .iter()
        .all(|index| self.routes[*index].matcher.is_prefix_only())
      {
        self
          .simple_exact_hosts
          .insert(host.clone(), route_indices.clone());
      }
    }
  }

  pub(crate) fn has_static_sendfile_candidates(&self) -> bool {
    !self.static_sendfile_prefixes.is_empty()
  }

  pub(crate) fn route_execution_entries(
    &self,
  ) -> impl Iterator<Item = (usize, &RouteConfig, Option<usize>, &RouteExecutionPlan)> + '_ {
    self.routes.iter().enumerate().map(|(index, entry)| {
      (
        index,
        &entry.route,
        entry.upstream_index,
        &entry.execution_plan,
      )
    })
  }

  pub(crate) fn static_sendfile_target_can_match(&self, target: &str) -> bool {
    let Some(path) = origin_form_target_path(target) else {
      return true;
    };
    self
      .static_sendfile_prefixes
      .iter()
      .any(|prefix| path_prefix_matches(prefix, path))
  }

  pub fn resolve<'a>(
    &'a self,
    host: &str,
    path: &str,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    let normalized_host = normalize_host(host);
    self.resolve_normalized_host(&normalized_host, path, upstreams)
  }

  pub(crate) fn resolve_normalized_host<'a>(
    &'a self,
    normalized_host: &str,
    path: &str,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    self.resolve_normalized_host_with_context(
      normalized_host,
      RouteMatchContext::path_only(path),
      upstreams,
    )
  }

  pub(crate) fn resolve_normalized_host_with_context<'a>(
    &'a self,
    normalized_host: &str,
    context: RouteMatchContext<'_>,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    let mut best = None;

    if let Some(route_indices) = self.exact_hosts.get(normalized_host) {
      let host_score = 10_000 + normalized_host.len();
      for &route_index in route_indices {
        self.consider_route(&mut best, route_index, host_score, context);
      }
    }

    self
      .wildcard_hosts
      .for_each_match(normalized_host, |wildcard| {
        self.consider_route(
          &mut best,
          wildcard.route_index,
          1_000 + wildcard.suffix_len,
          context,
        );
      });

    for &route_index in &self.catch_all_hosts {
      self.consider_route(&mut best, route_index, 1, context);
    }

    Some(self.resolve_match(best?, upstreams))
  }

  pub(crate) fn try_resolve_simple_exact_host<'a>(
    &'a self,
    normalized_host: &str,
    path: &str,
    upstreams: &'a [UpstreamConfig],
  ) -> Option<ResolvedRoute<'a>> {
    let route_indices = self.simple_exact_hosts.get(normalized_host)?;
    let host_score = 10_000 + normalized_host.len();
    let mut best = None;
    for &route_index in route_indices {
      let entry = self.routes.get(route_index)?;
      if !path_prefix_matches(entry.route.effective_path_prefix(), path) {
        continue;
      }
      let candidate = RouteMatch {
        route_index,
        match_result: RouteMatcherResult::default(),
        priority: entry.route.r#match.priority,
        host_score,
        path_len: entry.route.effective_path_prefix().len(),
        matcher_specificity: 0,
      };
      if best
        .as_ref()
        .is_none_or(|current| candidate.is_better_than(current))
      {
        best = Some(candidate);
      }
    }
    Some(self.resolve_match(best?, upstreams))
  }

  fn resolve_match<'a>(
    &'a self,
    route_match: RouteMatch,
    upstreams: &'a [UpstreamConfig],
  ) -> ResolvedRoute<'a> {
    let entry = &self.routes[route_match.route_index];
    let route = &entry.route;
    let (upstream_index, upstream) = match (entry.upstream_index, route.upstream.as_deref()) {
      (Some(index), Some(name)) => match upstreams
        .get(index)
        .filter(|upstream| upstream.name == name)
      {
        Some(upstream) => (Some(index), Some(upstream)),
        None => upstreams
          .iter()
          .enumerate()
          .find(|(_, item)| item.name == name)
          .map(|(index, upstream)| (Some(index), Some(upstream)))
          .unwrap_or((None, None)),
      },
      (Some(index), None) => (upstreams.get(index).map(|_| index), upstreams.get(index)),
      (None, Some(name)) => upstreams
        .iter()
        .enumerate()
        .find(|(_, item)| item.name == name)
        .map(|(index, upstream)| (Some(index), Some(upstream)))
        .unwrap_or((None, None)),
      (None, None) => (None, None),
    };
    ResolvedRoute {
      route_index: route_match.route_index,
      route,
      upstream,
      upstream_index,
      execution_plan: &entry.execution_plan,
      bandwidth: &entry.bandwidth,
      path_captures: route_match.match_result.path_captures,
    }
  }

  fn consider_route(
    &self,
    best: &mut Option<RouteMatch>,
    route_index: usize,
    host_score: usize,
    context: RouteMatchContext<'_>,
  ) {
    let Some(entry) = self.routes.get(route_index) else {
      return;
    };
    if !path_prefix_matches(entry.route.effective_path_prefix(), context.path) {
      return;
    }
    let Some(match_result) = entry.matcher.match_request(context) else {
      return;
    };

    let candidate = RouteMatch {
      route_index,
      match_result,
      priority: entry.route.r#match.priority,
      host_score,
      path_len: entry.route.effective_path_prefix().len(),
      matcher_specificity: entry.matcher.specificity(),
    };
    if best
      .as_ref()
      .is_none_or(|current| candidate.is_better_than(current))
    {
      *best = Some(candidate);
    }
  }
}

fn route_bandwidth_policy(route: &RouteConfig) -> BandwidthPolicy {
  fn rate(value: Option<u64>) -> BandwidthRate {
    value.map_or(BandwidthRate::Unlimited, |value| {
      match NonZeroU64::new(value) {
        Some(value) => BandwidthRate::BytesPerSecond(value),
        None => {
          tracing::error!(
            "validated route bandwidth rate unexpectedly became zero; failing closed"
          );
          BandwidthRate::BytesPerSecond(NonZeroU64::MIN)
        }
      }
    })
  }

  BandwidthPolicy::new(
    rate(route.bandwidth.upload_bytes_per_second),
    rate(route.bandwidth.download_bytes_per_second),
  )
}

#[derive(Debug, Clone)]
struct RouteMatch {
  route_index: usize,
  match_result: RouteMatcherResult,
  priority: i32,
  host_score: usize,
  path_len: usize,
  matcher_specificity: usize,
}

impl RouteMatch {
  fn is_better_than(&self, current: &Self) -> bool {
    self.priority > current.priority
      || (self.priority == current.priority && self.host_score > current.host_score)
      || (self.priority == current.priority
        && self.host_score == current.host_score
        && self.path_len > current.path_len)
      || (self.priority == current.priority
        && self.host_score == current.host_score
        && self.path_len == current.path_len
        && self.matcher_specificity > current.matcher_specificity)
      || (self.priority == current.priority
        && self.host_score == current.host_score
        && self.path_len == current.path_len
        && self.matcher_specificity == current.matcher_specificity
        && self.route_index < current.route_index)
  }
}

/// Normalizes a host value for route matching without validating ownership.
pub fn normalize_host(raw: &str) -> String {
  normalize_host_cow(raw).into_owned()
}

pub fn normalize_host_cow(raw: &str) -> Cow<'_, str> {
  let trimmed = raw.trim().trim_end_matches('.');
  if trimmed.starts_with('[')
    && let Some(end) = trimmed.find(']')
  {
    return ascii_lower_cow(&trimmed[1..end]);
  }

  if let Some((host, port)) = trimmed.rsplit_once(':')
    && !host.contains(':')
    && !port.is_empty()
    && port.chars().all(|ch| ch.is_ascii_digit())
  {
    return ascii_lower_cow(host);
  }

  ascii_lower_cow(trimmed)
}

fn ascii_lower_cow(value: &str) -> Cow<'_, str> {
  if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
    Cow::Owned(value.to_ascii_lowercase())
  } else {
    Cow::Borrowed(value)
  }
}

fn origin_form_target_path(target: &str) -> Option<&str> {
  if !target.starts_with('/') || target.starts_with("//") || target.contains("://") {
    return None;
  }
  Some(target.split_once('?').map_or(target, |(path, _)| path))
}

/// Returns whether a request path is within a configured route prefix boundary.
pub fn path_prefix_matches(prefix: &str, path: &str) -> bool {
  if prefix == "/" {
    return true;
  }
  if path == prefix {
    return true;
  }
  if let Some(rest) = path.strip_prefix(prefix) {
    return rest.starts_with('/');
  }
  false
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod more_tests;
