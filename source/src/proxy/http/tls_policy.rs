use crate::config::{Config, RouteConfig, TlsNegotiationPolicy};
use crate::state::AppSnapshot;
use crate::waf::WafTlsMetadata;

pub(crate) fn route_matches_selected_tls_negotiation_policy(
  state: &AppSnapshot,
  tls: &WafTlsMetadata,
  route: &RouteConfig,
) -> bool {
  if !tls.enabled {
    return true;
  }
  let selected_policy = state
    .tls_server_config
    .selected_negotiation_policy(tls.sni.as_deref());
  tls_negotiation_policy_matches_route(selected_policy, &state.config, route)
}

fn tls_negotiation_policy_matches_route(
  policy: &TlsNegotiationPolicy,
  config: &Config,
  route: &RouteConfig,
) -> bool {
  let route_tls12_groups = route
    .tls
    .tls12
    .groups
    .as_deref()
    .unwrap_or(config.tls.tls12.groups.as_slice());
  let route_tls13_key_exchange_groups = route
    .tls
    .tls13
    .key_exchange_groups
    .as_deref()
    .unwrap_or(config.tls.tls13.key_exchange_groups.as_slice());
  let route_tls13_ciphers = route
    .tls
    .tls13
    .ciphers
    .as_deref()
    .unwrap_or(config.tls.tls13.ciphers.as_slice());

  policy.min_version == route.tls.min_version.unwrap_or(config.tls.min_version)
    && policy.max_version == route.tls.max_version.unwrap_or(config.tls.max_version)
    && policy.tls12.groups.as_slice() == route_tls12_groups
    && policy.tls12.key_exchange_groups.as_slice()
      == config.tls.tls12.key_exchange_groups.as_slice()
    && policy.tls13.key_exchange_groups.as_slice() == route_tls13_key_exchange_groups
    && policy.tls13.ciphers.as_slice() == route_tls13_ciphers
}
