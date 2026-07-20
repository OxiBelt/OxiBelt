//! Rate, connection, dynamic-policy, and mitigation-store validation.

use super::*;

impl Config {
  pub(super) fn validate_limits(&self) -> anyhow::Result<()> {
    if self.limits.max_connections == 0
      || self.limits.max_connections_per_ip == 0
      || self.limits.max_webtransport_sessions == Some(0)
      || self.limits.max_webtransport_sessions_per_ip == Some(0)
      || self.limits.max_webtransport_sessions_per_connection == 0
      || self.limits.max_requests_per_connection == 0
      || self.limits.client_header_timeout_ms == 0
      || self.limits.client_body_timeout_ms == 0
      || self.limits.client_idle_timeout_ms == 0
      || self.limits.websocket_idle_timeout_ms == 0
      || self.limits.webtransport_idle_timeout_ms == 0
      || self.limits.tls_handshake_timeout_ms == 0
      || self.limits.response_send_timeout_ms == 0
      || self.limits.max_headers == 0
      || self.limits.max_header_name_bytes == 0
      || self.limits.max_header_value_bytes == 0
      || self.limits.max_total_header_bytes == 0
      || self.limits.max_uri_bytes == 0
      || self.limits.max_request_body_bytes == 0
    {
      bail!("limits values must be greater than 0");
    }
    let route_names = self
      .routes
      .iter()
      .map(|route| route.name.as_str())
      .collect::<HashSet<_>>();
    let mut names = HashSet::new();
    for rate_limit in &self.rate_limits {
      if rate_limit.name.trim().is_empty() {
        bail!("rate limit name must not be empty");
      }
      if !names.insert(rate_limit.name.as_str()) {
        bail!("duplicate rate limit name {}", rate_limit.name);
      }
      crate::limits::parse_rate(&rate_limit.rate)
        .with_context(|| format!("invalid rate_limits {} rate", rate_limit.name))?;
      if rate_limit.max_buckets == 0 {
        bail!(
          "rate limit {} max_buckets must be greater than 0",
          rate_limit.name
        );
      }
      http::StatusCode::from_u16(rate_limit.status)
        .with_context(|| format!("rate limit {} has invalid status", rate_limit.name))?;
      if let Some(token_header) = &rate_limit.token_header {
        http::header::HeaderName::from_bytes(token_header.as_bytes())
          .with_context(|| format!("rate limit {} has invalid token_header", rate_limit.name))?;
      }
      validate_rate_limit_identity_config(RateLimitIdentityValidation {
        label: "rate limit",
        name: &rate_limit.name,
        key: rate_limit.key,
        ipv4_prefix_bits: rate_limit.ipv4_prefix_bits,
        ipv6_prefix_bits: rate_limit.ipv6_prefix_bits,
        identity_parts: &rate_limit.identity_parts,
        token_bindings: &rate_limit.token_bindings,
        token_header: rate_limit.token_header.as_deref(),
        access_token_source: rate_limit.access_token_source,
        waf_context: false,
      })?;
      let mut route_filter_names = HashSet::new();
      for route in &rate_limit.routes {
        if !route_filter_names.insert(route.as_str()) {
          bail!(
            "rate limit {} contains duplicate route {}",
            rate_limit.name,
            route
          );
        }
        if !route_names.contains(route.as_str()) {
          bail!(
            "rate limit {} references unknown route {}",
            rate_limit.name,
            route
          );
        }
      }
    }
    names.clear();
    for connection_limit in &self.connection_limits {
      if connection_limit.name.trim().is_empty() {
        bail!("connection limit name must not be empty");
      }
      if !names.insert(connection_limit.name.as_str()) {
        bail!("duplicate connection limit name {}", connection_limit.name);
      }
      if connection_limit.limit == 0 {
        bail!(
          "connection limit {} limit must be greater than 0",
          connection_limit.name
        );
      }
      http::StatusCode::from_u16(connection_limit.status).with_context(|| {
        format!(
          "connection limit {} has invalid status",
          connection_limit.name
        )
      })?;
    }
    Ok(())
  }

  pub(super) fn validate_dynamic_policy(
    &self,
    route_names: &HashSet<String>,
  ) -> anyhow::Result<()> {
    let policy = &self.dynamic_policy;
    policy.validate_basic()?;
    validate_optional_non_empty("dynamic_policy.backend", policy.backend.as_deref())?;
    if policy.automation_api.enabled {
      if !policy.enabled {
        bail!("dynamic_policy.automation_api.enabled requires dynamic_policy.enabled = true");
      }
      if !self.admin.enabled {
        bail!("dynamic_policy.automation_api.enabled requires admin.enabled = true");
      }
      policy.automation_api.validate_signature_key_env()?;
    }
    if !policy.enabled {
      return Ok(());
    }
    if !self.shared_state.enabled {
      bail!("dynamic_policy.enabled requires shared_state.enabled = true");
    }
    let Some(backend_name) = self.dynamic_policy_backend_name() else {
      bail!(
        "dynamic_policy.enabled requires dynamic_policy.backend, shared_state.dynamic_policy_backend, shared_state.default_backend, or at least one shared_state backend"
      );
    };
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
    else {
      bail!("dynamic_policy backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("dynamic_policy backend {backend_name} must use kind = \"postgres\"");
    }
    if route_names.is_empty() {
      bail!("dynamic_policy requires at least one named route");
    }
    Ok(())
  }

  pub(super) fn validate_mitigation_database(&self) -> anyhow::Result<()> {
    let mitigation = &self.database.mitigation;
    let Some(backend_name) = mitigation.backend.as_deref() else {
      return Ok(());
    };
    if !mitigation.enabled {
      return Ok(());
    }
    if !self.shared_state.enabled {
      bail!("database.mitigation.backend requires shared_state.enabled = true");
    }
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
    else {
      bail!("database.mitigation.backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("database.mitigation.backend {backend_name} must use kind = \"postgres\"");
    }
    Ok(())
  }

  pub(crate) fn dynamic_policy_backend_name(&self) -> Option<&str> {
    self
      .dynamic_policy
      .backend
      .as_deref()
      .or(self.shared_state.dynamic_policy_backend.as_deref())
      .or(self.shared_state.default_backend.as_deref())
      .or_else(|| {
        self
          .shared_state
          .backends
          .first()
          .map(|backend| backend.name.as_str())
      })
  }
}
