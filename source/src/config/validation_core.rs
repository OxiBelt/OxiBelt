//! Top-level semantic validation and runtime artifact constraints.

use super::*;

impl Config {
  pub fn validate(&self) -> anyhow::Result<()> {
    #[cfg(feature = "admin-runtime")]
    let artifact = RuntimeArtifact::Standalone;
    #[cfg(not(feature = "admin-runtime"))]
    let artifact = RuntimeArtifact::StrictDataPlane;

    self.validate_for_artifact(artifact)
  }

  fn validate_common(&self) -> anyhow::Result<()> {
    self.proxy.upstream_resolution.validate()?;
    if !self.listeners.http1
      && !self.listeners.http2
      && !self.listeners.http3
      && !self.sni_forward.has_any_protocol()
    {
      bail!("at least one downstream HTTP version or SNI forwarding protocol must be enabled");
    }

    self.validate_listener_binds()?;
    if self.listeners.http_mode != HttpListenerMode::Off && self.listeners.http_binds.is_empty() {
      bail!("listeners.http_binds is required when listeners.http_mode is not \"off\"");
    }
    if self.listeners.proxy_protocol.enabled {
      for cidr in &self.listeners.proxy_protocol.trusted_sources {
        crate::identity::Cidr::parse(cidr).with_context(|| {
          format!("invalid listeners.proxy_protocol.trusted_sources entry {cidr}")
        })?;
      }
    }

    self.runtime.validate()?;
    self
      .rollout
      .validate(&self.source_paths, self.runtime.hot_reload.mode)?;
    self.validate_limits()?;
    self.validate_proxy()?;
    self.validate_compression()?;
    self.validate_cache()?;
    self.validate_ipm()?;
    self.validate_admin()?;
    self.validate_admin_mutations()?;
    self.validate_metrics_and_health()?;
    self.overload.validate()?;
    self.circuit_breakers.validate()?;
    self.telemetry.validate()?;
    security_headers::validate_security_headers(self)?;
    crypto::validate_crypto(self)?;
    self.validate_tls()?;
    self.certificate_transparency.validate()?;
    self.quic.validate(self.listeners.http3)?;
    self.validate_http3_alt_svc_binds()?;
    self.validate_sni_forward()?;
    self.access_log.validate()?;
    self.logging.validate()?;

    if self.runtime.linux_only && !cfg!(target_os = "linux") {
      bail!("this build is configured for Linux only");
    }

    if self.routes.is_empty()
      && self.stream_listeners.is_empty()
      && self.webrtc_turn_listeners.is_empty()
      && !self.sni_forward.has_any_target()
    {
      bail!(
        "at least one route, SNI forwarding rule/default target, stream listener, or WebRTC TURN listener must be configured"
      );
    }

    self.database.validate()?;
    self.shared_state.validate()?;
    self.validate_external_auth()?;
    self.validate_mitigation_database()?;

    let mut upstream_names = HashSet::new();
    for upstream in &self.upstreams {
      let mut svcb_ports = HashSet::new();
      for port in &upstream.svcb_allowed_ports {
        if *port == 0 || !svcb_ports.insert(*port) {
          bail!(
            "upstream {} svcb_allowed_ports must contain unique nonzero ports",
            upstream.name
          );
        }
      }
      if upstream.name.trim().is_empty() {
        bail!("upstream name must not be empty");
      }
      if !upstream_names.insert(upstream.name.clone()) {
        bail!("duplicate upstream name: {}", upstream.name);
      }

      if upstream.origin.scheme() != "http" && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use http:// or https:// origin, got {}",
          upstream.name,
          upstream.origin
        );
      }

      if upstream.max_http_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use https:// origin when max_http_version = \"h3\"",
          upstream.name
        );
      }
      if upstream.max_http_version == HttpVersion::H3
        && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        bail!(
          "upstream {} cannot enable proxy_protocol_egress with max_http_version = \"h3\"",
          upstream.name
        );
      }

      upstream.tls.validate(&upstream.name)?;
      if upstream.connect_timeout_ms == 0
        || upstream.request_timeout_ms == 0
        || upstream.first_byte_timeout_ms == 0
        || upstream.read_timeout_ms == 0
        || upstream.send_timeout_ms == 0
        || upstream.idle_timeout_ms == 0
      {
        bail!(
          "upstream {} timeout values must be greater than 0",
          upstream.name
        );
      }
    }

    let discovery_instance_total =
      self
        .upstream_pools
        .iter()
        .try_fold(0_usize, |total, pool| {
          total.checked_add(pool.discovery.len()).ok_or_else(|| {
            anyhow::anyhow!("upstream discovery instance count cannot be represented safely")
          })
        })?;
    if discovery_instance_total > upstream_pool::MAX_DISCOVERY_INSTANCES_TOTAL {
      bail!(
        "configuration has {discovery_instance_total} upstream discovery instances; maximum is {}",
        upstream_pool::MAX_DISCOVERY_INSTANCES_TOTAL
      );
    }

    let mut pool_names = HashSet::new();
    for pool in &self.upstream_pools {
      if pool.name.trim().is_empty() {
        bail!("upstream pool name must not be empty");
      }
      if !pool_names.insert(pool.name.clone()) {
        bail!("duplicate upstream pool name: {}", pool.name);
      }
      if pool.algorithm == LoadBalancingAlgorithm::StickyCookie {
        upstream_pool::validate_sticky_cookie_pool(pool)?;
      }
      if pool.servers.is_empty() && pool.discovery.is_empty() {
        bail!(
          "upstream pool {} must define at least one server or discovery provider",
          pool.name
        );
      }
      if pool.keepalive.idle_timeout_ms == 0 || pool.keepalive.max_lifetime_ms == 0 {
        bail!(
          "upstream pool {} keepalive timeout values must be greater than 0",
          pool.name
        );
      }
      upstream_pool::validate_pool_policy(pool)?;
      if let Some(circuit_breaker) = &pool.circuit_breaker {
        circuit_breaker.validate(&format!("upstream_pools {} circuit_breaker", pool.name))?;
      }
      let mut server_ids = HashSet::new();
      for (index, server) in pool.servers.iter().enumerate() {
        let server_id = upstream_pool_server_id(index, server);
        validate_runtime_identifier(
          &format!("upstream pool {} server id", pool.name),
          &server_id,
        )?;
        if !server_ids.insert(server_id.clone()) {
          bail!(
            "upstream pool {} has duplicate server id {server_id}",
            pool.name
          );
        }
        if server.origin.scheme() != "http" && server.origin.scheme() != "https" {
          bail!(
            "upstream pool {} server origin must use http:// or https://, got {}",
            pool.name,
            server.origin
          );
        }
        server
          .tls
          .validate(&format!("{} server {server_id}", pool.name))?;
        if server.origin.scheme() == "http" && server.tls != UpstreamTlsConfig::default() {
          bail!(
            "upstream pool {} server {server_id} cannot configure tls for an http:// origin",
            pool.name
          );
        }
        if server.weight == 0 {
          bail!(
            "upstream pool {} server weight must be greater than 0",
            pool.name
          );
        }
      }
      upstream_pool::validate_pool_discovery(pool)?;
      upstream_pool::validate_pool_health_check(pool)?;
    }

    let turn_pool_names = self.validate_turn_forwarding()?;

    let compression_policy_names = self
      .compression
      .policies
      .iter()
      .map(|policy| policy.name.as_str())
      .collect::<HashSet<_>>();
    let security_header_policy_names = self
      .security
      .header_policies
      .iter()
      .map(|policy| policy.name.as_str())
      .collect::<HashSet<_>>();

    let mut route_names = HashSet::new();
    for route in &self.routes {
      if route.upstream_http_version_mode == UpstreamHttpVersionMode::Ceiling
        && route.upstream_http_version.is_none()
      {
        bail!(
          "route {} upstream_http_version_mode requires explicit upstream_http_version",
          route.name
        );
      }
      if route.name.trim().is_empty() {
        bail!("route name must not be empty");
      }
      if !route_names.insert(route.name.clone()) {
        bail!("duplicate route name: {}", route.name);
      }
      if route.hosts.is_empty() {
        bail!("route {} must have at least one host match", route.name);
      }
      route::validate_route_path_value(&route.name, "path_prefix", &route.path_prefix)?;
      route::validate_route_match_config(route)?;
      if let Some(replacement) = &route.replace_prefix_with {
        route::validate_route_path_value(&route.name, "replace_prefix_with", replacement)?;
      }
      route_actions::validate_route_actions_config(route)?;
      route_static_files::validate_route_static_files_config(&route.name, &route.static_files)?;
      let target_count = usize::from(route.upstream.is_some())
        + usize::from(route.upstream_pool.is_some())
        + usize::from(route.static_root.is_some())
        + usize::from(route.ct_log.is_some())
        + usize::from(route.actions.redirect.is_some());
      if target_count != 1 {
        bail!(
          "route {} must set exactly one of upstream, upstream_pool, static_root, ct_log, or actions.redirect",
          route.name
        );
      }
      if route.ct_log.is_none()
        && route.ct_surface != CertificateTransparencyRouteSurface::Submission
      {
        bail!("route {} cannot set ct_surface without ct_log", route.name);
      }
      if let Some(ct_log) = &route.ct_log {
        validate_runtime_identifier(&format!("route {} ct_log", route.name), ct_log)?;
        if !self.certificate_transparency.enabled {
          bail!(
            "route {} requires certificate_transparency.enabled = true",
            route.name
          );
        }
        let Some(log) = self.certificate_transparency.log(ct_log) else {
          bail!(
            "route {} references unknown certificate transparency log {}",
            route.name,
            ct_log
          );
        };
        if route.ct_surface == CertificateTransparencyRouteSurface::Monitoring
          && log.protocol != CertificateTransparencyProtocol::StaticRfc6962V1
        {
          bail!(
            "route {} monitoring ct_surface requires a static_rfc6962_v1 log",
            route.name
          );
        }
        if !route.waf.functions.is_empty()
          || !route.waf.rulepack_files.is_empty()
          || !route.waf.rule_group_files.is_empty()
          || !route.waf.rule_groups.is_empty()
          || !route.waf.rules.is_empty()
        {
          bail!(
            "route {} cannot set waf when ct_log is configured",
            route.name
          );
        }
        if route.cache.is_some() {
          bail!(
            "route {} cannot set cache when ct_log is configured",
            route.name
          );
        }
        if route.retry.is_some() {
          bail!(
            "route {} cannot set retry when ct_log is configured",
            route.name
          );
        }
        if route.actions.rewrite.is_some() || route.actions.response_headers.has_actions() {
          bail!(
            "route {} cannot set response rewriting when ct_log is configured",
            route.name
          );
        }
      }
      route_actions::validate_route_action_target_compatibility(route)?;
      route_actions::validate_route_action_pool_references(route, &pool_names)?;
      match (
        &route.upstream,
        &route.upstream_pool,
        &route.static_root,
        &route.actions.redirect,
      ) {
        (Some(upstream), None, None, None) if !upstream_names.contains(upstream) => {
          bail!(
            "route {} references unknown upstream {}",
            route.name,
            upstream
          );
        }
        (None, Some(pool), None, None) if !pool_names.contains(pool) => {
          bail!(
            "route {} references unknown upstream_pool {}",
            route.name,
            pool
          );
        }
        (Some(_), None, None, None) | (None, Some(_), None, None) => {}
        (None, None, Some(static_root), None) => {
          crate::config::validate_static_root(static_root)
            .with_context(|| format!("route {} static_root is invalid", route.name))?;
          if route.replace_prefix_with.is_some() {
            bail!(
              "route {} cannot set replace_prefix_with when static_root is configured",
              route.name
            );
          }
          if route.cache.is_some() {
            bail!(
              "route {} cannot set cache when static_root is configured",
              route.name
            );
          }
          if route.upstream_http_version.is_some() {
            bail!(
              "route {} cannot set upstream_http_version when static_root is configured",
              route.name
            );
          }
          if route.generic_http_upgrade || route.connect_tunneling || route.grpc_web {
            bail!(
              "route {} cannot enable upstream-only route features when static_root is configured",
              route.name
            );
          }
        }
        (None, None, None, Some(_)) => {}
        _ => {}
      }
      if route.static_root.is_none() && route.static_files.has_convenience_options() {
        bail!(
          "route {} cannot set static_files options without static_root",
          route.name
        );
      }
      if let Some(cache) = &route.cache
        && cache != "default"
        && !self
          .cache
          .policies
          .iter()
          .any(|policy| policy.name == *cache)
      {
        bail!("route {} references unknown cache {}", route.name, cache);
      }
      if let Some(compression) = &route.compression
        && compression != "default"
        && compression != "off"
        && !compression_policy_names.contains(compression.as_str())
      {
        bail!(
          "route {} references unknown compression policy {}",
          route.name,
          compression
        );
      }
      if let Some(security_headers) = &route.security_headers
        && security_headers != "default"
        && security_headers != "off"
        && !security_header_policy_names.contains(security_headers.as_str())
      {
        bail!(
          "route {} references unknown security header policy {}",
          route.name,
          security_headers
        );
      }
      if let Some(external_auth) = &route.external_auth {
        let Some(auth_config) = self
          .external_auth
          .iter()
          .find(|config| config.name == *external_auth)
        else {
          bail!(
            "route {} references unknown external_auth {}",
            route.name,
            external_auth
          );
        };
        route_actions::validate_route_external_auth_identity_header_conflicts(
          route,
          &auth_config.identity_headers,
        )?;
      }
      if route.grpc_web && !self.proxy.grpc_web.enabled {
        bail!(
          "route {} enables grpc_web but proxy.grpc_web.enabled is false",
          route.name
        );
      }
      if route.generic_http_upgrade && !self.proxy.upgrades.generic_http_upgrade {
        bail!(
          "route {} enables generic_http_upgrade but proxy.upgrades.generic_http_upgrade is false",
          route.name
        );
      }
      if route.connect_tunneling && !self.proxy.upgrades.connect_tunneling {
        bail!(
          "route {} enables connect_tunneling but proxy.upgrades.connect_tunneling is false",
          route.name
        );
      }
      if let Some(route_version) = route.upstream_http_version {
        match (&route.upstream, &route.upstream_pool) {
          (Some(upstream_name), None) => {
            let Some(upstream) = self
              .upstreams
              .iter()
              .find(|item| item.name == *upstream_name)
            else {
              bail!(
                "route {} references unknown upstream {upstream_name}",
                route.name
              );
            };
            if route_version > upstream.max_http_version {
              bail!(
                "route {} upstream_http_version cannot exceed upstream {} max_http_version",
                route.name,
                upstream.name
              );
            }
            if route_version == HttpVersion::H3
              && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
            {
              bail!(
                "route {} cannot select HTTP/3 when upstream {} has proxy_protocol_egress enabled",
                route.name,
                upstream.name
              );
            }
          }
          (None, Some(_)) if route_version == HttpVersion::H3 => {
            bail!(
              "route {} cannot set upstream_http_version = \"h3\" for upstream_pool routes",
              route.name
            );
          }
          _ => {}
        }
      }
      route.timeouts.validate(&route.name)?;
      route.limits.validate(&route.name)?;
      route.ipm.validate(&route.name)?;
      if let Some(retry) = &route.retry {
        retry.validate(&route.name)?;
        let backoff_base = retry
          .backoff_base_ms
          .unwrap_or(self.proxy.retry.backoff_base_ms);
        let backoff_max = retry
          .backoff_max_ms
          .unwrap_or(self.proxy.retry.backoff_max_ms);
        if backoff_max > 0 && backoff_base > backoff_max {
          bail!(
            "route {} retry.backoff_max_ms must be 0 or greater than or equal to effective retry.backoff_base_ms",
            route.name
          );
        }
      }
      if let Some(circuit_breaker) = &route.circuit_breaker {
        circuit_breaker.validate(&format!("route {} circuit_breaker", route.name))?;
      }
    }
    route::validate_route_match_conflicts(&self.routes)?;

    self.validate_dynamic_policy(&route_names)?;
    self.validate_stream_upstream_pools()?;
    self.validate_stream_listeners()?;
    self.validate_webrtc_turn_listeners(&turn_pool_names)?;

    validate_ocsp_config("tls.ocsp", &self.tls.ocsp)?;
    self.tls.crlite.validate()?;
    self.client_identity.validate()?;
    crate::waf::validate_config(self)?;
    operational_profile::validate(self)?;

    Ok(())
  }

  /// Validates common semantics and rejects capabilities absent from the selected artifact.
  pub fn validate_for_artifact(&self, artifact: RuntimeArtifact) -> anyhow::Result<()> {
    self.validate_artifact_constraints(artifact)?;
    self.validate_common()
  }

  fn validate_artifact_constraints(&self, artifact: RuntimeArtifact) -> anyhow::Result<()> {
    if artifact == RuntimeArtifact::Standalone {
      return Ok(());
    }

    let defaults = AdminConfig::default();
    let mut configured = Vec::new();
    if self.admin.enabled {
      configured.push("admin.enabled");
    }
    if self.admin.bind != defaults.bind {
      configured.push("admin.bind");
    }
    if self.admin.bearer_token_env != defaults.bearer_token_env {
      configured.push("admin.bearer_token_env");
    }
    if self.admin.transport != defaults.transport {
      configured.push("admin.transport");
    }
    if self.admin.allow_insecure_plaintext != defaults.allow_insecure_plaintext {
      configured.push("admin.allow_insecure_plaintext");
    }
    if self.admin.plaintext_allowed_source_cidrs != defaults.plaintext_allowed_source_cidrs {
      configured.push("admin.plaintext_allowed_source_cidrs");
    }
    if self.admin.cache_purge_signing != defaults.cache_purge_signing {
      configured.push("admin.cache_purge_signing");
    }
    if self.admin.workload_identity != defaults.workload_identity {
      configured.push("admin.workload_identity");
    }
    if self.admin.audit != defaults.audit {
      configured.push("admin.audit");
    }
    if self.admin.operations != defaults.operations {
      configured.push("admin.operations");
    }
    if self.admin.mutations != defaults.mutations {
      configured.push("admin.mutations");
    }
    if self.admin.http3 != defaults.http3 {
      configured.push("admin.http3");
    }
    if self.admin.tls != defaults.tls {
      configured.push("admin.tls");
    }
    if self.admin.legacy_rbac.is_some() {
      configured.push("admin.rbac");
    }
    if self.admin.legacy_token_store.is_some() {
      configured.push("admin.token_store");
    }
    if self.runtime.hardening.seccomp.expectation != RuntimeSeccompExpectation::Required {
      configured.push("runtime.hardening.seccomp.expectation");
    }
    if !configured.is_empty() {
      bail!(
        "strict data-plane artifact requires disabled Admin capabilities and runtime.hardening.seccomp.expectation = \"required\": {}",
        configured.join(", ")
      );
    }
    Ok(())
  }
}
