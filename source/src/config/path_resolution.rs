//! Configuration-owned path resolution and external WAF source assembly.

use super::*;

impl Config {
  pub(super) fn resolve_relative_paths(
    &mut self,
    path_roots: &ConfigPathRoots,
  ) -> anyhow::Result<()> {
    self.source_paths.config_dir = Some(path_roots.config_dir.clone());
    self.source_paths.cert_dir = Some(path_roots.cert_dir.clone());
    self.source_paths.oxirule_dir = Some(path_roots.oxirule_dir.clone());
    self.resolve_admin_mutation_signer_paths(&path_roots.config_dir)?;
    self.resolve_admin_audit_anchor_paths(&path_roots.cert_dir)?;
    let (tls_cert_chain, tls_cert_chain_logical) =
      resolve_existing_local_config_file_path_with_logical(
        "tls.cert_chain",
        &path_roots.cert_dir,
        &self.tls.cert_chain,
      )?;
    self.tls.cert_chain = tls_cert_chain;
    self
      .source_paths
      .remember_runtime_file(tls_cert_chain_logical.clone());
    self
      .source_paths
      .remember_downstream_tls_file(tls_cert_chain_logical.clone());
    self.source_paths.downstream_tls_cert_chain = Some(tls_cert_chain_logical);

    if let Some(private_key) = self.tls.private_key.take() {
      let (tls_private_key, tls_private_key_logical) =
        resolve_existing_local_config_file_path_with_logical(
          "tls.private_key",
          &path_roots.cert_dir,
          &private_key,
        )?;
      self.tls.private_key = Some(tls_private_key);
      self
        .source_paths
        .remember_runtime_file(tls_private_key_logical.clone());
      self
        .source_paths
        .remember_downstream_tls_file(tls_private_key_logical.clone());
      self.source_paths.downstream_tls_private_key = Some(tls_private_key_logical);
    }

    self.source_paths.downstream_tls_certificates.clear();
    for (index, certificate) in self.tls.certificates.iter_mut().enumerate() {
      let (cert_chain, cert_logical) = resolve_existing_local_config_file_path_with_logical(
        &format!("tls.certificates[{index}].cert_chain"),
        &path_roots.cert_dir,
        &certificate.cert_chain,
      )?;
      certificate.cert_chain = cert_chain;
      self
        .source_paths
        .remember_runtime_file(cert_logical.clone());
      self
        .source_paths
        .remember_downstream_tls_file(cert_logical.clone());

      let private_key_logical = certificate
        .private_key
        .take()
        .map(|private_key| {
          let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
            &format!("tls.certificates[{index}].private_key"),
            &path_roots.cert_dir,
            &private_key,
          )?;
          certificate.private_key = Some(resolved);
          self.source_paths.remember_runtime_file(logical.clone());
          self
            .source_paths
            .remember_downstream_tls_file(logical.clone());
          Ok::<PathBuf, anyhow::Error>(logical)
        })
        .transpose()?;

      let ocsp_response_logical = certificate
        .ocsp
        .response_file
        .take()
        .map(|response_file| {
          let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
            &format!("tls.certificates[{index}].ocsp.response_file"),
            &path_roots.cert_dir,
            &response_file,
          )?;
          certificate.ocsp.response_file = Some(resolved);
          self.source_paths.remember_runtime_file(logical.clone());
          self
            .source_paths
            .remember_downstream_tls_file(logical.clone());
          Ok::<PathBuf, anyhow::Error>(logical)
        })
        .transpose()?;

      self
        .source_paths
        .downstream_tls_certificates
        .push(DownstreamTlsCertificateSourcePaths {
          cert_chain: cert_logical,
          private_key: private_key_logical,
          ocsp_response_file: ocsp_response_logical,
        });
    }

    self.tls.remote_signer.token_file = self
      .tls
      .remote_signer
      .token_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.remote_signer.token_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.tls.remote_signer.token_file_reload_path = Some(logical.clone());
        self.tls.remote_signer.token_file_reload_base_dir = Some(path_roots.cert_dir.clone());
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.downstream_tls_remote_signer_token_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;

    self.tls.ocsp.response_file = self
      .tls
      .ocsp
      .response_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.ocsp.response_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.downstream_tls_ocsp_response_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    crlite::resolve_filter_file(
      &mut self.tls.crlite,
      &mut self.source_paths,
      &path_roots.cert_dir,
    )?;
    client_identity::resolve_asn_database_file(
      &mut self.client_identity.asn,
      &mut self.source_paths,
      &path_roots.config_dir,
    )?;
    self.tls.client_auth.ca_certs = self
      .tls
      .client_auth
      .ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.client_auth.ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self.source_paths.remember_downstream_tls_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.proxy.trusted_ca_certs = self
      .proxy
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "proxy.trusted_ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.access_log.otlp.trusted_ca_certs = self
      .access_log
      .otlp
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "access_log.otlp.trusted_ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    outbound_revocation::resolve_outbound_crlite_filter_file(
      &mut self.proxy.upstream_revocation,
      &mut self.source_paths,
      &path_roots.cert_dir,
      "proxy.upstream_revocation.crlite.filter_file",
    )?;
    self.quic.host_key_file = self
      .quic
      .host_key_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "quic.host_key_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.quic_host_key_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    for upstream in &mut self.upstreams {
      for path in upstream.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path);
      }
      if let Some(revocation) = &mut upstream.tls.upstream_revocation {
        outbound_revocation::resolve_outbound_crlite_filter_file(
          revocation,
          &mut self.source_paths,
          &path_roots.cert_dir,
          "upstreams.tls.upstream_revocation.crlite.filter_file",
        )?;
      }
    }
    for path in self
      .database
      .mitigation
      .tls
      .resolve_relative_paths("database.mitigation.tls", &path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    for backend in &mut self.shared_state.backends {
      for path in backend.tls.resolve_relative_paths(
        &format!("shared_state.backends.{}.tls", backend.name),
        &path_roots.cert_dir,
      )? {
        self.source_paths.remember_runtime_file(path);
      }
      for path in backend.redis_tls.resolve_relative_paths(
        &format!("shared_state.backends.{}.redis_tls", backend.name),
        &path_roots.cert_dir,
      )? {
        self.source_paths.remember_runtime_file(path);
      }
      for path in backend.redis_auth.resolve_relative_paths(
        &format!("shared_state.backends.{}.redis_auth", backend.name),
        &path_roots.cert_dir,
      )? {
        self.source_paths.remember_runtime_file(path);
      }
    }
    for pool in &mut self.upstream_pools {
      for path in pool.resolve_discovery_paths(&path_roots.config_dir)? {
        self.source_paths.remember_discovery_file(path);
      }
      for path in pool.resolve_tls_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path);
      }
      pool.resolve_health_check_paths(&path_roots.cert_dir, &mut self.source_paths)?;
    }
    for listener in &mut self.webrtc_turn_listeners {
      for path in listener.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path.clone());
        self.source_paths.remember_downstream_tls_file(path);
      }
    }
    for path in self
      .admin
      .tls
      .resolve_relative_paths(&path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    self.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    for route in &mut self.routes {
      if let Some(static_root) = route.static_root.as_ref() {
        let resolved = if static_root.is_absolute() {
          static_root.clone()
        } else {
          validate_relative_path("routes.static_root", static_root)?;
          path_roots.config_dir.join(static_root)
        };
        route.static_root = Some(crate::config::validate_static_root(&resolved)?);
      }
      route.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    }
    Ok(())
  }

  pub(super) fn load_external_waf_rules(&mut self) -> anyhow::Result<()> {
    self.waf.load_external_rules()?;
    for route in &mut self.routes {
      route.waf.load_external_rules()?;
    }
    Ok(())
  }

  pub(super) fn normalize_loaded_waf_lb_policy_compat(&mut self) -> anyhow::Result<()> {
    let profile = self.config.lb_policy_compat_profile;
    let mut diagnostics = self
      .waf
      .normalize_lb_policy_compat(profile, "waf".to_string());
    for (route_index, route) in self.routes.iter_mut().enumerate() {
      diagnostics.extend(
        route
          .waf
          .normalize_lb_policy_compat(profile, format!("routes[{route_index}].waf")),
      );
    }
    lb_policy_compat::ensure_supported(&diagnostics)
  }

  pub(super) fn collect_loaded_waf_rule_paths(&mut self) {
    for path in self.waf.loaded_rule_paths() {
      self.source_paths.remember_oxirule_file(path);
    }
    for route in &self.routes {
      for path in route.waf.loaded_rule_paths() {
        self.source_paths.remember_oxirule_file(path);
      }
    }
  }
}
