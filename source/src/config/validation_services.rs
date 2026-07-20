//! Admin, observability, listener, HTTP/3, and TLS validation.

use super::*;

impl Config {
  pub(super) fn validate_admin(&self) -> anyhow::Result<()> {
    self.validate_legacy_admin_authorization()?;
    self.validate_admin_audit_config_fields()?;
    self.validate_admin_operations_config()?;
    if self.admin.audit.queue_capacity == 0 {
      bail!("admin.audit.queue_capacity must be greater than 0");
    }
    if !self.admin.enabled {
      if self.admin.audit.enabled {
        bail!("admin.audit.enabled requires admin.enabled = true");
      }
      if self.admin.http3.enabled {
        bail!("admin.http3.enabled requires admin.enabled = true");
      }
      if self.admin.workload_identity.enabled {
        bail!("admin.workload_identity.enabled requires admin.enabled = true");
      }
      return Ok(());
    }
    self.validate_admin_privileged_ports()?;
    self.validate_admin_audit_runtime()?;
    if !self.ipm.enabled {
      if self.admin.bearer_token_env.trim().is_empty() {
        bail!("admin.bearer_token_env must not be empty when admin is enabled");
      }
      if std::env::var(&self.admin.bearer_token_env)
        .ok()
        .is_none_or(|token| token.is_empty())
      {
        bail!(
          "admin bearer token environment variable {} must be set and non-empty",
          self.admin.bearer_token_env
        );
      }
    }
    for cidr in &self.admin.plaintext_allowed_source_cidrs {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid admin.plaintext_allowed_source_cidrs entry {cidr}"))?;
    }
    if self.admin.cache_purge_signing.enabled {
      validate_base64_32_byte_env(
        "admin.cache_purge_signing.key_env",
        &self.admin.cache_purge_signing.key_env,
      )?;
      if self.admin.cache_purge_signing.max_skew_seconds == 0 {
        bail!("admin.cache_purge_signing.max_skew_seconds must be greater than 0");
      }
      if self.admin.cache_purge_signing.nonce_ttl_seconds == 0 {
        bail!("admin.cache_purge_signing.nonce_ttl_seconds must be greater than 0");
      }
    }
    if self.admin.transport == AdminTransportMode::Plaintext && !self.admin.allow_insecure_plaintext
    {
      bail!("admin.allow_insecure_plaintext must be true when admin.transport = \"plaintext\"");
    }
    if matches!(
      self.admin.transport,
      AdminTransportMode::Auto | AdminTransportMode::Tls
    ) && !self.admin.bind.ip().is_loopback()
      && !self.admin.tls.enabled
    {
      bail!(
        "admin.tls.enabled must be true for non-loopback admin.bind when admin.transport requires TLS"
      );
    }
    if self.admin.http3.enabled {
      if !self.admin.tls.enabled {
        bail!("admin.http3.enabled requires admin.tls.enabled = true");
      }
      if self.admin.tls.max_version != TlsVersion::Tls13 {
        bail!("admin.http3.enabled requires admin.tls.max_version to allow tls1.3");
      }
    }
    self.admin.tls.validate()?;
    self.validate_admin_workload_identity()
  }

  pub(super) fn validate_metrics_and_health(&self) -> anyhow::Result<()> {
    self.validate_ops_privileged_ports()?;
    if self.metrics.histogram_buckets_ms.is_empty() {
      bail!("metrics.histogram_buckets_ms must not be empty");
    }
    let mut previous = 0;
    for bucket in &self.metrics.histogram_buckets_ms {
      if *bucket == 0 {
        bail!("metrics.histogram_buckets_ms values must be greater than 0");
      }
      if *bucket <= previous {
        bail!("metrics.histogram_buckets_ms values must be strictly increasing");
      }
      previous = *bucket;
    }
    if !self.health.ready_path.starts_with('/') || !self.health.live_path.starts_with('/') {
      bail!("health ready_path and live_path must start with '/'");
    }
    Ok(())
  }

  pub(super) fn validate_listener_binds(&self) -> anyhow::Result<()> {
    validate_bind_list("listeners.https_binds", &self.listeners.https_binds)?;
    if self.listeners.http_mode != HttpListenerMode::Off || !self.listeners.http_binds.is_empty() {
      validate_bind_list("listeners.http_binds", &self.listeners.http_binds)?;
    }
    if self.rejects_privileged_data_plane_ports() {
      for bind in &self.listeners.https_binds {
        if self.rejects_privileged_data_plane_bind(*bind) {
          bail!(
            "listeners.https_binds entry {} requires a privileged port but unprivileged_mode=true",
            bind
          );
        }
      }
      for bind in &self.listeners.http_binds {
        if self.rejects_privileged_data_plane_bind(*bind) {
          bail!(
            "listeners.http_binds entry {} requires a privileged port but unprivileged_mode=true",
            bind
          );
        }
      }
    }
    if self.needs_https_listener() && self.listeners.http_mode != HttpListenerMode::Off {
      validate_bind_lists_do_not_overlap(
        "listeners.https_binds",
        &self.listeners.https_binds,
        "listeners.http_binds",
        &self.listeners.http_binds,
      )?;
    }
    Ok(())
  }

  pub(super) fn validate_http3_alt_svc_binds(&self) -> anyhow::Result<()> {
    if !self.listeners.http3 || !self.quic.alt_svc.enabled {
      return Ok(());
    }
    let mut override_binds = HashSet::new();
    for port_override in &self.quic.alt_svc.port_overrides {
      if port_override.advertised_port == 0 {
        bail!("quic.alt_svc.port_overrides advertised_port must be greater than 0");
      }
      if !override_binds.insert(port_override.bind) {
        bail!(
          "quic.alt_svc.port_overrides contains duplicate bind {}",
          port_override.bind
        );
      }
      if !self.listeners.https_binds.contains(&port_override.bind) {
        bail!(
          "quic.alt_svc.port_overrides bind {} must match a listeners.https_binds entry",
          port_override.bind
        );
      }
    }
    if !self.quic.alt_svc.port_overrides.is_empty() {
      return Ok(());
    }
    let Some(first) = self.listeners.https_binds.first() else {
      return Ok(());
    };
    let port = first.port();
    if self
      .listeners
      .https_binds
      .iter()
      .any(|bind| bind.port() != port)
    {
      bail!(
        "listeners.https_binds entries must use the same port when listeners.http3 and quic.alt_svc.enabled are true"
      );
    }
    Ok(())
  }

  pub(super) fn validate_tls(&self) -> anyhow::Result<()> {
    if self.tls.min_version > self.tls.max_version {
      bail!("tls.min_version must be less than or equal to tls.max_version");
    }
    if self.tls.session_ticket_rotation_seconds == 0 {
      bail!("tls.session_ticket_rotation_seconds must be greater than 0");
    }
    tls::validate_tls_negotiation(&self.tls)?;
    route_tls_policy::validate_negotiation_policies(self)?;
    validate_tls_server_resumption("tls.resumption", &self.tls.resumption)?;
    let multi_certificate = !self.tls.certificates.is_empty();
    let multi_certificate_partitioned =
      self.tls.resumption.multi_certificate == TlsMultiCertificateResumptionMode::PartitionBySni;
    let tcp_early_data_enabled = self.downstream_tcp_early_data_enabled();
    if multi_certificate {
      let unsafe_multi_cert_resumption = self.tls.resumption.mode != TlsServerResumptionMode::Off
        || self.quic.zero_rtt != QuicZeroRttMode::Off
        || tcp_early_data_enabled;
      if unsafe_multi_cert_resumption && !multi_certificate_partitioned {
        bail!(
          "tls.resumption.multi_certificate = \"partition_by_sni\" is required when tls.certificates is configured with resumption, quic.zero_rtt, or ssl_early_data"
        );
      }
      if multi_certificate_partitioned && !self.tls.require_sni {
        bail!(
          "tls.require_sni must be true when tls.resumption.multi_certificate = \"partition_by_sni\""
        );
      }
      if multi_certificate_partitioned && !self.tls.reject_unknown_sni {
        bail!(
          "tls.reject_unknown_sni must be true when tls.resumption.multi_certificate = \"partition_by_sni\""
        );
      }
    }
    if tcp_early_data_enabled && self.tls.max_version < TlsVersion::Tls13 {
      bail!("tls.ssl_early_data requires tls.max_version to allow tls1.3");
    }
    if tcp_early_data_enabled && self.tls.resumption.mode != TlsServerResumptionMode::Stateful {
      bail!("tls.ssl_early_data requires tls.resumption.mode = \"stateful\"");
    }
    if self.listeners.http3
      && self.quic.zero_rtt == QuicZeroRttMode::SafeMethods
      && self.tls.resumption.mode == TlsServerResumptionMode::Stateless
    {
      bail!(
        "tls.resumption.mode = \"stateless\" cannot be used with quic.zero_rtt = \"safe_methods\""
      );
    }
    if self.tls.remote_signer.enabled {
      if self.tls.private_key.is_some() {
        bail!("tls.private_key must not be set when tls.remote_signer.enabled = true");
      }
      self.tls.remote_signer.validate("tls.remote_signer")?;
      if self.downstream_tls12_allowed() && !self.tls.remote_signer.allow_tls12_unstructured_signing
      {
        bail!(
          "tls.remote_signer.allow_tls12_unstructured_signing must be true when remote signing is enabled with any downstream TLS policy that allows tls1.2"
        );
      }
    } else if self.tls.private_key.is_none() {
      bail!("tls.private_key is required unless tls.remote_signer.enabled = true");
    }
    let mut server_names = HashSet::new();
    for name in &self.tls.server_names {
      validate_tls_server_name("tls.server_names", name)?;
      if !server_names.insert(name.to_ascii_lowercase()) {
        bail!("duplicate tls server_name {name}");
      }
    }
    for (index, certificate) in self.tls.certificates.iter().enumerate() {
      if certificate.server_names.is_empty() {
        bail!("tls.certificates[{index}].server_names must not be empty");
      }
      for name in &certificate.server_names {
        validate_tls_server_name("tls.certificates.server_names", name)?;
        if !server_names.insert(name.to_ascii_lowercase()) {
          bail!("duplicate tls certificate server_name {name}");
        }
      }
      if self.tls.remote_signer.enabled {
        if certificate.private_key.is_some() {
          bail!(
            "tls.certificates[{index}].private_key must not be set when tls.remote_signer.enabled = true"
          );
        }
        match certificate.remote_signer_key_id.as_deref() {
          Some(key_id) if !key_id.trim().is_empty() => {}
          _ => bail!(
            "tls.certificates[{index}].remote_signer_key_id is required when tls.remote_signer.enabled = true"
          ),
        }
      } else {
        if certificate.remote_signer_key_id.is_some() {
          bail!(
            "tls.certificates[{index}].remote_signer_key_id requires tls.remote_signer.enabled = true"
          );
        }
        if certificate.private_key.is_none() {
          bail!(
            "tls.certificates[{index}].private_key is required unless tls.remote_signer.enabled = true"
          );
        }
      }
      validate_ocsp_config(
        &format!("tls.certificates[{index}].ocsp"),
        &certificate.ocsp,
      )?;
    }
    if self.listeners.http3 && self.tls.min_version != TlsVersion::Tls13 {
      bail!("HTTP/3 requires tls.min_version = \"tls1.3\"");
    }
    self.tls.client_auth.validate("tls.client_auth")?;
    for listener in &self.webrtc_turn_listeners {
      if listener.tls.remote_signer_key_id.is_some() && !self.tls.remote_signer.enabled {
        bail!(
          "WebRTC TURN listener {} tls.remote_signer_key_id requires tls.remote_signer.enabled = true",
          listener.name
        );
      }
      if let Some(resumption) = &listener.tls.resumption {
        validate_tls_server_resumption(
          &format!("webrtc_turn_listeners.{}.tls.resumption", listener.name),
          resumption,
        )?;
      }
    }
    Ok(())
  }
}
