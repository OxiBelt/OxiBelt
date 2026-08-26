use crate::config::Config;
use crate::stream::pools::StreamPoolState;

use super::AppSnapshot;

impl AppSnapshot {
  pub async fn new_with_updated_stream_pools(
    config: Config,
    previous: &AppSnapshot,
  ) -> anyhow::Result<Self> {
    let hardening = previous.admitted_reload_hardening(&config)?;
    let stream_pool_generation = next_stream_pool_generation(&config, Some(previous));
    let stream_pools = StreamPoolState::new(&config.stream_upstream_pools);
    let circuit_breakers = previous.circuit_breakers.clone();
    circuit_breakers.configure(&config);
    let runtime_health = previous.runtime_health.clone();
    let runtime_generation = runtime_health.allocate_generation();
    let (hardening_state, readiness_critical) = match hardening.outcome {
      crate::hardening::RuntimeHardeningOutcome::Satisfied => {
        (crate::runtime_health::RuntimeSubsystemState::Healthy, false)
      }
      crate::hardening::RuntimeHardeningOutcome::Degraded => (
        crate::runtime_health::RuntimeSubsystemState::Degraded,
        false,
      ),
      crate::hardening::RuntimeHardeningOutcome::Blocked => {
        (crate::runtime_health::RuntimeSubsystemState::Failed, true)
      }
    };
    runtime_health.set_subsystem_state(
      runtime_generation,
      crate::runtime_health::RuntimeSubsystem::Hardening,
      hardening_state,
      readiness_critical,
    );

    Ok(Self {
      config,
      runtime_topology: previous.runtime_topology.clone(),
      hardening,
      secret_references: previous.secret_references.clone(),
      effective_direct_h1_io: previous.effective_direct_h1_io,
      route_table: previous.route_table.clone(),
      sni_forward: previous.sni_forward.clone(),
      upstreams: previous.upstreams.clone(),
      upstream_uri_parts: previous.upstream_uri_parts.clone(),
      upstream_uri_parts_by_index: previous.upstream_uri_parts_by_index.clone(),
      compiled_fast_path_actions: previous.compiled_fast_path_actions.clone(),
      clients: previous.clients.clone(),
      direct_h1_pools: previous.direct_h1_pools.clone(),
      direct_h2_pools: previous.direct_h2_pools.clone(),
      health_check_clients: previous.health_check_clients.clone(),
      control_http: previous.control_http.clone(),
      h3_clients: previous.h3_clients.clone(),
      outbound_revocation: previous.outbound_revocation.clone(),
      compio_direct_h1_budget: previous.compio_direct_h1_budget,
      compio_direct_h1_overlap_budget: previous.compio_direct_h1_overlap_budget.clone(),
      direct_h1_plan_generation: previous.direct_h1_plan_generation,
      compio_direct_h1_service: previous.compio_direct_h1_service.clone(),
      staged_compio_direct_h1_service: None,
      compio_direct_h1_fleet_reservation: previous.compio_direct_h1_fleet_reservation.clone(),
      upstream_pool_generation: previous.upstream_pool_generation,
      stream_pool_generation,
      limits: previous.limits.clone(),
      pools: previous.pools.clone(),
      stream_pools,
      turn_pools: previous.turn_pools.clone(),
      cache: previous.cache.clone(),
      compression: previous.compression.clone(),
      waf_body_coding: previous.waf_body_coding.clone(),
      static_files: previous.static_files.clone(),
      certificate_transparency: previous.certificate_transparency.clone(),
      metrics: previous.metrics.clone(),
      overload: previous.overload.clone(),
      circuit_breakers,
      telemetry: previous.telemetry.clone(),
      ipm: previous.ipm.clone(),
      dynamic_policy: previous.dynamic_policy.clone(),
      external_auth: previous.external_auth.clone(),
      client_identity: previous.client_identity.clone(),
      runtime_introspection: previous.runtime_introspection.clone(),
      #[cfg(feature = "admin-runtime")]
      webtransport_admin: previous.webtransport_admin.clone(),
      lifecycle: previous.lifecycle.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_audit: previous.admin_audit.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_mutations: previous.admin_mutations.clone(),
      shared_state: previous.shared_state.clone(),
      crlite: previous.crlite.clone(),
      downstream_ct: previous.downstream_ct.clone(),
      ocsp_staple: previous.ocsp_staple.clone(),
      tls_server_config: previous.tls_server_config.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_tls_server_config: previous.admin_tls_server_config.clone(),
      quic_server_config: previous.quic_server_config.clone(),
      #[cfg(feature = "admin-runtime")]
      admin_quic_server_config: previous.admin_quic_server_config.clone(),
      tls_resumption: previous.tls_resumption.clone(),
      waf: previous.waf.clone(),
      mitigation: previous.mitigation.clone(),
      access_logs: previous.access_logs.clone(),
      system_access_log: previous.system_access_log.clone(),
      runtime_health,
      runtime_generation,
      request_path_features: previous.request_path_features,
      alt_svc_header_values: previous.alt_svc_header_values.clone(),
      http1_upgrades_possible: previous.http1_upgrades_possible,
    })
  }
}

pub(super) fn next_stream_pool_generation(config: &Config, previous: Option<&AppSnapshot>) -> u64 {
  let Some(previous) = previous else {
    return 0;
  };
  if config.stream_upstream_pools == previous.config.stream_upstream_pools {
    previous.stream_pool_generation
  } else {
    previous.stream_pool_generation.saturating_add(1)
  }
}
