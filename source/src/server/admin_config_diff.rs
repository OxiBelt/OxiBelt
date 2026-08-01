//! Online activation-plan enrichment from active runtime configuration.
//!
//! This module is deliberately pure: it compares resolved configuration and
//! bounded runtime metadata, but never prepares listeners or sends an Admin
//! control command.

use std::collections::{BTreeMap, BTreeSet};

use crate::activation_plan::{
  ActivationPrerequisite, ActivationPrerequisiteStatus, ActivationReasonCode,
  ConfigActivationReport, ConfinementDifference, ConfinementDifferenceKind, ConfinementFit,
  ConnectionEffect, DeploymentMode, MAX_CONFINEMENT_DIFFERENCES, PrerequisiteAvailability,
  ResolvedActivationOperation, RollbackKind,
};
use crate::config::{Config, HttpListenerMode, RuntimeLandlockMode, StreamNetwork};
use crate::filesystem_access::{FilesystemAccessFindingCode, FilesystemAccessManifest};
use crate::hardening::{
  LandlockEnforcementState, RuntimeHardeningSnapshot, SeccompVerificationState,
};
use crate::reload::{
  FullReloadCompatibility, FullReloadRestartReason, classify_full_reload_runtime_compatibility,
};

use super::admin_auth::AdminAuthorization;

pub(super) fn enrich_activation_plan(
  report: &mut ConfigActivationReport,
  active: &Config,
  candidate: &Config,
  hardening: Option<&RuntimeHardeningSnapshot>,
  authorization: &AdminAuthorization<'_>,
) {
  resolve_runtime_compatibility(report, active, candidate);
  select_online_config_load_operation(report);
  resolve_listener_transition(report, active, candidate);
  resolve_confinement(report, active, candidate, hardening);
  resolve_deployment(report, active, candidate, authorization);
  resolve_connection_impact(report, active);
  normalize_plan(report);
}

fn select_online_config_load_operation(report: &mut ConfigActivationReport) {
  if report.changes.is_empty()
    || report.activation_plan.selected_operation.strength()
      >= ResolvedActivationOperation::FullSnapshotReload.strength()
  {
    return;
  }
  report.activation_plan.selected_operation = ResolvedActivationOperation::FullSnapshotReload;
  if !report
    .activation_plan
    .reason_codes
    .contains(&ActivationReasonCode::FullSnapshotReload)
  {
    report
      .activation_plan
      .reason_codes
      .push(ActivationReasonCode::FullSnapshotReload);
  }
}

fn resolve_runtime_compatibility(
  report: &mut ConfigActivationReport,
  active: &Config,
  candidate: &Config,
) {
  match classify_full_reload_runtime_compatibility(active, candidate) {
    FullReloadCompatibility::InProcess => {
      for change in &mut report.changes {
        if change
          .missing_prerequisites
          .contains(&ActivationPrerequisite::RuntimeCapabilityContext)
        {
          change
            .missing_prerequisites
            .retain(|item| *item != ActivationPrerequisite::RuntimeCapabilityContext);
          change.prerequisite_missing = !change.missing_prerequisites.is_empty();
          change.conditional = change.prerequisite_missing;
          change.reason_code = ActivationReasonCode::FullSnapshotReload;
        }
      }
      report
        .activation_plan
        .prerequisites
        .retain(|status| status.prerequisite != ActivationPrerequisite::RuntimeCapabilityContext);
    }
    FullReloadCompatibility::RestartRequired(reason) => {
      let code = match reason {
        FullReloadRestartReason::MainRuntime | FullReloadRestartReason::TokioWorkers => {
          ActivationReasonCode::RuntimeNotResizable
        }
        _ => ActivationReasonCode::StartupOnlySubsystem,
      };
      promote(report, ResolvedActivationOperation::ProcessRestart, code);
      for change in &mut report.changes {
        if change.resolved_operation == ResolvedActivationOperation::ProcessRestart
          || change
            .missing_prerequisites
            .contains(&ActivationPrerequisite::RuntimeCapabilityContext)
        {
          change.resolved_operation = ResolvedActivationOperation::ProcessRestart;
          change.reason_code = code;
          change.conditional = false;
          change
            .missing_prerequisites
            .retain(|item| *item != ActivationPrerequisite::RuntimeCapabilityContext);
          change.prerequisite_missing = !change.missing_prerequisites.is_empty();
          change.long_connections_affected = true;
        }
      }
    }
  }
}

fn resolve_listener_transition(
  report: &mut ConfigActivationReport,
  active: &Config,
  candidate: &Config,
) {
  let active_http = http_listener_inventory(active);
  let candidate_http = http_listener_inventory(candidate);
  for listener in active_http.intersection(&candidate_http) {
    push_unique(
      &mut report.activation_plan.listener.unchanged,
      listener.clone(),
    );
  }
  append_set_changes(
    &active_http,
    &candidate_http,
    &mut report.activation_plan.listener.additions,
    &mut report.activation_plan.listener.removals,
  );

  let tcp_options_changed = active.runtime.accept != candidate.runtime.accept;
  let quic_options_changed = active.quic.socket != candidate.quic.socket
    || active.quic.transport != candidate.quic.transport;
  for listener in active_http.intersection(&candidate_http) {
    let tcp = !listener.starts_with("http3:") && !listener.starts_with("admin_http3:");
    if (tcp && tcp_options_changed) || (!tcp && quic_options_changed) {
      push_unique(
        &mut report.activation_plan.listener.rebinds,
        listener.clone(),
      );
      let overlap_safe = if tcp {
        active.runtime.accept.reuse_port && candidate.runtime.accept.reuse_port
      } else {
        active.quic.socket.reuse_port && candidate.quic.socket.reuse_port
      };
      if !overlap_safe {
        push_unique(
          &mut report.activation_plan.listener.bind_conflicts,
          listener.clone(),
        );
      }
    }
  }

  let active_streams = active
    .stream_listeners
    .iter()
    .map(|listener| (listener.name.as_str(), listener))
    .collect::<BTreeMap<_, _>>();
  let candidate_streams = candidate
    .stream_listeners
    .iter()
    .map(|listener| (listener.name.as_str(), listener))
    .collect::<BTreeMap<_, _>>();
  for name in active_streams
    .keys()
    .chain(candidate_streams.keys())
    .copied()
    .collect::<BTreeSet<_>>()
  {
    match (active_streams.get(name), candidate_streams.get(name)) {
      (None, Some(listener)) => push_unique(
        &mut report.activation_plan.listener.additions,
        stream_listener_id(listener),
      ),
      (Some(listener), None) => push_unique(
        &mut report.activation_plan.listener.removals,
        stream_listener_id(listener),
      ),
      (Some(left), Some(right)) if *left != *right => {
        let id = format!("stream:{name}");
        push_unique(&mut report.activation_plan.listener.rebinds, id.clone());
        if left.bind == right.bind {
          push_unique(&mut report.activation_plan.listener.bind_conflicts, id);
        }
      }
      (Some(listener), Some(_)) => push_unique(
        &mut report.activation_plan.listener.unchanged,
        stream_listener_id(listener),
      ),
      _ => {}
    }
  }

  let active_turn = active
    .webrtc_turn_listeners
    .iter()
    .map(|listener| (listener.name.as_str(), listener))
    .collect::<BTreeMap<_, _>>();
  let candidate_turn = candidate
    .webrtc_turn_listeners
    .iter()
    .map(|listener| (listener.name.as_str(), listener))
    .collect::<BTreeMap<_, _>>();
  let mut turn_changed = false;
  for name in active_turn
    .keys()
    .chain(candidate_turn.keys())
    .copied()
    .collect::<BTreeSet<_>>()
  {
    match (active_turn.get(name), candidate_turn.get(name)) {
      (None, Some(_)) => {
        turn_changed = true;
        push_unique(
          &mut report.activation_plan.listener.additions,
          format!("turn:{name}"),
        );
      }
      (Some(_), None) => {
        turn_changed = true;
        push_unique(
          &mut report.activation_plan.listener.removals,
          format!("turn:{name}"),
        );
      }
      (Some(left), Some(right)) if *left != *right => {
        turn_changed = true;
        let id = format!("turn:{name}");
        push_unique(&mut report.activation_plan.listener.rebinds, id.clone());
        push_unique(&mut report.activation_plan.listener.bind_conflicts, id);
      }
      (Some(_), Some(_)) => push_unique(
        &mut report.activation_plan.listener.unchanged,
        format!("turn:{name}"),
      ),
      _ => {}
    }
  }

  let (transition, bind_conflict) = {
    let listener = &mut report.activation_plan.listener;
    let rebound = listener.rebinds.iter().cloned().collect::<BTreeSet<_>>();
    listener.unchanged.retain(|item| !rebound.contains(item));
    listener.unchanged.sort();
    listener.additions.sort();
    listener.removals.sort();
    listener.rebinds.sort();
    listener.bind_conflicts.sort();
    let transition = !listener.additions.is_empty()
      || !listener.removals.is_empty()
      || !listener.rebinds.is_empty();
    listener.external_port_availability = if transition {
      PrerequisiteAvailability::Unknown
    } else {
      PrerequisiteAvailability::NotApplicable
    };
    (transition, !listener.bind_conflicts.is_empty())
  };
  if transition {
    add_prerequisite(
      report,
      ActivationPrerequisite::ResolvedListenerInventory,
      PrerequisiteAvailability::Available,
    );
    promote(
      report,
      if !bind_conflict {
        ResolvedActivationOperation::ListenerTransition
      } else {
        ResolvedActivationOperation::GracefulDrain
      },
      if !bind_conflict {
        ActivationReasonCode::ListenerRebindRequired
      } else {
        ActivationReasonCode::ListenerBindConflict
      },
    );
  }
  if turn_changed {
    promote(
      report,
      ResolvedActivationOperation::ProcessRestart,
      ActivationReasonCode::ListenerBindConflict,
    );
  }
}

fn resolve_connection_impact(report: &mut ConfigActivationReport, active: &Config) {
  if report.changes.is_empty() {
    return;
  }
  let operation = report.activation_plan.selected_operation;
  let effect = if operation.strength() >= ResolvedActivationOperation::ProcessRestart.strength() {
    ConnectionEffect::ProcessRestart
  } else {
    ConnectionEffect::GracefulDrain
  };
  let connections = &mut report.activation_plan.connections;
  connections.http1_keepalive = effect;
  connections.http2 = effect;
  connections.http3 = effect;
  connections.websocket = effect;
  connections.connect_tunnel = effect;
  connections.webtransport = effect;
  let stream_changed = !report.activation_plan.listener.rebinds.is_empty()
    || !report.activation_plan.listener.removals.is_empty()
    || operation.strength() >= ResolvedActivationOperation::ProcessRestart.strength();
  if stream_changed {
    connections.tcp_streams = effect;
    connections.udp_flows = effect;
  }
  let graceful = active.runtime.drain.graceful_timeout_ms;
  let long = active.runtime.drain.long_connection_close_delay_ms;
  connections.configured_drain_timeout_ms = Some(graceful);
  connections.effective_force_close_timeout_ms = Some(graceful.min(long));
  if !report
    .activation_plan
    .reason_codes
    .contains(&ActivationReasonCode::GracefulDrainRequired)
  {
    report
      .activation_plan
      .reason_codes
      .push(ActivationReasonCode::GracefulDrainRequired);
  }
  for change in &mut report.changes {
    change.long_connections_affected = true;
  }
}

fn resolve_confinement(
  report: &mut ConfigActivationReport,
  active: &Config,
  candidate: &Config,
  hardening: Option<&RuntimeHardeningSnapshot>,
) {
  if report.changes.is_empty() {
    return;
  }
  let current_manifest = FilesystemAccessManifest::from_config(active);
  let candidate_manifest = FilesystemAccessManifest::from_config(candidate);
  let mut landlock_expands = false;
  let mut impossible = false;
  let mut mount_impossible = false;
  let mut seccomp_unsatisfied = false;

  match (current_manifest.as_ref(), candidate_manifest.as_ref()) {
    (Ok(current), Ok(candidate_manifest)) => {
      let check = candidate_manifest.check_current(false);
      let confinement = &mut report.activation_plan.confinement;
      confinement.current_manifest_digest = Some(current.digest().to_string());
      confinement.candidate_manifest_digest = Some(candidate_manifest.digest().to_string());
      confinement.filesystem = if check.ok {
        ConfinementFit::Fits
      } else {
        impossible = true;
        ConfinementFit::Impossible
      };
      confinement.mount_policy = match check.read_only_rootfs_compatible {
        Some(true) => ConfinementFit::Fits,
        Some(false) => {
          impossible = true;
          mount_impossible = true;
          ConfinementFit::Impossible
        }
        None => {
          push_unique(
            &mut confinement.missing_prerequisites,
            ActivationPrerequisite::MountPolicyEvidence,
          );
          ConfinementFit::Unknown
        }
      };

      let installed_manifest = hardening.and_then(|snapshot| {
        (snapshot.landlock.enforcement == LandlockEnforcementState::Active
          && snapshot.landlock.requested_mode == RuntimeLandlockMode::Manifest)
          .then_some(current)
      });
      let expansion = hardening
        .filter(|snapshot| snapshot.landlock.enforcement == LandlockEnforcementState::Active)
        .map(|_| {
          candidate_manifest.access_expansion_from_landlock(
            installed_manifest,
            &active.runtime.hardening.landlock.read_paths,
            &active.runtime.hardening.landlock.read_write_paths,
          )
        })
        .unwrap_or_default();
      landlock_expands = !expansion.is_empty();
      confinement.landlock = match hardening {
        Some(snapshot) if snapshot.landlock.enforcement == LandlockEnforcementState::Active => {
          confinement.active_policy_digest = snapshot.landlock.policy_digest.clone();
          if landlock_expands {
            confinement.requires_policy_expansion = true;
            confinement.restart_required = true;
            ConfinementFit::ExpansionRequired
          } else {
            ConfinementFit::Fits
          }
        }
        Some(_) if active.runtime.hardening.landlock.mode == RuntimeLandlockMode::Off => {
          ConfinementFit::Fits
        }
        _ => {
          push_unique(
            &mut confinement.missing_prerequisites,
            ActivationPrerequisite::ActiveLandlockPolicy,
          );
          ConfinementFit::Unknown
        }
      };

      for (index, entry) in expansion
        .iter()
        .take(MAX_CONFINEMENT_DIFFERENCES)
        .enumerate()
      {
        confinement.differences.push(ConfinementDifference {
          path_id: format!("path-{:04}", index + 1),
          source_config_path: entry.source_config_path().map(ToOwned::to_owned),
          kind: ConfinementDifferenceKind::PathAdded,
        });
      }
      confinement.differences_truncated = expansion.len() > MAX_CONFINEMENT_DIFFERENCES;
      for finding in check.findings.iter().filter(|finding| {
        matches!(
          finding.code,
          FilesystemAccessFindingCode::PathMissing
            | FilesystemAccessFindingCode::PathTypeMismatch
            | FilesystemAccessFindingCode::ReadOnlyMount
        )
      }) {
        if confinement.differences.len() >= MAX_CONFINEMENT_DIFFERENCES {
          confinement.differences_truncated = true;
          break;
        }
        let kind = match finding.code {
          FilesystemAccessFindingCode::PathTypeMismatch => ConfinementDifferenceKind::TypeMismatch,
          FilesystemAccessFindingCode::ReadOnlyMount => ConfinementDifferenceKind::MountUnavailable,
          _ => ConfinementDifferenceKind::PathUnavailable,
        };
        confinement.differences.push(ConfinementDifference {
          path_id: finding
            .path_id
            .clone()
            .unwrap_or_else(|| format!("path-{:04}", confinement.differences.len() + 1)),
          source_config_path: finding.source_config_path.clone(),
          kind,
        });
      }
    }
    _ => {
      impossible = true;
      let confinement = &mut report.activation_plan.confinement;
      confinement.filesystem = ConfinementFit::Impossible;
      confinement.landlock = ConfinementFit::Unknown;
      confinement.mount_policy = ConfinementFit::Unknown;
      push_unique(
        &mut confinement.missing_prerequisites,
        ActivationPrerequisite::FilesystemManifest,
      );
    }
  }

  {
    let confinement = &mut report.activation_plan.confinement;
    confinement.seccomp = match hardening {
      Some(snapshot)
        if candidate.runtime.hardening.seccomp.profile_identity
          != snapshot.seccomp.expected_profile_identity
          || candidate.runtime.hardening.seccomp.profile_digest
            != snapshot.seccomp.expected_profile_digest =>
      {
        confinement.requires_policy_expansion = true;
        confinement.restart_required = true;
        ConfinementFit::ExpansionRequired
      }
      Some(snapshot) => match snapshot.seccomp.verification {
        SeccompVerificationState::NotRequired
          if candidate.runtime.hardening.seccomp.expectation
            == crate::config::RuntimeSeccompExpectation::Off =>
        {
          ConfinementFit::Fits
        }
        SeccompVerificationState::NotRequired => ConfinementFit::ExpansionRequired,
        SeccompVerificationState::Satisfied => ConfinementFit::Fits,
        SeccompVerificationState::Degraded => ConfinementFit::Unknown,
        SeccompVerificationState::Blocked => {
          impossible = true;
          seccomp_unsatisfied = true;
          ConfinementFit::Impossible
        }
      },
      None => {
        push_unique(
          &mut confinement.missing_prerequisites,
          ActivationPrerequisite::ActiveSeccompProfile,
        );
        ConfinementFit::Unknown
      }
    };
  }

  if landlock_expands {
    promote(
      report,
      ResolvedActivationOperation::ProcessRestart,
      ActivationReasonCode::LandlockPolicyExpansion,
    );
    add_reason(report, ActivationReasonCode::FilesystemAccessExpansion);
  }
  if report.activation_plan.confinement.seccomp == ConfinementFit::ExpansionRequired {
    promote(
      report,
      ResolvedActivationOperation::ProcessRestart,
      ActivationReasonCode::ExternalSeccompProfileRequired,
    );
  }
  if impossible {
    promote(
      report,
      ResolvedActivationOperation::BlockedByConfinement,
      ActivationReasonCode::FilesystemAccessUnavailable,
    );
  }
  if mount_impossible {
    add_reason(report, ActivationReasonCode::MountPolicyIncompatible);
  }
  if seccomp_unsatisfied {
    add_reason(report, ActivationReasonCode::SeccompExpectationUnsatisfied);
  }
  for prerequisite in report
    .activation_plan
    .confinement
    .missing_prerequisites
    .clone()
  {
    add_prerequisite(report, prerequisite, PrerequisiteAvailability::Unknown);
  }
  if !report
    .activation_plan
    .confinement
    .missing_prerequisites
    .is_empty()
  {
    add_reason(report, ActivationReasonCode::ConfinementEvidenceUnavailable);
    report.activation_plan.conditional = true;
  }
}

fn resolve_deployment(
  report: &mut ConfigActivationReport,
  active: &Config,
  candidate: &Config,
  authorization: &AdminAuthorization<'_>,
) {
  if report.changes.is_empty() {
    return;
  }
  if active.rollout.is_immutable() {
    let deployment = &mut report.activation_plan.deployment;
    deployment.mode = DeploymentMode::KubernetesImmutable;
    deployment.target_count = Some(1);
    deployment
      .missing_prerequisites
      .push(ActivationPrerequisite::PriorRollbackArtifact);
    let target_available = if let Some(target) = active.rollout.kubernetes_rollout_target() {
      deployment.target_identities.push(format!(
        "{}:{}/{}",
        target.kind().as_str(),
        target.namespace(),
        target.name()
      ));
      true
    } else {
      deployment
        .missing_prerequisites
        .push(ActivationPrerequisite::DeploymentTargetIdentity);
      false
    };
    promote(
      report,
      ResolvedActivationOperation::KubernetesImmutableRollout,
      ActivationReasonCode::ImmutableConfigRequiresRollout,
    );
    apply_deployment_operation(
      report,
      ResolvedActivationOperation::KubernetesImmutableRollout,
    );
    add_prerequisite(
      report,
      ActivationPrerequisite::DeploymentTargetIdentity,
      if target_available {
        PrerequisiteAvailability::Available
      } else {
        PrerequisiteAvailability::Missing
      },
    );
    if !target_available
      && !report
        .activation_plan
        .reason_codes
        .contains(&ActivationReasonCode::DeploymentTargetUnavailable)
    {
      report
        .activation_plan
        .reason_codes
        .push(ActivationReasonCode::DeploymentTargetUnavailable);
    }
    add_prerequisite(
      report,
      ActivationPrerequisite::PriorRollbackArtifact,
      PrerequisiteAvailability::Unknown,
    );
    return;
  }
  if !active.rollout.is_admin_cluster() {
    return;
  }

  let rollout = &active.admin.mutations.rollout;
  let mut members = rollout.members.clone();
  members.sort();
  members.dedup();
  let deployment = &mut report.activation_plan.deployment;
  deployment.mode = DeploymentMode::AdminCluster;
  deployment.target_count = Some(members.len());
  deployment.identities_withheld =
    !authorization.is_allowed("config:GetInstances", "instances/current");
  if !deployment.identities_withheld {
    deployment.target_identities = members;
  }
  let target = crate::admin_mutation::configured_target(active);
  deployment.membership_revision = Some(target.membership_revision);
  deployment.signed_artifact_required = true;
  deployment.durable_artifact_required = true;
  deployment.all_members_acknowledgement_required = true;
  deployment.missing_prerequisites = vec![
    ActivationPrerequisite::SignedMutationArtifact,
    ActivationPrerequisite::DurableMutationArtifact,
    ActivationPrerequisite::AllMembersAcknowledgement,
    ActivationPrerequisite::PriorRollbackArtifact,
  ];
  let membership_changed = active.admin.mutations.rollout != candidate.admin.mutations.rollout
    || active.admin.mutations != candidate.admin.mutations;
  promote(
    report,
    ResolvedActivationOperation::AdminClusterRollout,
    if membership_changed {
      ActivationReasonCode::AdminClusterMembershipEpoch
    } else {
      ActivationReasonCode::AdminClusterCoordinatedRollout
    },
  );
  apply_deployment_operation(report, ResolvedActivationOperation::AdminClusterRollout);
  for prerequisite in [
    ActivationPrerequisite::SignedMutationArtifact,
    ActivationPrerequisite::DurableMutationArtifact,
    ActivationPrerequisite::AllMembersAcknowledgement,
    ActivationPrerequisite::PriorRollbackArtifact,
  ] {
    add_prerequisite(report, prerequisite, PrerequisiteAvailability::Missing);
  }
}

fn apply_deployment_operation(
  report: &mut ConfigActivationReport,
  operation: ResolvedActivationOperation,
) {
  report.activation_plan.can_apply_in_process = false;
  report.activation_plan.rollback = RollbackKind::Conditional;
  for change in &mut report.changes {
    change.resolved_operation = operation;
    change.long_connections_affected = true;
    change.rollback = RollbackKind::Conditional;
  }
}

fn promote(
  report: &mut ConfigActivationReport,
  operation: ResolvedActivationOperation,
  reason: ActivationReasonCode,
) {
  if matches!(
    operation,
    ResolvedActivationOperation::BlockedByConfinement
      | ResolvedActivationOperation::InvalidOrUnsupported
  ) {
    report.ok = false;
  }
  if operation.strength() > report.activation_plan.minimum_required_operation.strength() {
    report.activation_plan.minimum_required_operation = operation;
  }
  if operation.strength() > report.activation_plan.selected_operation.strength() {
    report.activation_plan.selected_operation = operation;
  }
  if !report.activation_plan.reason_codes.contains(&reason) {
    report.activation_plan.reason_codes.push(reason);
  }
  report.activation_plan.can_apply_in_process = matches!(
    report.activation_plan.selected_operation,
    ResolvedActivationOperation::None
      | ResolvedActivationOperation::OxiRuleReload
      | ResolvedActivationOperation::DownstreamTlsReload
      | ResolvedActivationOperation::FullSnapshotReload
      | ResolvedActivationOperation::ListenerTransition
      | ResolvedActivationOperation::GracefulDrain
  );
}

fn add_prerequisite(
  report: &mut ConfigActivationReport,
  prerequisite: ActivationPrerequisite,
  availability: PrerequisiteAvailability,
) {
  if let Some(existing) = report
    .activation_plan
    .prerequisites
    .iter_mut()
    .find(|status| status.prerequisite == prerequisite)
  {
    existing.availability = availability;
  } else {
    report
      .activation_plan
      .prerequisites
      .push(ActivationPrerequisiteStatus {
        prerequisite,
        availability,
      });
  }
  if matches!(
    availability,
    PrerequisiteAvailability::Missing | PrerequisiteAvailability::Unknown
  ) {
    report.activation_plan.conditional = true;
  }
}

fn normalize_plan(report: &mut ConfigActivationReport) {
  report.activation_plan.reason_codes.sort();
  report.activation_plan.reason_codes.dedup();
  report
    .activation_plan
    .prerequisites
    .sort_by_key(|status| status.prerequisite);
  report
    .activation_plan
    .prerequisites
    .dedup_by_key(|status| status.prerequisite);
}

fn http_listener_inventory(config: &Config) -> BTreeSet<String> {
  let mut listeners = BTreeSet::new();
  if config.needs_https_listener() {
    for bind in &config.listeners.https_binds {
      listeners.insert(format!("https:{bind}"));
    }
  }
  if config.listeners.http_mode != HttpListenerMode::Off {
    for bind in &config.listeners.http_binds {
      listeners.insert(format!("http:{bind}"));
    }
  }
  if config.listeners.http3 {
    for bind in &config.listeners.https_binds {
      listeners.insert(format!("http3:{bind}"));
    }
  }
  if config.admin.enabled {
    listeners.insert(format!("admin:{}", config.admin.bind));
    if config.admin.http3.enabled {
      listeners.insert(format!(
        "admin_http3:{}",
        config.admin.http3.bind.unwrap_or(config.admin.bind)
      ));
    }
  }
  if config.metrics.enabled {
    listeners.insert(format!("metrics:{}", config.metrics.bind));
  }
  if config.health.enabled {
    listeners.insert(format!("health:{}", config.health.bind));
  }
  listeners
}

fn append_set_changes(
  active: &BTreeSet<String>,
  candidate: &BTreeSet<String>,
  additions: &mut Vec<String>,
  removals: &mut Vec<String>,
) {
  for item in candidate.difference(active) {
    push_unique(additions, item.clone());
  }
  for item in active.difference(candidate) {
    push_unique(removals, item.clone());
  }
}

fn stream_listener_id(listener: &crate::config::StreamListenerConfig) -> String {
  let network = match listener.network {
    StreamNetwork::Tcp => "tcp",
    StreamNetwork::Udp => "udp",
  };
  format!("stream:{}:{network}:{}", listener.name, listener.bind)
}

fn add_reason(report: &mut ConfigActivationReport, reason: ActivationReasonCode) {
  if !report.activation_plan.reason_codes.contains(&reason) {
    report.activation_plan.reason_codes.push(reason);
  }
}

fn push_unique<T: Eq>(values: &mut Vec<T>, value: T) {
  if !values.contains(&value) {
    values.push(value);
  }
}

#[cfg(test)]
mod tests {
  use std::net::SocketAddr;

  use crate::activation_plan::{PlanningBasis, plan_toml_values};
  use crate::config::{
    AdminMutationRolloutMode, IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig,
  };
  use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};

  use super::*;

  fn test_config() -> Config {
    toml::from_str(
      r#"
[runtime]
worker_threads = 1

[runtime.accept]
workers = 1
reuse_port = false
backlog = 1024
accept_error_backoff_ms = 50

[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
"#,
    )
    .expect("activation plan test config should parse")
  }

  fn changed_report() -> ConfigActivationReport {
    let active: toml::Value = toml::from_str("[compression]\nenabled = true\n")
      .expect("active comparison value should parse");
    let candidate: toml::Value = toml::from_str("[compression]\nenabled = false\n")
      .expect("candidate comparison value should parse");
    plan_toml_values(&active, &candidate, PlanningBasis::OnlineActive)
      .expect("comparison should plan")
  }

  fn authorization_inputs(actions: &[&str]) -> (IpmActor, IpmRuntime, IpmRequestContext) {
    let actor = IpmActor {
      name: "planner".to_string(),
      principal: "planner".to_string(),
      subject: "planner@example.com".to_string(),
      groups: vec!["ops".to_string()],
    };
    let policy = IpmPolicyConfig {
      name: "planner-test".to_string(),
      version: "2026-07-31".to_string(),
      statements: vec![IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Allow,
        actions: actions.iter().map(|action| (*action).to_string()).collect(),
        resources: vec!["*".to_string()],
        conditions: Vec::new(),
      }],
    };
    (
      actor.clone(),
      IpmRuntime::test_with_actor_policy("oxibelt", actor, policy),
      IpmRequestContext::default(),
    )
  }

  #[test]
  fn resolved_listener_plan_reports_unchanged_add_remove_conflict_and_drain() {
    let active = test_config();

    let mut replaced = active.clone();
    replaced.listeners.https_binds = vec![
      "127.0.0.1:9443"
        .parse::<SocketAddr>()
        .expect("replacement bind should parse"),
    ];
    let mut transition = changed_report();
    resolve_listener_transition(&mut transition, &active, &replaced);
    assert_eq!(
      transition.activation_plan.listener.additions,
      ["https:127.0.0.1:9443"]
    );
    assert_eq!(
      transition.activation_plan.listener.removals,
      ["https:127.0.0.1:8443"]
    );

    let mut rebound = active.clone();
    rebound.runtime.accept.backlog += 1;
    let mut conflict = changed_report();
    resolve_listener_transition(&mut conflict, &active, &rebound);
    resolve_connection_impact(&mut conflict, &active);
    assert!(
      conflict
        .activation_plan
        .listener
        .rebinds
        .contains(&"https:127.0.0.1:8443".to_string())
    );
    assert!(
      conflict
        .activation_plan
        .listener
        .bind_conflicts
        .contains(&"https:127.0.0.1:8443".to_string())
    );
    assert!(
      !conflict
        .activation_plan
        .listener
        .unchanged
        .contains(&"https:127.0.0.1:8443".to_string())
    );
    assert_eq!(
      conflict.activation_plan.connections.websocket,
      ConnectionEffect::GracefulDrain
    );
    assert_eq!(
      conflict
        .activation_plan
        .connections
        .configured_drain_timeout_ms,
      Some(active.runtime.drain.graceful_timeout_ms)
    );

    let mut unchanged = changed_report();
    resolve_listener_transition(&mut unchanged, &active, &active);
    assert!(
      unchanged
        .activation_plan
        .listener
        .unchanged
        .contains(&"https:127.0.0.1:8443".to_string())
    );
  }

  #[test]
  fn enforced_landlock_known_path_expansion_requires_restart() {
    let mut active = test_config();
    active.tls.cert_chain = "fullchain.pem".into();
    active.tls.private_key = Some("privkey.pem".into());
    active.runtime.hardening.landlock.mode = RuntimeLandlockMode::Enforce;
    active
      .runtime
      .hardening
      .landlock
      .read_paths
      .push("/etc/oxibelt".into());
    assert_eq!(
      active.tls.cert_chain,
      std::path::PathBuf::from("fullchain.pem")
    );
    let mut candidate = active.clone();
    candidate
      .source_paths
      .config_files
      .push("/var/lib/oxibelt/extra.toml".into());
    let mut report = changed_report();
    let active_manifest =
      FilesystemAccessManifest::from_config(&active).expect("active manifest should be generated");
    let projection = active_manifest.landlock_projection();
    let mut hardening =
      crate::hardening::observe_runtime_hardening(&active.runtime.hardening, Some(&projection));
    hardening.landlock.enforcement = LandlockEnforcementState::Active;

    resolve_confinement(&mut report, &active, &candidate, Some(&hardening));

    assert_eq!(
      report.activation_plan.confinement.landlock,
      ConfinementFit::ExpansionRequired
    );
    assert!(report.activation_plan.confinement.requires_policy_expansion);
    assert_eq!(
      report.activation_plan.selected_operation,
      ResolvedActivationOperation::BlockedByConfinement
    );
    assert!(!report.ok);
    assert!(
      report
        .activation_plan
        .reason_codes
        .contains(&ActivationReasonCode::LandlockPolicyExpansion)
    );
  }

  #[test]
  fn immutable_and_admin_cluster_plans_preserve_or_withhold_target_identity() {
    let mut immutable = test_config();
    immutable.rollout = crate::config::ConfigRolloutIdentity::immutable_for_planning_test(
      "edge",
      "Deployment",
      "oxibelt",
    );
    let immutable_candidate = immutable.clone();
    let (actor, ipm, context) = authorization_inputs(&["config:Diff"]);
    let authorization = AdminAuthorization::new(&actor, &ipm, &context);
    let mut report = changed_report();
    resolve_deployment(
      &mut report,
      &immutable,
      &immutable_candidate,
      &authorization,
    );
    assert_eq!(
      report.activation_plan.selected_operation,
      ResolvedActivationOperation::KubernetesImmutableRollout
    );
    assert_eq!(
      report.activation_plan.deployment.target_identities,
      ["Deployment:edge/oxibelt"]
    );

    let mut cluster = test_config();
    cluster.rollout =
      crate::config::ConfigRolloutIdentity::admin_cluster_for_planning_test("node-a");
    cluster.admin.mutations.rollout.mode = AdminMutationRolloutMode::AdminCluster;
    cluster.admin.mutations.rollout.cluster_id = "edge".to_string();
    cluster.admin.mutations.rollout.members = vec!["node-b".to_string(), "node-a".to_string()];
    let cluster_candidate = cluster.clone();
    let mut withheld = changed_report();
    resolve_deployment(&mut withheld, &cluster, &cluster_candidate, &authorization);
    assert_eq!(withheld.activation_plan.deployment.target_count, Some(2));
    assert!(withheld.activation_plan.deployment.identities_withheld);
    assert!(
      withheld
        .activation_plan
        .deployment
        .target_identities
        .is_empty()
    );

    let (actor, ipm, context) = authorization_inputs(&["config:Diff", "config:GetInstances"]);
    let authorization = AdminAuthorization::new(&actor, &ipm, &context);
    let mut visible = changed_report();
    resolve_deployment(&mut visible, &cluster, &cluster_candidate, &authorization);
    assert!(!visible.activation_plan.deployment.identities_withheld);
    assert_eq!(
      visible.activation_plan.deployment.target_identities,
      ["node-a", "node-b"]
    );
  }
}
