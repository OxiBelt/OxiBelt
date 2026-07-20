//! Atomic cluster admission: audit intent, claim, exact targets, and ciphertext.

use anyhow::Context;
use http::{HeaderMap, Method, StatusCode, Uri};

use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};
use crate::admin_mutation::artifact::ArtifactBinding;
use crate::admin_mutation::cluster_command::{
  ClusterAuthenticatedActor, ClusterCommandAuthorization, ClusterMutationCommand,
};
use crate::admin_mutation::envelope::{TranscriptContext, parse_mutation_header, parse_timestamp};
use crate::admin_mutation::ledger::{ClaimOutcome, MutationClaim};
use crate::admin_mutation::rollout_store::{cluster_admit_tx, prove_exact_resource_membership};
use crate::admin_mutation::{MUTATION_HEADER, MutationProtocolErrorKind};
use crate::ipm::IpmActor;

use super::{
  AdminMutationRuntime, MutationAdmission, MutationAdmissionError, MutationConflict,
  claim_outcome_admission,
};

impl AdminMutationRuntime {
  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn admit_cluster(
    &self,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    authenticated_principal: &str,
    authenticated_actor: &IpmActor,
    credential_kind: &str,
    authenticated_with_break_glass: bool,
    body: &[u8],
    action: &str,
    resource: &str,
    current_revision: &str,
    precondition_revision: &str,
    authorization: ClusterCommandAuthorization,
    audit: &AdminAuditHandle,
    audit_runtime: &AdminAuditRuntime,
  ) -> Result<MutationAdmission, MutationAdmissionError> {
    if !self.cluster_mode() {
      return Err(anyhow::anyhow!("cluster admission requires admin_cluster mode").into());
    }
    if authenticated_actor.principal != authenticated_principal {
      return Err(
        anyhow::anyhow!("authenticated actor conflicts with the signed mutation principal").into(),
      );
    }
    let authenticated_actor = ClusterAuthenticatedActor::new(
      authenticated_actor,
      credential_kind,
      authenticated_with_break_glass,
    )?;
    if !self.has_envelope(headers) {
      return Err(
        crate::admin_mutation::MutationProtocolError::new(
          MutationProtocolErrorKind::MissingHeader,
          "mutation envelope header is required",
        )
        .into(),
      );
    }

    let store = self.store()?;
    let parsed = parse_mutation_header(headers)?;
    let existing = store
      .load_mutation(&parsed.unsigned.request_id)
      .await
      .context("failed to look up existing cluster mutation")?;
    let now_unix_seconds = if existing.is_some() {
      parse_timestamp(&parsed.unsigned.issued_at)?
    } else {
      sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
        .fetch_one(store.pool())
        .await
        .context("failed to read authoritative mutation time")?
    };
    let path_and_query = uri
      .path_and_query()
      .map(|value| value.as_str())
      .unwrap_or_else(|| uri.path());
    let verified = self.inner.signers.verify(
      headers,
      &TranscriptContext {
        method,
        path_and_query,
        ipm_namespace: &self.inner.namespace,
        authenticated_principal,
        body,
        precondition_revision,
        now_unix_seconds,
        maximum_validity_seconds: self.inner.maximum_validity_seconds,
        maximum_clock_skew_seconds: self.inner.maximum_clock_skew_seconds,
      },
    )?;
    if verified.envelope.unsigned.target != self.inner.target {
      return Ok(MutationAdmission::Conflict(MutationConflict::Target));
    }
    let unsigned = &verified.envelope.unsigned;
    audit.record_mutation_context(
      &unsigned.signer_id,
      action,
      resource,
      &unsigned.expected_previous_revision,
      &unsigned.new_revision,
      &unsigned.content_digest,
      &unsigned.target.cluster_id,
      &unsigned.target.membership_revision,
    );
    if let Some(record) = existing {
      let exact = record.fingerprint == verified.fingerprint
        && record.principal == authenticated_principal
        && record.signer_id == unsigned.signer_id
        && record.action == action
        && record.resource == resource
        && record.expected_previous_revision == unsigned.expected_previous_revision
        && record.new_revision == unsigned.new_revision
        && record.content_digest == unsigned.content_digest
        && record.cluster_id.as_deref() == Some(unsigned.target.cluster_id.as_str())
        && record.membership_revision.as_deref()
          == Some(unsigned.target.membership_revision.as_str())
        && record.issued_at == unsigned.issued_at
        && record.expires_at == unsigned.expires_at;
      if !exact {
        return Ok(MutationAdmission::Conflict(MutationConflict::RequestId));
      }
      if audit_runtime.anchoring_enabled() {
        let retry_intent = audit.critical_mutation_event(
          &unsigned.request_id,
          StatusCode::ACCEPTED,
          "attempted",
          None,
        );
        audit_runtime
          .persist_critical_mutation(retry_intent)
          .await
          .context("failed to anchor replayed cluster mutation audit intent")?;
      }
      audit.mark_critical_mutation_lifecycle_managed();
      return Ok(if record.terminal_response_ready() {
        MutationAdmission::Replay(record)
      } else {
        MutationAdmission::InProgress(record)
      });
    }
    if !self.cluster_rollout_ready() {
      return Err(anyhow::anyhow!("Admin cluster mutation authority is unavailable").into());
    }
    if precondition_revision != current_revision {
      let intent = audit.critical_mutation_event(
        &unsigned.request_id,
        StatusCode::PRECONDITION_FAILED,
        "rejected",
        Some("mutation precondition failed"),
      );
      audit_runtime.persist_critical_mutation(intent).await?;
      return Ok(MutationAdmission::PreconditionFailed {
        active_revision: current_revision.to_string(),
      });
    }
    let logical = store
      .load_revision(resource)
      .await
      .context("failed to load cluster mutation logical revision")?
      .context("cluster mutation baseline is not initialized")?;
    if !(logical.committed_revision == unsigned.expected_previous_revision
      && logical.cluster_id.as_deref() == Some(self.inner.target.cluster_id.as_str())
      && logical.membership_revision.as_deref()
        == Some(self.inner.target.membership_revision.as_str()))
    {
      return Err(
        anyhow::anyhow!("cluster mutation baseline does not match the active runtime").into(),
      );
    }
    let exact = prove_exact_resource_membership(
      store,
      &self.inner.cluster_id,
      &self.inner.target.membership_revision,
      &self.inner.members,
      env!("CARGO_PKG_VERSION"),
      "admin-mutation-rollout-v1",
      self.artifact_key_fingerprint()?,
      resource,
    )
    .await?;

    let mutation_header = headers
      .get(MUTATION_HEADER)
      .context("verified mutation header disappeared")?
      .to_str()
      .context("verified mutation header is not visible ASCII")?;
    let intent = audit.critical_mutation_event(
      &unsigned.request_id,
      StatusCode::ACCEPTED,
      "attempted",
      None,
    );
    let mut staged_audit = audit_runtime.stage_critical_mutation(intent).await?;
    let mut tx = store.pool().begin().await.map_err(anyhow::Error::from)?;
    let audit_record_id = staged_audit.insert(&mut tx).await?;
    let claim = MutationClaim {
      request_id: unsigned.request_id.clone(),
      fingerprint: verified.fingerprint,
      principal: authenticated_principal.to_string(),
      signer_id: unsigned.signer_id.clone(),
      action: action.to_string(),
      resource: resource.to_string(),
      expected_previous_revision: unsigned.expected_previous_revision.clone(),
      new_revision: unsigned.new_revision.clone(),
      content_digest: unsigned.content_digest.clone(),
      cluster_id: Some(unsigned.target.cluster_id.clone()),
      membership_revision: Some(unsigned.target.membership_revision.clone()),
      issued_at: unsigned.issued_at.clone(),
      expires_at: unsigned.expires_at.clone(),
      allowed_clock_skew_seconds: i64::try_from(self.inner.maximum_clock_skew_seconds)
        .context("Admin mutation clock skew exceeds the supported range")?,
      retention_seconds: self.inner.retention_seconds,
      audit_record_id,
    };
    let command = ClusterMutationCommand::new(
      method,
      path_and_query,
      precondition_revision,
      authenticated_principal,
      authenticated_actor,
      &unsigned.signer_id,
      action,
      resource,
      &unsigned.expected_previous_revision,
      &unsigned.new_revision,
      body,
      mutation_header,
      authorization,
    )?;
    let command_path = path_and_query.split('?').next().unwrap_or_default();
    let token_producing = *method == Method::POST
      && (command_path == "/admin/v1/ipm/credentials"
        || (command_path.starts_with("/admin/v1/ipm/credentials/")
          && command_path.ends_with("/rotate")));
    let binding = ArtifactBinding::from_claim(store.namespace(), &claim)?;
    command.validate_against(&binding)?;
    let sealed = self
      .artifact_cipher()?
      .seal(&binding, command.into_plaintext()?)?;
    let admission_member = self.cluster_controller_ref()?.member_fence().await?;
    let admission = cluster_admit_tx(
      &mut tx,
      store,
      &claim,
      &exact,
      &admission_member,
      &sealed,
      audit_runtime.anchoring_required(),
    )
    .await?;
    let registered = token_producing && matches!(&admission.outcome, ClaimOutcome::Claimed(_));
    let winner_response =
      registered.then(|| self.register_shared_winner_response(&unsigned.request_id));
    tx.commit()
      .await
      .context("failed to commit cluster mutation admission")?;
    staged_audit.publish().await?;
    if audit_runtime.anchoring_required() && matches!(&admission.outcome, ClaimOutcome::Claimed(_))
    {
      store
        .confirm_admission_audit(&unsigned.request_id, audit_record_id)
        .await
        .context("failed to promote anchored cluster mutation admission")?;
    }
    if admission.artifact.is_some() {
      audit.mark_critical_mutation_lifecycle_managed();
    }
    Ok(claim_outcome_admission(
      admission.outcome,
      audit,
      winner_response,
    ))
  }
}
