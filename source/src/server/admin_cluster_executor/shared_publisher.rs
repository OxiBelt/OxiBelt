//! Coordinator-fenced publisher for shared IPM and break-glass mutations.

use std::future::Future;
use std::pin::Pin;

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::admin_mutation::{
  AdminMutationRuntime, CoordinatorFence, MemberFence, SharedPublicationClaim,
  SharedPublicationOutcome, SharedPublicationState, begin_coordinator_transaction,
  capture_break_glass_checkpoint_tx, claim_shared_publication, consume_shared_winner_response,
  create_break_glass_activation_tx, finish_shared_publication, load_shared_publication,
  publish_checkpoint_in_coordinator_transaction, restore_break_glass_checkpoint_tx,
  revoke_break_glass_activation_tx,
};
use crate::ipm::{IpmActor, IpmMutationCheckpoint, IpmRuntime, IpmTransactionalMutationResult};
use crate::state::AppHandle;

use super::{
  BreakGlassStagedMutation, SharedPublishResult, SharedStagedOperation, SharedStagedPublisher,
};

#[derive(Clone)]
pub(crate) struct RuntimeSharedPublisher {
  runtime: AdminMutationRuntime,
  state: AppHandle,
}

impl RuntimeSharedPublisher {
  pub(crate) fn new(runtime: AdminMutationRuntime, state: AppHandle) -> Self {
    Self { runtime, state }
  }

  async fn publish(
    &self,
    fence: &CoordinatorFence,
    actor: &IpmActor,
    operation: &SharedStagedOperation,
  ) -> anyhow::Result<SharedPublishResult> {
    self.ensure_same_backend()?;
    let context = self.context(fence, operation).await?;
    let mut transaction = begin_coordinator_transaction(self.runtime.store()?, fence).await?;
    let outcome = claim_shared_publication(&mut transaction, &context.claim).await?;
    if let SharedPublicationOutcome::Replay(record) = outcome {
      ensure!(
        record.state == SharedPublicationState::Applied,
        "shared publication is not in the applied state"
      );
      transaction.commit().await?;
      return Ok(replayed_result(operation));
    }

    let ipm = self.state.snapshot().ipm.clone();
    let effect = apply_effect(
      &mut transaction,
      &ipm,
      actor,
      operation,
      &fence.request_id,
      self.maximum_break_glass_ttl(),
    )
    .await?;
    let plaintext = effect.checkpoint().encode()?;
    let sealed = self.runtime.seal_shared_cluster_checkpoint(
      &context.record,
      &context.owner,
      context.assignment_epoch,
      &context.record.expected_previous_revision,
      &context.prior_digest,
      &plaintext,
    )?;
    publish_checkpoint_in_coordinator_transaction(&mut transaction, &context.owner, &sealed)
      .await?;
    let safe_response = effect.safe_response();
    finish_shared_publication(
      &mut transaction,
      SharedPublicationState::Applied,
      Some(safe_response.clone()),
    )
    .await?;
    let attach = if effect.token().is_some() {
      consume_shared_winner_response(&mut transaction).await?
    } else {
      false
    };
    transaction.commit().await?;
    let attached_winner_response = if attach {
      effect.winner_response()?
    } else {
      None
    };
    if let Some(response) = attached_winner_response.as_ref() {
      self
        .runtime
        .deliver_shared_winner_response(&fence.request_id, response.clone());
    }
    ipm.refresh_after_shared_commit().await?;
    Ok(SharedPublishResult {
      revision: operation.candidate_revision.clone(),
      digest: operation.candidate_digest.clone(),
    })
  }

  async fn restore(
    &self,
    fence: &CoordinatorFence,
    actor: &IpmActor,
    operation: &SharedStagedOperation,
  ) -> anyhow::Result<SharedPublishResult> {
    self.ensure_same_backend()?;
    let context = self.context(fence, operation).await?;
    let encrypted = self
      .runtime
      .fetch_shared_cluster_checkpoint(&context.record, &context.owner, context.assignment_epoch)
      .await?;
    ensure!(
      encrypted.candidate_revision == context.record.new_revision
        && encrypted.candidate_digest == context.record.content_digest
        && encrypted.prior_revision == context.record.expected_previous_revision
        && encrypted.prior_digest == context.prior_digest,
      "shared rollback checkpoint evidence conflicts with the durable rollout"
    );
    let checkpoint = SharedEffectCheckpoint::decode(&encrypted.plaintext)?;
    let mut transaction = begin_coordinator_transaction(self.runtime.store()?, fence).await?;
    let publication = claim_shared_publication(&mut transaction, &context.claim).await?;
    match &publication {
      SharedPublicationOutcome::Replay(record)
        if record.state == SharedPublicationState::Restored =>
      {
        transaction.commit().await?;
        return Ok(SharedPublishResult {
          revision: context.record.expected_previous_revision,
          digest: context.prior_digest,
        });
      }
      SharedPublicationOutcome::Replay(record)
        if record.state == SharedPublicationState::Applied => {}
      _ => bail!("shared rollback requires an exact applied publication"),
    }
    let ipm = self.state.snapshot().ipm.clone();
    match checkpoint {
      SharedEffectCheckpoint::Ipm(checkpoint) => {
        ipm
          .restore_admin_mutation_tx(transaction.transaction(), actor, &checkpoint)
          .await?;
      }
      SharedEffectCheckpoint::BreakGlass(checkpoint) => {
        restore_break_glass_checkpoint_tx(
          transaction.transaction(),
          self.runtime.store()?.namespace(),
          &checkpoint,
        )
        .await?;
      }
    }
    let safe = restored_response();
    finish_shared_publication(
      &mut transaction,
      SharedPublicationState::Restored,
      Some(safe.clone()),
    )
    .await?;
    transaction.commit().await?;
    ipm.refresh_after_shared_commit().await?;
    Ok(SharedPublishResult {
      revision: context.record.expected_previous_revision,
      digest: context.prior_digest,
    })
  }

  async fn context(
    &self,
    fence: &CoordinatorFence,
    operation: &SharedStagedOperation,
  ) -> anyhow::Result<PublicationContext> {
    let record = self
      .runtime
      .load_mutation(&fence.request_id)
      .await?
      .context("shared mutation disappeared")?;
    ensure!(
      record.principal == operation.principal
        && record.expected_previous_revision == operation.previous_revision
        && record.new_revision == operation.candidate_revision
        && record.content_digest == operation.candidate_digest,
      "shared operation does not match its durable mutation"
    );
    let canary = deterministic_canary(&record.request_id, self.runtime.configured_members())?;
    let owner = fence
      .exact_membership
      .members
      .iter()
      .find(|member| member.instance_id == canary)
      .cloned()
      .context("deterministic canary is outside exact membership")?;
    let target = self
      .runtime
      .cluster_targets(&record.request_id)
      .await?
      .into_iter()
      .find(|target| target.instance_id == canary)
      .context("deterministic canary target is missing")?;
    ensure!(target.assignment_epoch > 0, "canary is not apply-assigned");
    let prior_digest = self
      .runtime
      .cluster_logical_revision(&record.resource)
      .await?
      .context("shared logical head is missing")?
      .content_digest;
    let claim = SharedPublicationClaim {
      operation_kind: record.action.clone(),
      operation_fingerprint: record.fingerprint.clone(),
      candidate_revision: record.new_revision.clone(),
      candidate_digest: record.content_digest.clone(),
      checkpoint_reference: owner.instance_id.clone(),
      token_producing: operation.token_producing(),
    };
    Ok(PublicationContext {
      record,
      owner,
      assignment_epoch: target.assignment_epoch,
      prior_digest,
      claim,
    })
  }

  fn ensure_same_backend(&self) -> anyhow::Result<()> {
    let snapshot = self.state.snapshot();
    ensure!(
      snapshot.config.ipm_backend_name() == snapshot.config.admin.mutations.backend.as_deref(),
      "shared publisher requires IPM and mutation ledger on the same backend"
    );
    Ok(())
  }

  fn maximum_break_glass_ttl(&self) -> u64 {
    self
      .state
      .snapshot()
      .config
      .ipm
      .break_glass
      .max_activation_seconds
  }
}

impl SharedStagedPublisher for RuntimeSharedPublisher {
  fn publish_once<'a>(
    &'a self,
    fence: &'a CoordinatorFence,
    actor: &'a IpmActor,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<SharedPublishResult>> + Send + 'a>> {
    Box::pin(self.publish(fence, actor, operation))
  }

  fn observe<'a>(
    &'a self,
    request_id: &'a str,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
    Box::pin(async move {
      let record = load_shared_publication(self.runtime.store()?, request_id).await?;
      Ok(record.is_some_and(|record| {
        record.state == SharedPublicationState::Applied
          && record.candidate_revision == operation.candidate_revision
          && record.candidate_digest == operation.candidate_digest
      }))
    })
  }

  fn restore_once<'a>(
    &'a self,
    fence: &'a CoordinatorFence,
    actor: &'a IpmActor,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<SharedPublishResult>> + Send + 'a>> {
    Box::pin(self.restore(fence, actor, operation))
  }

  fn observe_restored<'a>(
    &'a self,
    request_id: &'a str,
    operation: &'a SharedStagedOperation,
  ) -> Pin<Box<dyn Future<Output = anyhow::Result<bool>> + Send + 'a>> {
    Box::pin(async move {
      let record = load_shared_publication(self.runtime.store()?, request_id).await?;
      Ok(record.is_some_and(|record| {
        record.state == SharedPublicationState::Restored
          && record.candidate_revision == operation.candidate_revision
          && record.candidate_digest == operation.candidate_digest
      }))
    })
  }
}

struct PublicationContext {
  record: crate::admin_mutation::MutationRecord,
  owner: MemberFence,
  assignment_epoch: i64,
  prior_digest: String,
  claim: SharedPublicationClaim,
}

enum AppliedEffect {
  Ipm(IpmTransactionalMutationResult),
  BreakGlass {
    checkpoint: crate::admin_mutation::BreakGlassMutationCheckpoint,
    safe_response: serde_json::Value,
  },
}

impl AppliedEffect {
  fn checkpoint(&self) -> SharedEffectCheckpoint {
    match self {
      Self::Ipm(result) => SharedEffectCheckpoint::Ipm(result.checkpoint.clone()),
      Self::BreakGlass { checkpoint, .. } => SharedEffectCheckpoint::BreakGlass(checkpoint.clone()),
    }
  }

  fn safe_response(&self) -> serde_json::Value {
    match self {
      Self::Ipm(result) => json!({
        "ok": true,
        "target_kind": result.target_kind,
        "target_id": result.target_id,
        "token_recoverable": false,
      }),
      Self::BreakGlass { safe_response, .. } => safe_response.clone(),
    }
  }

  fn token(&self) -> Option<&str> {
    match self {
      Self::Ipm(result) => result.one_time_token.as_ref().map(|value| value.as_str()),
      Self::BreakGlass { .. } => None,
    }
  }

  fn winner_response(&self) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let Self::Ipm(result) = self else {
      return Ok(None);
    };
    let Some(token) = result.one_time_token.as_ref().map(|value| value.as_str()) else {
      return Ok(None);
    };
    let credential = result
      .winner_credential
      .clone()
      .context("winning IPM credential response was not captured transactionally")?;
    #[derive(Serialize)]
    struct Response<'a> {
      credential: crate::ipm::RedactedIpmCredential,
      token: &'a str,
    }
    Ok(Some(Zeroizing::new(serde_json::to_vec(&Response {
      credential,
      token,
    })?)))
  }
}

async fn apply_effect(
  transaction: &mut crate::admin_mutation::FencedCoordinatorTransaction<'_>,
  ipm: &IpmRuntime,
  actor: &IpmActor,
  operation: &SharedStagedOperation,
  request_id: &str,
  maximum_break_glass_ttl: u64,
) -> anyhow::Result<AppliedEffect> {
  if let Some(mutation) = operation.ipm_mutation()? {
    return Ok(AppliedEffect::Ipm(
      ipm
        .apply_admin_mutation_tx(
          transaction.transaction(),
          actor,
          &operation.operational_precondition_revision,
          mutation,
        )
        .await?,
    ));
  }
  ipm
    .validate_admin_mutation_tx_precondition(
      transaction.transaction(),
      &operation.operational_precondition_revision,
    )
    .await?;
  sqlx::query("LOCK TABLE oxibelt_admin_break_glass_activations IN SHARE ROW EXCLUSIVE MODE")
    .execute(&mut **transaction.transaction())
    .await?;
  let namespace = transaction.store().namespace().to_string();
  match operation
    .break_glass_mutation()?
    .context("shared mutation has no typed effect")?
  {
    BreakGlassStagedMutation::Activate { ttl_seconds } => {
      ensure!(
        (1..=maximum_break_glass_ttl).contains(&ttl_seconds),
        "break-glass activation TTL is outside the configured bound"
      );
      let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_break_glass_activations
          WHERE namespace=$1 AND principal=$2 AND revoked_at IS NULL AND expires_at>now())",
      )
      .bind(&namespace)
      .bind(&operation.principal)
      .fetch_one(&mut **transaction.transaction())
      .await?;
      ensure!(!active, "an active break-glass activation already exists");
      let checkpoint =
        capture_break_glass_checkpoint_tx(transaction.transaction(), &namespace, request_id)
          .await?;
      let expires_at: String =
        sqlx::query_scalar("SELECT (now() + make_interval(secs => $1::double precision))::text")
          .bind(ttl_seconds as f64)
          .fetch_one(&mut **transaction.transaction())
          .await?;
      let activation = create_break_glass_activation_tx(
        transaction.transaction(),
        &namespace,
        request_id,
        &operation.principal,
        &["admin".to_string()],
        request_id,
        &expires_at,
      )
      .await?;
      Ok(AppliedEffect::BreakGlass {
        checkpoint,
        safe_response: json!({"ok":true,"activation":activation}),
      })
    }
    BreakGlassStagedMutation::Revoke { id } => {
      let checkpoint =
        capture_break_glass_checkpoint_tx(transaction.transaction(), &namespace, &id).await?;
      ensure!(
        revoke_break_glass_activation_tx(
          transaction.transaction(),
          &namespace,
          &id,
          &operation.principal,
        )
        .await?,
        "break-glass activation was not active"
      );
      Ok(AppliedEffect::BreakGlass {
        checkpoint,
        safe_response: json!({"ok":true,"activation_id":id}),
      })
    }
  }
}

enum SharedEffectCheckpoint {
  Ipm(IpmMutationCheckpoint),
  BreakGlass(crate::admin_mutation::BreakGlassMutationCheckpoint),
}

#[derive(Serialize)]
struct SharedCheckpointWire<'a> {
  format: &'static str,
  kind: &'static str,
  payload: &'a [u8],
}

#[derive(Deserialize)]
struct SharedCheckpointWireOwned {
  format: String,
  kind: String,
  payload: Vec<u8>,
}

impl SharedEffectCheckpoint {
  fn encode(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let (kind, payload) = match self {
      Self::Ipm(checkpoint) => ("ipm", checkpoint.encode_plaintext()?),
      Self::BreakGlass(checkpoint) => ("break_glass", checkpoint.encode_plaintext()?),
    };
    Ok(Zeroizing::new(serde_json::to_vec(&SharedCheckpointWire {
      format: "oxibelt-shared-effect-checkpoint-v1",
      kind,
      payload: &payload,
    })?))
  }

  fn decode(encoded: &[u8]) -> anyhow::Result<Self> {
    let wire: SharedCheckpointWireOwned = serde_json::from_slice(encoded)?;
    ensure!(
      wire.format == "oxibelt-shared-effect-checkpoint-v1",
      "unsupported shared checkpoint format"
    );
    let payload = Zeroizing::new(wire.payload);
    match wire.kind.as_str() {
      "ipm" => Ok(Self::Ipm(IpmMutationCheckpoint::decode_plaintext(
        &payload,
      )?)),
      "break_glass" => Ok(Self::BreakGlass(
        crate::admin_mutation::BreakGlassMutationCheckpoint::decode_plaintext(&payload)?,
      )),
      _ => bail!("unsupported shared checkpoint kind"),
    }
  }
}

fn deterministic_canary(request_id: &str, members: &[String]) -> anyhow::Result<String> {
  members
    .iter()
    .min_by_key(|member| {
      let mut hasher = Sha256::new();
      hasher.update(b"oxibelt-admin-mutation-canary-v1\0");
      hasher.update(request_id.as_bytes());
      hasher.update(b"\0");
      hasher.update(member.as_bytes());
      hasher.finalize()
    })
    .cloned()
    .context("fixed membership is empty")
}

fn replayed_result(operation: &SharedStagedOperation) -> SharedPublishResult {
  SharedPublishResult {
    revision: operation.candidate_revision.clone(),
    digest: operation.candidate_digest.clone(),
  }
}

fn restored_response() -> serde_json::Value {
  json!({"ok":true,"restored":true,"token_recoverable":false})
}
