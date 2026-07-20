mod artifact;
mod artifact_store;
mod cluster_command;
mod envelope;
mod error;
mod ledger;
#[cfg(test)]
mod postgres_test_support;
mod response;
mod rollout;
mod rollout_store;
mod runtime;
mod store;
mod store_anchor;
mod verifier;

pub(crate) use cluster_command::{
  ClusterAuthorizationCheck, ClusterCommandAuthorization, ClusterExecutionModel,
  ClusterMutationCommand,
};
pub use envelope::{
  MutationEnvelope, MutationSignature, MutationTarget, SignatureSuite, TranscriptContext,
  UnsignedMutationEnvelope, encode_mutation_header, mutation_transcript, parse_mutation_header,
};
pub use error::{MutationProtocolError, MutationProtocolErrorKind};
#[cfg(test)]
pub(crate) use ledger::{ClaimOutcome, MutationClaim};
pub(crate) use ledger::{MutationRecord, MutationState};
pub use response::{
  IDEMPOTENT_REPLAY_HEADER, MUTATION_REQUEST_ID_HEADER, MUTATION_REVISION_HEADER,
  MutationResponseMetadata, attach_mutation_response_headers,
};
pub(crate) use rollout::RolloutDirective;
#[cfg(test)]
pub(crate) use rollout_store::load_recoverable_mutations;
pub(crate) use rollout_store::{
  CoordinatorFence, FencedCoordinatorTransaction, FencedTargetTransition, MemberFence, MemberWork,
  ResourceHeadUpdate, RolloutTarget, RolloutTransitionPlan, SharedPublicationClaim,
  SharedPublicationOutcome, SharedPublicationState, TargetPlan, TargetState,
  begin_coordinator_transaction, claim_shared_publication, consume_shared_winner_response,
  finish_shared_publication, load_shared_publication,
  publish_checkpoint_in_coordinator_transaction,
};
pub(crate) use runtime::{
  AdminMutationRuntime, ClusterHeartbeatTask, MutationAdmission, MutationAdmissionError,
  MutationConflict, configured_target,
};
pub(crate) use store::{
  BreakGlassMutationCheckpoint, capture_break_glass_checkpoint_tx,
  create_break_glass_activation_tx, restore_break_glass_checkpoint_tx,
  revoke_break_glass_activation_tx,
};
#[cfg(test)]
pub(crate) use store::{
  MutationStore, StoreRolloutMode, claim_tx_with_mode, init_postgres as init_mutation_postgres,
};
pub use verifier::{SignerBinding, SignerRegistry, VerifiedMutation};

pub const MUTATION_HEADER: &str = "x-oxibelt-mutation";

#[cfg(test)]
mod artifact_postgres_tests;
#[cfg(test)]
mod rollout_store_fault_tests;
#[cfg(test)]
mod rollout_store_postgres_tests;
#[cfg(test)]
mod rollout_store_shared_postgres_tests;
#[cfg(test)]
mod store_postgres_tests;
#[cfg(test)]
mod tests;
