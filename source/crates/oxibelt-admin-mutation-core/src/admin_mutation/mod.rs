pub mod artifact;
pub mod artifact_store;
pub mod cluster_command;
pub mod envelope;
pub mod error;
pub mod ledger;
pub mod membership;
pub mod membership_crypto;
pub mod membership_store;
#[cfg(test)]
pub(crate) mod postgres_test_support;
pub mod response;
pub mod rollout;
pub mod rollout_store;
pub mod store;
pub mod store_anchor;
pub mod verifier;

pub use cluster_command::{
  ClusterAuthorizationCheck, ClusterCommandAuthorization, ClusterExecutionModel,
  ClusterMutationCommand,
};
pub use envelope::{
  MutationEnvelope, MutationSignature, MutationTarget, SignatureSuite, TranscriptContext,
  UnsignedMutationEnvelope, encode_mutation_header, mutation_transcript, parse_mutation_header,
};
pub use error::{MutationProtocolError, MutationProtocolErrorKind};
pub use ledger::{ClaimOutcome, MutationClaim};
pub use ledger::{MutationRecord, MutationState};
pub use membership::{
  MembershipActivationRequest, MembershipCancelRequest, MembershipMember,
  MembershipReadinessReceipt, MembershipTransitionRequest,
};
pub use membership_store::{
  MembershipArtifactCiphers, MembershipMutationCheckpoint, MembershipTransition,
  apply_membership_proposal_tx, authorize_membership_activation_tx,
  cancel_membership_transition_tx, restore_membership_mutation_tx,
};
pub use response::{
  IDEMPOTENT_REPLAY_HEADER, MUTATION_REQUEST_ID_HEADER, MUTATION_REVISION_HEADER,
  MutationResponseMetadata, attach_mutation_response_headers,
};
pub use rollout::RolloutDirective;
pub use rollout_store::load_recoverable_mutations;
pub use rollout_store::{
  CoordinatorFence, FencedCoordinatorTransaction, FencedTargetTransition, MemberFence, MemberWork,
  ResourceHeadUpdate, RolloutTarget, RolloutTransitionPlan, SharedPublicationClaim,
  SharedPublicationOutcome, SharedPublicationState, TargetPlan, TargetState,
  begin_coordinator_transaction, claim_shared_publication, consume_shared_winner_response,
  finish_shared_publication, load_shared_publication,
  publish_checkpoint_in_coordinator_transaction,
};
pub use store::{
  BreakGlassMutationCheckpoint, capture_break_glass_checkpoint_tx,
  create_break_glass_activation_tx, restore_break_glass_checkpoint_tx,
  revoke_break_glass_activation_tx,
};
pub use store::{
  MutationStore, StoreRolloutMode, claim_tx_with_mode, init_postgres as init_mutation_postgres,
};
pub use verifier::{SignerBinding, SignerRegistry, VerifiedMutation};

pub const MUTATION_HEADER: &str = "x-oxibelt-mutation";

#[cfg(feature = "fuzzing")]
pub fn fuzz_cluster_rollout(data: &[u8]) {
  const MAX_FRAME_BYTES: usize = 32 * 1024;
  let data = &data[..data.len().min(MAX_FRAME_BYTES)];
  cluster_command::fuzz_decode_frame(data);
  rollout::fuzz_classify_rollout(data);
}

#[cfg(test)]
mod artifact_postgres_tests;
#[cfg(test)]
mod rollout_store_fault_tests;
#[cfg(test)]
mod rollout_store_postgres_tests;
#[cfg(test)]
mod rollout_store_shared_postgres_tests;
#[cfg(test)]
mod tests;
