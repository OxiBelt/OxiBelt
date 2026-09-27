//! Integrated Admin mutation adapter and compatibility facade.

#[cfg(test)]
pub(crate) mod postgres_test_support;

mod runtime;

pub(crate) use oxibelt_admin_mutation_core::admin_mutation::{
  BreakGlassMutationCheckpoint, ClusterAuthorizationCheck, ClusterCommandAuthorization,
  ClusterExecutionModel, ClusterMutationCommand, CoordinatorFence, FencedCoordinatorTransaction,
  FencedTargetTransition, MemberFence, MemberWork, MembershipActivationRequest,
  MembershipArtifactCiphers, MembershipCancelRequest, MembershipMember,
  MembershipMutationCheckpoint, MembershipReadinessReceipt, MembershipTransition,
  MembershipTransitionRequest, MutationRecord, MutationState, ResourceHeadUpdate, RolloutDirective,
  RolloutTarget, RolloutTransitionPlan, SharedPublicationClaim, SharedPublicationOutcome,
  SharedPublicationState, TargetPlan, TargetState, apply_membership_proposal_tx,
  authorize_membership_activation_tx, begin_coordinator_transaction,
  cancel_membership_transition_tx, capture_break_glass_checkpoint_tx, claim_shared_publication,
  consume_shared_winner_response, create_break_glass_activation_tx, finish_shared_publication,
  load_shared_publication, publish_checkpoint_in_coordinator_transaction,
  restore_break_glass_checkpoint_tx, restore_membership_mutation_tx,
  revoke_break_glass_activation_tx,
};
#[cfg(test)]
pub(crate) use oxibelt_admin_mutation_core::admin_mutation::{
  ClaimOutcome, MutationClaim, MutationStore, StoreRolloutMode, claim_tx_with_mode,
  init_mutation_postgres, load_recoverable_mutations,
};
pub use oxibelt_admin_mutation_core::admin_mutation::{
  IDEMPOTENT_REPLAY_HEADER, MUTATION_HEADER, MUTATION_REQUEST_ID_HEADER, MUTATION_REVISION_HEADER,
  MutationEnvelope, MutationProtocolError, MutationProtocolErrorKind, MutationResponseMetadata,
  MutationSignature, MutationTarget, SignatureSuite, SignerBinding, SignerRegistry,
  TranscriptContext, UnsignedMutationEnvelope, VerifiedMutation, attach_mutation_response_headers,
  encode_mutation_header, mutation_transcript, parse_mutation_header,
};
pub(crate) use oxibelt_admin_mutation_core::admin_mutation::{
  artifact, artifact_store, cluster_command, envelope, ledger, membership, membership_store,
  rollout, rollout_store, store,
};
pub(crate) use runtime::{
  AdminMutationRuntime, ClusterHeartbeatBootstrap, ClusterHeartbeatTask, LocalMembershipHead,
  MutationAdmission, MutationAdmissionError, MutationConflict, configured_target,
};

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_cluster_rollout(data: &[u8]) {
  oxibelt_admin_mutation_core::admin_mutation::fuzz_cluster_rollout(data)
}

#[cfg(test)]
mod store_postgres_tests;
