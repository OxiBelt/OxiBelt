// Reserved, fail-closed admin_cluster building blocks. Configuration validation
// rejects this rollout mode until the server/worker execution path is wired.
#[allow(dead_code)]
mod artifact;
#[allow(dead_code)]
mod artifact_store;
mod envelope;
mod error;
mod ledger;
mod response;
#[allow(dead_code)]
mod rollout;
#[allow(dead_code)]
mod rollout_store;
mod runtime;
mod store;
mod verifier;

pub use envelope::{
  MutationEnvelope, MutationSignature, MutationTarget, SignatureSuite, TranscriptContext,
  UnsignedMutationEnvelope, encode_mutation_header, mutation_transcript, parse_mutation_header,
};
pub use error::{MutationProtocolError, MutationProtocolErrorKind};
pub(crate) use ledger::MutationRecord;
pub use response::{
  IDEMPOTENT_REPLAY_HEADER, MUTATION_REQUEST_ID_HEADER, MUTATION_REVISION_HEADER,
  MutationResponseMetadata, attach_mutation_response_headers,
};
pub(crate) use runtime::{
  AdminMutationRuntime, MutationAdmission, MutationAdmissionError, MutationConflict,
};
pub use verifier::{SignerBinding, SignerRegistry, VerifiedMutation};

pub const MUTATION_HEADER: &str = "x-oxibelt-mutation";

#[cfg(test)]
mod artifact_postgres_tests;
#[cfg(test)]
mod store_postgres_tests;
#[cfg(test)]
mod tests;
