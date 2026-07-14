use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationProtocolErrorKind {
  MissingHeader,
  InvalidEnvelope,
  UnsupportedVersion,
  InvalidTimestamp,
  Expired,
  NotYetValid,
  ValidityWindowTooLong,
  DigestMismatch,
  UnknownSigner,
  PrincipalMismatch,
  SignatureSuiteMismatch,
  InvalidSignature,
  DuplicateSigner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationProtocolError {
  kind: MutationProtocolErrorKind,
  detail: &'static str,
}

impl MutationProtocolError {
  pub(crate) const fn new(kind: MutationProtocolErrorKind, detail: &'static str) -> Self {
    Self { kind, detail }
  }

  pub const fn kind(&self) -> MutationProtocolErrorKind {
    self.kind
  }

  pub const fn detail(&self) -> &'static str {
    self.detail
  }

  pub const fn code(&self) -> &'static str {
    use MutationProtocolErrorKind as Kind;

    match self.kind {
      Kind::MissingHeader => "mutation_required",
      Kind::DigestMismatch => "mutation_digest_mismatch",
      Kind::Expired => "mutation_expired",
      Kind::NotYetValid => "mutation_not_yet_valid",
      Kind::UnknownSigner
      | Kind::PrincipalMismatch
      | Kind::SignatureSuiteMismatch
      | Kind::InvalidSignature => "invalid_mutation_signature",
      Kind::DuplicateSigner
      | Kind::InvalidEnvelope
      | Kind::InvalidTimestamp
      | Kind::UnsupportedVersion
      | Kind::ValidityWindowTooLong => "invalid_mutation_envelope",
    }
  }

  pub const fn http_status(&self) -> http::StatusCode {
    use MutationProtocolErrorKind as Kind;

    match self.kind {
      Kind::MissingHeader => http::StatusCode::PRECONDITION_REQUIRED,
      Kind::UnknownSigner
      | Kind::PrincipalMismatch
      | Kind::SignatureSuiteMismatch
      | Kind::InvalidSignature => http::StatusCode::UNAUTHORIZED,
      Kind::DigestMismatch
      | Kind::DuplicateSigner
      | Kind::Expired
      | Kind::InvalidEnvelope
      | Kind::InvalidTimestamp
      | Kind::NotYetValid
      | Kind::UnsupportedVersion
      | Kind::ValidityWindowTooLong => http::StatusCode::BAD_REQUEST,
    }
  }
}

impl fmt::Display for MutationProtocolError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.detail)
  }
}

impl std::error::Error for MutationProtocolError {}
