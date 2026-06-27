#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum DynamicPolicyAction {
  Allow,
  Challenge,
  Reject,
  RateLimit,
  SilentClose,
}

impl DynamicPolicyAction {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Allow => "allow",
      Self::Challenge => "challenge",
      Self::Reject => "reject",
      Self::RateLimit => "rate_limit",
      Self::SilentClose => "silent_close",
    }
  }
}
