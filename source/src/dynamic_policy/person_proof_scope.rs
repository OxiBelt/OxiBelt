use crate::config::DynamicPolicyConfig;

use super::{DynamicPolicy, DynamicPolicyRequest, DynamicPolicySnapshot, DynamicPolicySubjectType};

impl DynamicPolicySnapshot {
  pub(super) fn needs_person_proof_clearance_for_request(
    &self,
    config: &DynamicPolicyConfig,
    request: DynamicPolicyRequest<'_>,
  ) -> bool {
    let request_path = if config.matching.normalize_path {
      crate::waf::normalization::normalize_path(request.path)
    } else {
      request.path.to_string()
    };
    self.policies.iter().any(|policy| {
      policy.subject_type == DynamicPolicySubjectType::PersonProofClearance
        && policy.matches_request_scope(config, &request, &request_path)
    })
  }
}

impl DynamicPolicy {
  pub(super) fn matches_request_scope(
    &self,
    config: &DynamicPolicyConfig,
    request: &DynamicPolicyRequest<'_>,
    request_path: &str,
  ) -> bool {
    if let Some(method) = &self.method
      && method != request.method
    {
      return false;
    }
    if config.matching.trust_route_name
      && let Some(route_name) = &self.route_name
      && route_name != request.route_name
    {
      return false;
    }
    if let Some(path_prefix) = &self.path_prefix
      && !crate::routes::path_prefix_matches(path_prefix, request_path)
    {
      return false;
    }
    true
  }
}
