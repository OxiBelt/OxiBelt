//! Compile-time contracts for the data-plane package boundary.

#[test]
fn admin_and_person_proof_remain_unconditional_runtime_surfaces() {
  assert!(
    !oxibelt::server::ADMIN_CAPABILITY_FEATURE_KEYS.is_empty(),
    "the data-plane library must retain its integrated Admin capability surface"
  );
  assert_eq!(oxibelt::waf::PERSON_PROOF_API_VERSION, "1.0.0");
  let _ = std::any::TypeId::of::<oxibelt::waf::WafPersonProofConfig>();
}
