pub(super) fn assert_embedded_build_metadata(version: &serde_json::Value) {
  assert_eq!(version["source_revision"], env!("OXIBELT_SOURCE_REVISION"));
  assert_eq!(
    version["person_proof_api_version"],
    crate::waf::PERSON_PROOF_API_VERSION
  );
  assert_eq!(
    version["person_proof_asset_sha256"],
    env!("OXIBELT_PERSON_PROOF_ASSET_SHA256")
  );
  assert_eq!(
    version["admin_openapi_sha256"],
    env!("OXIBELT_ADMIN_OPENAPI_SHA256")
  );
}
