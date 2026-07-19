use super::*;

#[test]
fn file_authorization_is_exact_and_normalized() {
  let body = br#"{"operations":[{"op":"put","root":"oxirule","path":"nested/test.oxirule.toml","content":""}],"apply":"oxirule"}"#;
  let (_, checks, _) = derive_operation(&Method::POST, "/admin/v1/files/sync", body, "controller")
    .expect("file operation");
  assert_eq!(
    checks,
    vec![
      ClusterAuthorizationCheck {
        action: "waf:PutOxiRule".into(),
        resource: "oxirule/nested/test.oxirule.toml".into(),
      },
      ClusterAuthorizationCheck {
        action: "waf:ReloadOxiRule".into(),
        resource: "*".into(),
      },
    ]
  );
}

#[test]
fn secret_reference_activation_derives_exact_cluster_authorization() {
  let field = "external_auth/oidc/client_secret_env";
  let body = br#"{"schema_version":1,"field":"external_auth/oidc/client_secret_env","reference":"OXIBELT_NEXT_SECRET"}"#;
  let (kind, checks, apply) = derive_operation(
    &Method::POST,
    "/admin/v1/config/secret-references/update",
    body,
    "controller",
  )
  .expect("typed secret-reference operation should be rollout eligible");
  assert_eq!(kind, OperationKind::SecretReference);
  assert_eq!(apply, None);
  assert_eq!(
    checks,
    vec![ClusterAuthorizationCheck {
      action: "config:UpdateSecretReference".to_string(),
      resource: format!("secret-reference/{}", admin_resource::component(field)),
    }]
  );
}

#[test]
fn secret_reference_apply_evidence_must_match_durable_validation() {
  let operation = ValidatedOperation {
    kind: OperationKind::SecretReference,
    actor: crate::ipm::IpmActor {
      name: "controller".to_string(),
      principal: "controller".to_string(),
      subject: "controller".to_string(),
      groups: Vec::new(),
    },
    previous_revision: "r-1".to_string(),
    operational_precondition_revision: "r-1".to_string(),
    candidate_revision: "r-2".to_string(),
    candidate_digest: format!("sha256:{}", "1".repeat(64)),
    validation_digest: format!("sha256:{}", "2".repeat(64)),
    mutation_request_id: "00000000-0000-4000-8000-000000000001".to_string(),
    body: Zeroizing::new(Vec::new()),
    permissions: ControlPlaneConfigPermissions::default(),
    file_apply: None,
    shared: None,
  };
  assert!(
    operation.matches_validation_evidence(Some("r-2"), Some(&format!("sha256:{}", "2".repeat(64))))
  );
  assert!(
    !operation
      .matches_validation_evidence(Some("r-2"), Some(&format!("sha256:{}", "3".repeat(64))))
  );
}
