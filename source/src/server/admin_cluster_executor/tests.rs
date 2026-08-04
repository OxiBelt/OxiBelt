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
fn membership_mutations_derive_exact_shared_staged_authorization() {
  let epoch = format!("sha256:{}", "a".repeat(64));
  let cases = [
    (
      "/admin/v1/membership/transitions",
      r#"{"version":1,"kind":"initialize","expected_active_epoch":null,"member":null}"#.to_string(),
      "membership:Propose",
      "membership/current".to_string(),
    ),
    (
      "/admin/v1/membership/transitions/join-1/activate",
      format!(r#"{{"version":1,"transition_id":"join-1","expected_target_epoch":"{epoch}"}}"#),
      "membership:Activate",
      "membership/transition/join-1".to_string(),
    ),
    (
      "/admin/v1/membership/transitions/join-1/cancel",
      format!(r#"{{"version":1,"transition_id":"join-1","expected_target_epoch":"{epoch}"}}"#),
      "membership:Cancel",
      "membership/transition/join-1".to_string(),
    ),
  ];

  for (path, body, action, resource) in cases {
    let (kind, checks, apply) = derive_operation(
      &Method::POST,
      path,
      body.as_bytes(),
      "membership-controller",
    )
    .expect("membership mutation should be rollout eligible");
    assert_eq!(kind, OperationKind::SharedStaged, "{path}");
    assert_eq!(apply, None, "{path}");
    assert_eq!(
      checks,
      vec![ClusterAuthorizationCheck {
        action: action.to_string(),
        resource,
      }],
      "{path}"
    );
  }
}

#[test]
fn membership_derivation_keeps_non_mutations_and_malformed_routes_fail_closed() {
  let epoch = format!("sha256:{}", "a".repeat(64));
  let proposal = r#"{"version":1,"kind":"initialize","expected_active_epoch":null,"member":null}"#;
  let matching =
    format!(r#"{{"version":1,"transition_id":"join-1","expected_target_epoch":"{epoch}"}}"#);
  let mismatched =
    format!(r#"{{"version":1,"transition_id":"join-2","expected_target_epoch":"{epoch}"}}"#);
  let cases = [
    (Method::GET, "/admin/v1/membership", b"".as_slice()),
    (
      Method::GET,
      "/admin/v1/membership/transitions",
      proposal.as_bytes(),
    ),
    (
      Method::POST,
      "/admin/v1/membership/transitions/join-1/readiness",
      b"{}".as_slice(),
    ),
    (
      Method::GET,
      "/admin/v1/membership/transitions/join-1/catchup",
      b"".as_slice(),
    ),
    (
      Method::POST,
      "/admin/v1/membership/transitions//activate",
      matching.as_bytes(),
    ),
    (
      Method::POST,
      "/admin/v1/membership/transitions/join-1/nested/activate",
      matching.as_bytes(),
    ),
    (
      Method::POST,
      "/admin/v1/membership/unknown",
      b"{}".as_slice(),
    ),
    (
      Method::POST,
      "/admin/v1/membership/transitions/join-1/activate",
      mismatched.as_bytes(),
    ),
    (
      Method::POST,
      "/admin/v1/membership/transitions/join-1/cancel",
      mismatched.as_bytes(),
    ),
  ];

  for (method, path, body) in cases {
    assert!(
      derive_operation(&method, path, body, "membership-controller").is_err(),
      "unexpectedly admitted {method} {path}"
    );
  }
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
