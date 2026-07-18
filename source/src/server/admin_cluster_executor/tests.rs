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
fn secret_reference_activation_stays_fail_closed() {
  assert!(
    derive_operation(
      &Method::POST,
      "/admin/v1/config/secret-references/update",
      b"{}",
      "controller",
    )
    .is_err()
  );
}
