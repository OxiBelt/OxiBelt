use super::*;

#[test]
fn non_admin_cannot_assign_credential_to_admin_principal() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();

  let error = runtime
    .ensure_actor_may_assign_credential_principal(&actor, None, "admin")
    .expect_err("non-admin actor must not mint credentials for admin principal");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_grant_ipm_admin_group() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let groups = vec!["ipm-admin".to_string()];

  let error = runtime
    .ensure_actor_may_create_principal(&actor, "new-admin", "new-admin@example.com", &groups)
    .expect_err("non-admin actor must not create an ipm-admin principal");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_grant_group_bound_admin_policy() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "admin-policy".to_string(),
    policy("admin-policy", &["ipm:*"]).1,
  );
  snapshot
    .group_bindings
    .insert("ops-admin".to_string(), vec!["admin-policy".to_string()]);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let groups = vec!["ops-admin".to_string()];

  let error = runtime
    .ensure_actor_may_create_principal(&actor, "new-admin", "new-admin@example.com", &groups)
    .expect_err("non-admin actor must not join a group with admin policy bindings");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_patch_subject_into_admin_policy_condition() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "subject-admin".to_string(),
    subject_policy("subject-admin", "ipm:UpdateConfig", "admin@example.com").1,
  );
  snapshot
    .group_bindings
    .insert("ops".to_string(), vec!["subject-admin".to_string()]);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();

  let error = runtime
    .ensure_actor_may_patch_principal(&actor, "operator", Some("admin@example.com"), None)
    .expect_err("non-admin actor must not change subject into an admin-capable condition");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_create_or_bind_admin_policy() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "admin-policy".to_string(),
    policy("admin-policy", &["ipm:*"]).1,
  );
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let admin_policy = runtime.snapshot().policies["admin-policy"].policy.clone();
  let create_error = runtime
    .ensure_actor_may_create_policy(&actor, &admin_policy)
    .expect_err("non-admin actor must not create admin-capable policies");
  assert!(
    create_error
      .to_string()
      .contains("requires an admin-capable")
  );

  let binding = IpmBindingCreate {
    id: Some("operator-admin".to_string()),
    principal: Some("operator".to_string()),
    group: None,
    policy: "admin-policy".to_string(),
    enabled: Some(true),
  };
  let bind_error = runtime
    .ensure_actor_may_create_binding(&actor, &binding)
    .expect_err("non-admin actor must not bind admin-capable policies");
  assert!(bind_error.to_string().contains("requires an admin-capable"));
}

#[test]
fn unknown_group_binding_is_rejected_before_refresh() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot.policies.insert(
    "read-only".to_string(),
    policy("read-only", &["ipm:GetStatus"]).1,
  );
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["admin"].actor.clone();
  let binding = IpmBindingCreate {
    id: Some("missing-group".to_string()),
    principal: None,
    group: Some("missing".to_string()),
    policy: "read-only".to_string(),
    enabled: Some(true),
  };

  let error = runtime
    .ensure_actor_may_create_binding(&actor, &binding)
    .expect_err("unknown groups must not be committed to the IPM store");

  assert!(error.to_string().contains("unknown IPM group missing"));
}

#[test]
fn admin_actor_can_grant_admin_authority() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "admin-policy".to_string(),
    policy("admin-policy", &["ipm:*"]).1,
  );
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["admin"].actor.clone();
  let groups = vec!["ipm-admin".to_string()];
  let binding = IpmBindingCreate {
    id: Some("operator-admin".to_string()),
    principal: Some("operator".to_string()),
    group: None,
    policy: "admin-policy".to_string(),
    enabled: Some(true),
  };

  runtime
    .ensure_actor_may_create_principal(&actor, "new-admin", "new-admin@example.com", &groups)
    .expect("admin actor should be able to create admin-capable principals");
  let admin_policy = runtime.snapshot().policies["admin-policy"].policy.clone();
  runtime
    .ensure_actor_may_create_policy(&actor, &admin_policy)
    .expect("admin actor should be able to create admin-capable policies");
  runtime
    .ensure_actor_may_create_binding(&actor, &binding)
    .expect("admin actor should be able to bind admin-capable policies");
}
