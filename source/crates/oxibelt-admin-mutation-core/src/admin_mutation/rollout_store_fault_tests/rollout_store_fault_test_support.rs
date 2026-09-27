use super::*;

pub(super) struct ActiveFixture {
  pub(super) pool: sqlx::PgPool,
  pub(super) namespace: String,
  pub(super) store: MutationStore,
  pub(super) member_ids: Vec<String>,
  pub(super) members: Vec<MemberFence>,
  pub(super) exact: ExactMembership,
  pub(super) coordinator: CoordinatorFence,
  pub(super) prior_digest: String,
  pub(super) candidate_digest: String,
}

impl ActiveFixture {
  pub(super) async fn new(pool: &sqlx::PgPool, label: &str, state: MutationState) -> Self {
    let namespace = unique_namespace(label);
    let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("cluster store");
    let prior_digest = sha256_digest(format!("{label} prior").as_bytes());
    let candidate_digest = sha256_digest(format!("{label} candidate").as_bytes());
    let member_ids = vec!["edge-00".to_string(), "edge-01".to_string()];
    let mut members = Vec::new();
    for instance_id in &member_ids {
      let fence = heartbeat_fenced(
        &store,
        &heartbeat(instance_id, &format!("boot-{instance_id}"), &prior_digest),
      )
      .await
      .expect("fixture heartbeat");
      publish_head(&store, &fence, &prior_digest, true)
        .await
        .expect("fixture resource head");
      members.push(fence);
    }
    store
      .initialize_revision(
        RESOURCE,
        PRIOR,
        &prior_digest,
        Some(CLUSTER),
        Some(MEMBERSHIP),
      )
      .await
      .expect("fixture logical head");
    let claim = claim(&candidate_digest);
    assert!(matches!(
      store.claim(&claim).await.expect("fixture mutation claim"),
      ClaimOutcome::Claimed(_)
    ));
    register_targets(&store, REQUEST_ID, &member_ids)
      .await
      .expect("fixture target set");
    if state != MutationState::Claimed {
      sqlx::query(
        "UPDATE oxibelt_admin_mutations SET state=$3,state_version=state_version+1,
           phase_started_at=now(),phase_deadline_at=now()+interval '5 minutes',
           rollback_deadline_at=CASE WHEN $3='rolling_back'
             THEN now()+interval '5 minutes' ELSE rollback_deadline_at END
          WHERE namespace=$1 AND request_id=$2",
      )
      .bind(&namespace)
      .bind(REQUEST_ID)
      .bind(state.as_str())
      .execute(pool)
      .await
      .expect("fixture durable state");
    }
    let exact = prove_exact_resource_membership(
      &store,
      CLUSTER,
      MEMBERSHIP,
      &member_ids,
      BUILD,
      CAPABILITY,
      KEY,
      RESOURCE,
    )
    .await
    .expect("fixture exact membership");
    let coordinator = acquire_coordinator_fence(&store, REQUEST_ID, &members[0], &exact, 300)
      .await
      .expect("fixture coordinator query")
      .expect("fixture coordinator");
    Self {
      pool: pool.clone(),
      namespace,
      store,
      member_ids,
      members,
      exact,
      coordinator,
      prior_digest,
      candidate_digest,
    }
  }

  pub(super) async fn cleanup(&self) {
    cleanup(&self.pool, &self.namespace).await;
  }
}
