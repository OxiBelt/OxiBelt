use anyhow::bail;

pub(super) async fn ensure_principal_unreferenced(
  store: &super::store::IpmStore,
  principal: &str,
) -> anyhow::Result<()> {
  let refs: i64 = sqlx::query_scalar(
    "SELECT
       (SELECT count(*) FROM oxibelt_ipm_credentials WHERE namespace = $1 AND principal_id = $2)
       +
       (SELECT count(*) FROM oxibelt_ipm_policy_bindings WHERE namespace = $1 AND principal_id = $2)",
  )
  .bind(store.namespace())
  .bind(principal)
  .fetch_one(store.pool())
  .await?;
  if refs > 0 {
    bail!("IPM principal {principal} is still referenced");
  }
  Ok(())
}

pub(super) async fn ensure_policy_unreferenced(
  store: &super::store::IpmStore,
  policy: &str,
) -> anyhow::Result<()> {
  let refs: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_ipm_policy_bindings WHERE namespace = $1 AND policy_id = $2",
  )
  .bind(store.namespace())
  .bind(policy)
  .fetch_one(store.pool())
  .await?;
  if refs > 0 {
    bail!("IPM policy {policy} is still referenced");
  }
  Ok(())
}
