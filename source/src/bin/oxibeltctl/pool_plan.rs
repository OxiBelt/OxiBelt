use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde_json::{Value, json};

use crate::cli::{PoolCommand, PoolServerArg, PoolSubcommand};
use crate::plan::{
  RequestPlan, delete, get, patch_json, path_id, post_json, remove_nulls, with_etag,
};
use crate::resource_hint;

pub(crate) async fn plan_pool(
  client: &AdminClient,
  command: &PoolCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    PoolSubcommand::Status => get(
      "/admin/v1/upstream-pools/status",
      "upstream-pool:GetStatus",
      resource_hint::upstream_pool_status(),
    ),
    PoolSubcommand::List => get("/admin/v1/upstream-pools", "upstream-pool:List", "*"),
    PoolSubcommand::Get(args) => get(
      &format!("/admin/v1/upstream-pools/{}", path_id(&args.pool)?),
      "upstream-pool:Get",
      &args.pool,
    ),
    PoolSubcommand::AddServer(args) => {
      let etag = pool_etag_or_current(client, &args.etag).await?;
      with_etag(
        post_json(
          &format!("/admin/v1/upstream-pools/{}/servers", path_id(&args.pool)?),
          json!({
            "id": args.id,
            "origin": args.origin,
            "state": args.state,
            "weight": args.weight,
            "max_conns": args.max_conns,
            "backup": args.backup,
          }),
          "upstream-pool:AddServer",
          &resource_hint::upstream_pool_server(&args.pool, &args.id),
        )?,
        etag,
      )
    }
    PoolSubcommand::UpdateServer(args) => {
      let etag = pool_etag_or_current(client, &args.etag).await?;
      with_etag(
        pool_patch(
          &args.pool,
          &args.server_id,
          json!({
            "state": args.state,
            "weight": args.weight,
            "max_conns": args.max_conns,
            "backup": args.backup,
          }),
        )?,
        etag,
      )
    }
    PoolSubcommand::RemoveServer(args) => {
      let etag = pool_etag_or_current(client, &args.etag).await?;
      with_etag(
        delete(
          &format!(
            "/admin/v1/upstream-pools/{}/servers/{}",
            path_id(&args.pool)?,
            path_id(&args.server_id)?
          ),
          "upstream-pool:RemoveServer",
          &resource_hint::upstream_pool_server(&args.pool, &args.server_id),
        )?,
        etag,
      )
    }
    PoolSubcommand::Ready(args) => pool_state(client, args, "ready").await,
    PoolSubcommand::Drain(args) => pool_state(client, args, "drain").await,
    PoolSubcommand::Down(args) => pool_state(client, args, "down").await,
    PoolSubcommand::Maintenance(args) => pool_state(client, args, "maintenance").await,
  }
}

async fn pool_etag_or_current(
  client: &AdminClient,
  etag: &Option<String>,
) -> anyhow::Result<String> {
  match etag {
    Some(etag) => Ok(etag.clone()),
    None => current_pool_etag(client).await,
  }
}

async fn current_pool_etag(client: &AdminClient) -> anyhow::Result<String> {
  let response = client
    .request_json(Method::GET, "/admin/v1/upstream-pools/status", None, None)
    .await?;
  if !response.status.is_success() {
    bail!(
      "failed to fetch current upstream-pool ETag: {}",
      response.status
    );
  }
  let value =
    serde_json::from_slice::<Value>(&response.body).context("upstream-pool status was not JSON")?;
  value
    .get("etag")
    .and_then(Value::as_str)
    .map(str::to_string)
    .context("upstream-pool status response did not include etag")
}

fn pool_patch(pool: &str, server_id: &str, body: Value) -> anyhow::Result<RequestPlan> {
  patch_json(
    &format!(
      "/admin/v1/upstream-pools/{}/servers/{}",
      path_id(pool)?,
      path_id(server_id)?
    ),
    remove_nulls(body),
    "upstream-pool:UpdateServer",
    &resource_hint::upstream_pool_server(pool, server_id),
  )
}

async fn pool_state(
  client: &AdminClient,
  args: &PoolServerArg,
  state: &str,
) -> anyhow::Result<RequestPlan> {
  let etag = pool_etag_or_current(client, &args.etag).await?;
  with_etag(
    pool_patch(&args.pool, &args.server_id, json!({ "state": state }))?,
    etag,
  )
}
