use std::time::Duration;

use http::Method;
use oxibelt::admin_client::{AdminClient, AdminClientOptions, DEFAULT_ADMIN_URL};
use serde_json::json;
use url::Url;

use super::*;

#[test]
fn auth_check_uses_ipm_simulate_shape() {
  let command = Command::Auth(AuthCommand {
    command: AuthSubcommand::Check(AuthCheckArgs {
      action: "config:GetStatus".to_string(),
      resource: "*".to_string(),
    }),
  });
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .expect("runtime");
  let client = dummy_client();
  let plan = runtime
    .block_on(plan_command(&client, &command))
    .expect("plan");
  assert_eq!(plan.method, Method::POST);
  assert_eq!(plan.endpoint, "/admin/v1/ipm/simulate");
  assert_eq!(
    plan.body,
    Some(json!({ "action": "config:GetStatus", "resource": "*" }))
  );
}

fn dummy_client() -> AdminClient {
  oxibelt::tls::install_default_provider().expect("provider");
  let options = AdminClientOptions::new(
    Url::parse(DEFAULT_ADMIN_URL).expect("url"),
    "test-token".to_string(),
    Duration::from_secs(1),
  );
  AdminClient::new(options).expect("client")
}
