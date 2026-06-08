use std::net::SocketAddr;
use std::path::Path;

use crate::config::Config;

use super::admin_resource_scope_tests::{
  log_safe_text, parse_scoped_config, try_scoped_admin_response,
};

#[tokio::test]
async fn stream_pool_status_requires_status_resource() {
  let Some(denied) = try_scoped_admin_response(
    "resource-stream-status-deny",
    stream_pool_scope_config,
    "GET",
    "/admin/v1/stream-pools/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    denied.starts_with("HTTP/1.1 403 Forbidden")
      && denied.contains(r#""action":"stream-pool:GetStatus""#)
      && denied.contains(r#""resource":"oxibelt:oxibelt:stream-pool:status/current""#),
    "stream pool status should require status/current: {}",
    log_safe_text(&denied)
  );

  let Some(allowed) = try_scoped_admin_response(
    "resource-stream-status-allow",
    stream_pool_status_scope_config,
    "GET",
    "/admin/v1/stream-pools/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    allowed.starts_with("HTTP/1.1 200 OK")
      && allowed.contains(r#""generation":0"#)
      && allowed.contains(r#""etag":"\"oxibelt-stream-pools-0\"""#),
    "stream pool status permission should return the status ETag: {}",
    log_safe_text(&allowed)
  );
}

fn stream_pool_scope_config(cert_path: &Path, key_path: &Path, admin_bind: SocketAddr) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[stream_upstream_pools]]
name = "edge-stream"

[[stream_upstream_pools.servers]]
id = "primary"
origin = "tcp://primary.internal.example:9443"

[[ipm.policies.statements]]
effect = "allow"
actions = ["stream-pool:UpdateServer"]
resources = ["oxibelt:oxibelt:stream-pool:edge-stream"]
"#,
  )
}

fn stream_pool_status_scope_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_scoped_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["stream-pool:GetStatus"]
resources = ["oxibelt:oxibelt:stream-pool:status/current"]
"#,
  )
}
