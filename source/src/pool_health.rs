use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use tokio::sync::watch;
use tracing::{debug, warn};

use crate::config::{HealthCheckMode, HttpVersion, UpstreamPoolConfig};
use crate::state::{AppHandle, AppSnapshot, UpstreamBody};

pub(crate) async fn run_pool_health_checks(state: AppHandle, mut shutdown: watch::Receiver<bool>) {
  let mut next_checks = HashMap::new();

  loop {
    if *shutdown.borrow() {
      break;
    }

    let snapshot = state.snapshot();
    let now = Instant::now();
    let mut next_sleep = Duration::from_secs(5);

    for pool in &snapshot.config.upstream_pools {
      if pool.health_check.mode != HealthCheckMode::Active || !pool.health_check.enabled {
        continue;
      }

      for index in 0..pool.servers.len() {
        let upstream_name = crate::pools::synthetic_upstream_name(&pool.name, index);
        let due = next_checks.entry(upstream_name.clone()).or_insert(now);
        if *due > now {
          next_sleep = next_sleep.min(*due - now);
          continue;
        }

        *due = now + Duration::from_millis(pool.health_check.interval_ms);
        if check_pool_server(snapshot.clone(), pool, index, &upstream_name).await {
          snapshot.pools.report_success(&upstream_name);
        } else {
          snapshot.pools.report_failure(&upstream_name);
        }
      }
    }

    tokio::select! {
      _ = shutdown.changed() => {}
      _ = tokio::time::sleep(next_sleep) => {}
    }
  }
}

async fn check_pool_server(
  snapshot: Arc<AppSnapshot>,
  pool: &UpstreamPoolConfig,
  index: usize,
  upstream_name: &str,
) -> bool {
  let server = &pool.servers[index];
  let mut url = server.origin.clone();
  url.set_path(&pool.health_check.path);
  url.set_query(None);
  url.set_fragment(None);

  let uri = match url.as_str().parse::<http::Uri>() {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "active health check URI is invalid");
      return false;
    }
  };

  let Some(client) =
    snapshot
      .clients
      .for_upstream_version(upstream_name, server.origin.scheme(), HttpVersion::H1)
  else {
    warn!(
      upstream = upstream_name,
      "active health check upstream client is not configured"
    );
    return false;
  };

  let request = match http::Request::builder()
    .method(http::Method::GET)
    .uri(uri)
    .body(empty_body())
  {
    Ok(request) => request,
    Err(error) => {
      warn!(error = %error, upstream = upstream_name, "failed to build active health check request");
      return false;
    }
  };

  let response = match tokio::time::timeout(
    Duration::from_millis(pool.health_check.timeout_ms),
    client.request(request),
  )
  .await
  {
    Ok(Ok(response)) => response,
    Ok(Err(error)) => {
      debug!(error = %error, upstream = upstream_name, "active health check request failed");
      return false;
    }
    Err(_) => {
      debug!(
        upstream = upstream_name,
        "active health check request timed out"
      );
      return false;
    }
  };

  let healthy = pool
    .health_check
    .expected_status
    .iter()
    .any(|status| *status == response.status().as_u16());
  debug!(
    upstream = upstream_name,
    status = response.status().as_u16(),
    healthy,
    "active health check completed"
  );
  healthy
}

fn empty_body() -> UpstreamBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
    .boxed()
}
