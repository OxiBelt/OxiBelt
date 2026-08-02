//! Upstream discovery supervisor.
//! Provider snapshots are merged under one generation so route handlers see coherent updates.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::{
  KubernetesDiscoveryResource, UpstreamDiscoveryProvider, UpstreamPoolDiscoveryConfig,
};
use crate::state::AppHandle;

pub(crate) async fn run_dynamic_upstream_discovery(
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
) {
  let mut workers: HashMap<DiscoveryWorkerKey, DiscoveryWorker> = HashMap::new();

  loop {
    if *shutdown.borrow() {
      break;
    }

    let snapshot = state.snapshot();
    let desired = snapshot
      .config
      .upstream_pools
      .iter()
      .flat_map(|pool| {
        pool.discovery.iter().map(|discovery| DiscoveryWorkerKey {
          pool_name: pool.name.clone(),
          provider: discovery.provider,
          discovery_instance_id: discovery.effective_id().to_string(),
        })
      })
      .collect::<HashSet<_>>();
    let stale_keys = workers
      .keys()
      .filter(|key| !desired.contains(*key))
      .cloned()
      .collect::<Vec<_>>();
    for key in stale_keys {
      if let Some(worker) = workers.remove(&key) {
        worker.stop();
      }
      let source = super::discovery_source(key.provider);
      let discovery_instance_id = key.discovery_instance_id.clone();
      if let Err(error) = crate::upstream_control::apply_runtime_pool_update(&state, |config| {
        crate::upstream_control::remove_discovered_servers(
          config,
          &key.pool_name,
          source,
          &discovery_instance_id,
        )
      })
      .await
      {
        tracing::warn!(
          error = %error,
          pool = %key.pool_name,
          provider = ?key.provider,
          "stale upstream discovery cohort removal failed"
        );
      }
    }

    for pool in &snapshot.config.upstream_pools {
      for discovery in pool.discovery.iter().cloned() {
        let key = DiscoveryWorkerKey {
          pool_name: pool.name.clone(),
          provider: discovery.provider,
          discovery_instance_id: discovery.effective_id().to_string(),
        };
        let fingerprint = discovery_fingerprint(&discovery);
        let should_spawn = workers
          .get(&key)
          .is_none_or(|worker| worker.fingerprint != fingerprint || worker.task.is_finished());
        if !should_spawn {
          continue;
        }
        if let Some(worker) = workers.remove(&key) {
          worker.stop();
        }
        workers.insert(
          key.clone(),
          spawn_discovery_worker(state.clone(), key.pool_name.clone(), discovery, fingerprint),
        );
      }
    }

    tokio::select! {
      _ = shutdown.changed() => {}
      _ = tokio::time::sleep(Duration::from_secs(1)) => {}
    }
  }

  for worker in workers.into_values() {
    worker.stop();
  }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DiscoveryWorkerKey {
  pool_name: String,
  provider: UpstreamDiscoveryProvider,
  discovery_instance_id: String,
}

struct DiscoveryWorker {
  fingerprint: String,
  shutdown: watch::Sender<bool>,
  task: JoinHandle<()>,
}

impl DiscoveryWorker {
  fn stop(&self) {
    let _ = self.shutdown.send(true);
    self.task.abort();
  }
}

fn spawn_discovery_worker(
  state: AppHandle,
  pool_name: String,
  discovery: UpstreamPoolDiscoveryConfig,
  fingerprint: String,
) -> DiscoveryWorker {
  let (shutdown, shutdown_rx) = watch::channel(false);
  let task = if is_kubernetes_endpoint_slice_watch(&discovery) {
    tokio::spawn(super::kubernetes::run_kubernetes_endpoint_slice_watch(
      state,
      pool_name,
      discovery,
      shutdown_rx,
    ))
  } else {
    tokio::spawn(run_polling_discovery_worker(
      state,
      pool_name,
      discovery,
      shutdown_rx,
    ))
  };
  DiscoveryWorker {
    fingerprint,
    shutdown,
    task,
  }
}

fn is_kubernetes_endpoint_slice_watch(discovery: &UpstreamPoolDiscoveryConfig) -> bool {
  discovery.provider == UpstreamDiscoveryProvider::Kubernetes
    && discovery.kubernetes_resource == KubernetesDiscoveryResource::EndpointSlice
    && discovery.watch
}

fn discovery_fingerprint(discovery: &UpstreamPoolDiscoveryConfig) -> String {
  format!("{discovery:?}")
}

async fn run_polling_discovery_worker(
  state: AppHandle,
  pool_name: String,
  discovery: UpstreamPoolDiscoveryConfig,
  mut shutdown: watch::Receiver<bool>,
) {
  let mut nomad_index: Option<String> = None;
  loop {
    if *shutdown.borrow() {
      break;
    }

    let snapshot = state.snapshot();
    let fallback_delay = Duration::from_millis(discovery.refresh_interval_ms);
    let result = if discovery.provider == UpstreamDiscoveryProvider::Nomad && discovery.watch {
      match super::nomad::discover_nomad_servers(
        &snapshot.control_http,
        &discovery,
        nomad_index.as_deref(),
      )
      .await
      {
        Ok(result) => {
          nomad_index = result.index;
          Ok((result.servers, result.delay))
        }
        Err(error) => Err(error),
      }
    } else {
      super::discover_servers(&snapshot.control_http, &discovery).await
    };
    let delay = match result {
      Ok((servers, delay)) => {
        if let Err(error) =
          super::apply_discovered_servers(&state, &pool_name, &discovery, servers).await
        {
          tracing::warn!(
            error = %error,
            pool = %pool_name,
            provider = ?discovery.provider,
            "dynamic upstream discovery update rejected; keeping previous pool state"
          );
        }
        delay
      }
      Err(error) => {
        tracing::warn!(
          error = %error,
          pool = %pool_name,
          provider = ?discovery.provider,
          "dynamic upstream discovery failed; keeping previous pool state"
        );
        fallback_delay
      }
    };

    tokio::select! {
      _ = shutdown.changed() => {}
      _ = tokio::time::sleep(delay) => {}
    }
  }
}
