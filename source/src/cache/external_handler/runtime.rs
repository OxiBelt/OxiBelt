use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::config::Config;
use crate::metrics::Metrics;

use super::client::{ExternalCacheHttpClient, ExternalCacheLookupHit, ExternalCachePublishBody};
use super::protocol::{
  ExternalCacheEntryMetadata, ExternalCacheLookupRequest, ExternalCachePurgeRequest,
};

#[derive(Clone)]
pub(crate) struct ExternalCacheRuntime {
  handlers: Arc<HashMap<String, Arc<ExternalCacheHandler>>>,
  metrics: Arc<Metrics>,
}

struct ExternalCacheHandler {
  name: String,
  client: ExternalCacheHttpClient,
  limiter: Arc<Semaphore>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExternalCachePurgeReport {
  pub handler: String,
  pub status: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub purged: Option<usize>,
}

impl ExternalCacheRuntime {
  pub(crate) fn disabled(metrics: Arc<Metrics>) -> Self {
    Self {
      handlers: Arc::new(HashMap::new()),
      metrics,
    }
  }

  pub(crate) fn new(config: &Config, metrics: Arc<Metrics>) -> anyhow::Result<Self> {
    if config.cache.external_handlers.is_empty() {
      return Ok(Self::disabled(metrics));
    }
    let mut handlers = HashMap::new();
    for handler in &config.cache.external_handlers {
      let max_body_bytes = handler
        .max_body_bytes
        .unwrap_or(config.cache.max_size_bytes);
      let client = ExternalCacheHttpClient::new(
        handler,
        &config.proxy.trusted_ca_certs,
        config.proxy.buffering.max_memory_body_bytes,
        max_body_bytes,
      )?;
      handlers.insert(
        handler.name.clone(),
        Arc::new(ExternalCacheHandler {
          name: handler.name.clone(),
          client,
          limiter: Arc::new(Semaphore::new(handler.max_inflight_requests)),
        }),
      );
    }
    Ok(Self {
      handlers: Arc::new(handlers),
      metrics,
    })
  }

  pub(crate) async fn lookup(
    &self,
    handler_name: &str,
    request: ExternalCacheLookupRequest,
    temp_dir: Option<&Path>,
  ) -> Option<ExternalCacheLookupHit> {
    let handler = self.handlers.get(handler_name)?;
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "lookup", "saturated");
      return None;
    };
    match handler.client.lookup(&request, temp_dir).await {
      Ok(Some(hit)) => {
        self.record(&handler.name, "lookup", "hit");
        Some(hit)
      }
      Ok(None) => {
        self.record(&handler.name, "lookup", "miss");
        None
      }
      Err(error) => {
        self.record(&handler.name, "lookup", "error");
        warn!(handler = %handler.name, error = %error, "external cache lookup failed");
        None
      }
    }
  }

  pub(crate) fn spawn_fill(
    &self,
    handler_name: String,
    metadata: ExternalCacheEntryMetadata,
    body: ExternalCachePublishBody,
  ) {
    let Some(handler) = self.handlers.get(&handler_name).cloned() else {
      return;
    };
    let metrics = self.metrics.clone();
    let Ok(permit) = handler.limiter.clone().try_acquire_owned() else {
      metrics.record_external_cache_operation(&handler.name, "fill", "saturated");
      return;
    };
    tokio::spawn(async move {
      let _permit = permit;
      match handler.client.fill(metadata, body).await {
        Ok(()) => metrics.record_external_cache_operation(&handler.name, "fill", "stored"),
        Err(error) => {
          metrics.record_external_cache_operation(&handler.name, "fill", "error");
          warn!(handler = %handler.name, error = %error, "external cache fill failed");
        }
      }
    });
  }

  pub(crate) fn spawn_revalidate(
    &self,
    handler_name: String,
    metadata: ExternalCacheEntryMetadata,
  ) {
    let Some(handler) = self.handlers.get(&handler_name).cloned() else {
      return;
    };
    let metrics = self.metrics.clone();
    let Ok(permit) = handler.limiter.clone().try_acquire_owned() else {
      metrics.record_external_cache_operation(&handler.name, "revalidate", "saturated");
      return;
    };
    tokio::spawn(async move {
      let _permit = permit;
      match handler.client.revalidate(&metadata).await {
        Ok(()) => metrics.record_external_cache_operation(&handler.name, "revalidate", "updated"),
        Err(error) => {
          metrics.record_external_cache_operation(&handler.name, "revalidate", "error");
          warn!(handler = %handler.name, error = %error, "external cache revalidation failed");
        }
      }
    });
  }

  pub(crate) async fn purge(
    &self,
    handler_name: &str,
    purge: ExternalCachePurgeRequest,
  ) -> ExternalCachePurgeReport {
    let Some(handler) = self.handlers.get(handler_name) else {
      return ExternalCachePurgeReport {
        handler: handler_name.to_string(),
        status: "not_configured",
        purged: None,
      };
    };
    let Ok(_permit) = handler.limiter.clone().try_acquire_owned() else {
      self.record(&handler.name, "purge", "saturated");
      return ExternalCachePurgeReport {
        handler: handler.name.clone(),
        status: "saturated",
        purged: None,
      };
    };
    match handler.client.purge(&purge).await {
      Ok(response) => {
        self.record(&handler.name, "purge", "ok");
        ExternalCachePurgeReport {
          handler: handler.name.clone(),
          status: "ok",
          purged: response.purged,
        }
      }
      Err(error) => {
        self.record(&handler.name, "purge", "error");
        warn!(handler = %handler.name, error = %error, "external cache purge failed");
        ExternalCachePurgeReport {
          handler: handler.name.clone(),
          status: "error",
          purged: None,
        }
      }
    }
  }

  fn record(&self, handler: &str, operation: &str, outcome: &str) {
    self
      .metrics
      .record_external_cache_operation(handler, operation, outcome);
  }
}

impl fmt::Debug for ExternalCacheRuntime {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("ExternalCacheRuntime")
      .field("handlers", &self.handlers.keys().collect::<Vec<_>>())
      .finish_non_exhaustive()
  }
}
