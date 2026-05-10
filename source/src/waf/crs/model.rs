use std::collections::HashMap;

use http::{HeaderMap, StatusCode, Version};
use tracing::warn;

use super::super::{WafBodyInput, WafRequestInput, WafResponseInput};
use super::actions::CrsAction;
use super::engine::{CrsEngine, CrsHitKey};
use super::operators::CrsOperator;
use super::transforms::{CrsTransform, apply_transforms};
use super::variables::CrsVariable;

#[derive(Clone)]
pub(super) enum CrsEntry {
  Rule(Box<CrsRule>),
  Marker(String),
}

#[derive(Clone)]
pub(super) struct CrsRule {
  pub(super) id: String,
  pub(super) phase: u8,
  pub(super) variables: Vec<CrsVariable>,
  pub(super) operator: CrsOperator,
  pub(super) transforms: Vec<CrsTransform>,
  pub(super) actions: Vec<CrsAction>,
  pub(super) tags: Vec<String>,
  pub(super) msg: Option<String>,
  pub(super) skip_after: Option<String>,
  pub(super) chain: Vec<CrsRule>,
  pub(super) expects_chain: bool,
  pub(super) hit_key: Option<CrsHitKey>,
}

impl CrsRule {
  pub(super) fn matches(
    &self,
    tx: &mut CrsTransaction<'_>,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<bool> {
    if !self.paranoia_enabled(tx.engine.paranoia_level) {
      return Ok(false);
    }
    if !self.variables_match(tx, response)? {
      return Ok(false);
    }
    for chained in &self.chain {
      if !chained.variables_match(tx, response)? {
        return Ok(false);
      }
    }
    Ok(true)
  }

  fn variables_match(
    &self,
    tx: &mut CrsTransaction<'_>,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<bool> {
    let values = self
      .variables
      .iter()
      .flat_map(|variable| {
        variable.values(tx, response).unwrap_or_else(|error| {
          warn!(error = %error, "failed to resolve CRS variable");
          Vec::new()
        })
      })
      .collect::<Vec<_>>();
    for value in values {
      let transformed = apply_transforms(value.as_str(), &self.transforms);
      if self.operator.matches(&transformed, tx)? {
        tx.matched_var = Some(transformed);
        return Ok(true);
      }
    }
    Ok(false)
  }

  pub(super) fn apply_actions(
    &self,
    tx: &mut CrsTransaction<'_>,
    contribute_to_blocking_score: bool,
  ) -> anyhow::Result<()> {
    for action in &self.actions {
      action.apply(tx, contribute_to_blocking_score)?;
    }
    for chained in &self.chain {
      for action in &chained.actions {
        action.apply(tx, contribute_to_blocking_score)?;
      }
    }
    Ok(())
  }

  fn paranoia_enabled(&self, configured: u8) -> bool {
    self
      .tags
      .iter()
      .filter_map(|tag| tag.strip_prefix("paranoia-level/"))
      .filter_map(|level| level.parse::<u8>().ok())
      .next()
      .map(|level| level <= configured)
      .unwrap_or(true)
  }
}

pub(super) struct CrsTransaction<'a> {
  pub(super) engine: &'a CrsEngine,
  pub(super) request: WafRequestInput<'a>,
  pub(super) response: Option<CrsResponseView<'a>>,
  pub(super) tx: HashMap<String, String>,
  pub(super) blocking_tx: HashMap<String, String>,
  pub(super) matched_var: Option<String>,
  pub(super) last_blocking_match: Option<CrsAuditRuleMatch>,
}

impl<'a> CrsTransaction<'a> {
  pub(super) fn new(engine: &'a CrsEngine, request: WafRequestInput<'a>) -> Self {
    let mut tx = HashMap::new();
    tx.insert("critical_anomaly_score".to_string(), "5".to_string());
    tx.insert("error_anomaly_score".to_string(), "4".to_string());
    tx.insert("warning_anomaly_score".to_string(), "3".to_string());
    tx.insert("notice_anomaly_score".to_string(), "2".to_string());
    tx.insert(
      "paranoia_level".to_string(),
      engine.paranoia_level.to_string(),
    );
    tx.insert(
      "blocking_paranoia_level".to_string(),
      engine.paranoia_level.to_string(),
    );
    tx.insert(
      "detection_paranoia_level".to_string(),
      engine.paranoia_level.to_string(),
    );
    tx.insert(
      "inbound_anomaly_score_threshold".to_string(),
      engine.inbound_threshold.to_string(),
    );
    tx.insert(
      "outbound_anomaly_score_threshold".to_string(),
      engine.outbound_threshold.to_string(),
    );
    for key in [
      "anomaly_score",
      "anomaly_score_pl1",
      "anomaly_score_pl2",
      "anomaly_score_pl3",
      "anomaly_score_pl4",
      "inbound_anomaly_score",
      "outbound_anomaly_score",
    ] {
      tx.insert(key.to_string(), "0".to_string());
    }
    let blocking_tx = tx.clone();
    Self {
      engine,
      request,
      response: None,
      tx,
      blocking_tx,
      matched_var: None,
      last_blocking_match: None,
    }
  }

  pub(super) fn get_i64(&self, key: &str) -> i64 {
    self
      .tx
      .get(&key.to_ascii_lowercase())
      .and_then(|value| value.parse::<i64>().ok())
      .unwrap_or(0)
  }

  pub(super) fn set_value(&mut self, key: &str, value: String) {
    self.tx.insert(key.to_ascii_lowercase(), value);
  }

  pub(super) fn get_blocking_i64(&self, key: &str) -> i64 {
    self
      .blocking_tx
      .get(&key.to_ascii_lowercase())
      .and_then(|value| value.parse::<i64>().ok())
      .unwrap_or(0)
  }

  pub(super) fn set_blocking_value(&mut self, key: &str, value: String) {
    self.blocking_tx.insert(key.to_ascii_lowercase(), value);
  }

  pub(super) fn inbound_score(&self) -> i64 {
    let explicit = self.get_i64("inbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_i64(&format!("anomaly_score_pl{level}")))
      .sum()
  }

  pub(super) fn inbound_blocking_score(&self) -> i64 {
    let explicit = self.get_blocking_i64("inbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_blocking_i64(&format!("anomaly_score_pl{level}")))
      .sum()
  }

  pub(super) fn outbound_score(&self) -> i64 {
    let explicit = self.get_i64("outbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_i64(&format!("anomaly_score_pl{level}")))
      .sum()
  }

  pub(super) fn outbound_blocking_score(&self) -> i64 {
    let explicit = self.get_blocking_i64("outbound_anomaly_score");
    if explicit > 0 {
      return explicit;
    }
    (1..=self.engine.paranoia_level)
      .map(|level| self.get_blocking_i64(&format!("anomaly_score_pl{level}")))
      .sum()
  }
}

#[derive(Debug, Clone)]
pub(super) struct CrsAuditRuleMatch {
  pub(super) id: String,
  pub(super) msg: Option<String>,
  pub(super) mode: String,
  pub(super) tuning_name: Option<String>,
}

pub(super) struct CrsResponseView<'a> {
  pub(super) status: StatusCode,
  pub(super) headers: &'a HeaderMap,
  pub(super) body: Option<WafBodyInput<'a>>,
  pub(super) version: Version,
}

impl<'a> CrsResponseView<'a> {
  pub(super) fn from_input(input: WafResponseInput<'a>) -> Self {
    Self {
      status: input.status,
      headers: input.headers,
      body: input.body,
      version: input.version,
    }
  }
}
