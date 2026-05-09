use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

use super::super::{
  WafMode, WafRequestInput, WafResponseInput, WafRuleHitSnapshot, WafTerminalResponse,
};
use super::config::{WafCrsConfig, validate_config};
use super::model::{CrsEntry, CrsResponseView, CrsRule, CrsTransaction};
use super::parser::CrsParser;
use super::utils::crs_phase_name;
use super::variables::CrsVariable;

#[derive(Clone)]
pub(crate) struct CrsEngine {
  enabled: bool,
  pub(super) mode: WafMode,
  pub(super) paranoia_level: u8,
  pub(super) inbound_threshold: i64,
  pub(super) outbound_threshold: i64,
  rules: Vec<CrsEntry>,
  counters: HashMap<CrsHitKey, Arc<AtomicU64>>,
  latest_scores: Arc<std::sync::Mutex<CrsLatestScores>>,
}

impl Default for CrsEngine {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: WafMode::Monitor,
      paranoia_level: 1,
      inbound_threshold: 5,
      outbound_threshold: 4,
      rules: Vec::new(),
      counters: HashMap::new(),
      latest_scores: Arc::new(std::sync::Mutex::new(CrsLatestScores::default())),
    }
  }
}

impl CrsEngine {
  pub(crate) fn compile(
    config: &WafCrsConfig,
    previous_counters: &HashMap<CrsHitKey, Arc<AtomicU64>>,
  ) -> anyhow::Result<Self> {
    if !config.enabled {
      return Ok(Self::default());
    }
    validate_config(config)?;
    let mut parser = CrsParser::new();
    if let Some(path) = &config.setup_file_resolved {
      parser.load_file(path)?;
    }
    for path in &config.rule_files_resolved {
      parser.load_file(path)?;
    }
    let mut rules = parser.entries;
    let mut counters = HashMap::new();
    for entry in &mut rules {
      if let CrsEntry::Rule(rule) = entry {
        let key = CrsHitKey {
          phase: rule.phase,
          id: rule.id.clone(),
          name: rule.msg.clone(),
          mode: config.mode,
        };
        let counter = previous_counters.get(&key).cloned().unwrap_or_default();
        rule.hit_key = Some(key.clone());
        counters.insert(key, counter);
      }
    }
    Ok(Self {
      enabled: true,
      mode: config.mode,
      paranoia_level: config.paranoia_level,
      inbound_threshold: config.inbound_anomaly_score_threshold,
      outbound_threshold: config.outbound_anomaly_score_threshold,
      rules,
      counters,
      latest_scores: Arc::new(std::sync::Mutex::new(CrsLatestScores::default())),
    })
  }

  pub(crate) fn enabled(&self) -> bool {
    self.enabled
  }

  pub(crate) fn active_hit_counters(&self) -> HashMap<CrsHitKey, Arc<AtomicU64>> {
    self.counters.clone()
  }

  pub(crate) fn requires_request_body_inspection(&self) -> bool {
    self.enabled
      && self.rules.iter().any(|entry| match entry {
        CrsEntry::Rule(rule) => {
          matches!(rule.phase, 2)
            && rule
              .variables
              .iter()
              .any(CrsVariable::requires_request_body)
        }
        CrsEntry::Marker(_) => false,
      })
  }

  pub(crate) fn requires_response_body_inspection(&self) -> bool {
    self.enabled
      && self.rules.iter().any(|entry| match entry {
        CrsEntry::Rule(rule) => {
          matches!(rule.phase, 4)
            && rule
              .variables
              .iter()
              .any(CrsVariable::requires_response_body)
        }
        CrsEntry::Marker(_) => false,
      })
  }

  pub(crate) fn rule_hit_snapshots(&self) -> Vec<WafRuleHitSnapshot> {
    let scores = self
      .latest_scores
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .clone();
    let mut snapshots = self
      .counters
      .iter()
      .map(|(key, counter)| WafRuleHitSnapshot {
        scope: "crs".to_string(),
        route: None,
        phase: crs_phase_name(key.phase).to_string(),
        name: key
          .name
          .clone()
          .unwrap_or_else(|| format!("crs-rule-{}", key.id)),
        id: Some(key.id.clone()),
        effective_mode: key.mode.as_str().to_string(),
        hits: counter.load(Ordering::Relaxed),
        latest_inbound_anomaly_score: Some(scores.inbound),
        latest_outbound_anomaly_score: Some(scores.outbound),
      })
      .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
      left
        .phase
        .cmp(&right.phase)
        .then_with(|| left.id.cmp(&right.id))
        .then_with(|| left.name.cmp(&right.name))
    });
    snapshots
  }

  pub(crate) fn evaluate_request(&self, input: WafRequestInput<'_>) -> anyhow::Result<CrsDecision> {
    if !self.enabled {
      return Ok(CrsDecision::default());
    }
    let mut tx = CrsTransaction::new(self, input);
    self.evaluate_phase(&mut tx, 1, None)?;
    self.evaluate_phase(&mut tx, 2, None)?;
    let score = tx.inbound_score();
    self.remember_scores(score, 0);
    if self.mode == WafMode::Enforcing && score >= self.inbound_threshold {
      return Ok(CrsDecision {
        terminal: Some(WafTerminalResponse::new(
          StatusCode::FORBIDDEN,
          "Blocked by CRS".to_string(),
        )),
      });
    }
    Ok(CrsDecision::default())
  }

  pub(crate) fn evaluate_response(
    &self,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<CrsDecision> {
    if !self.enabled {
      return Ok(CrsDecision::default());
    }
    let mut tx = CrsTransaction::new(self, input.request);
    tx.response = Some(CrsResponseView::from_input(input));
    self.evaluate_phase(&mut tx, 3, Some(input))?;
    self.evaluate_phase(&mut tx, 4, Some(input))?;
    let outbound = tx.outbound_score();
    self.remember_scores(0, outbound);
    if self.mode == WafMode::Enforcing && outbound >= self.outbound_threshold {
      return Ok(CrsDecision {
        terminal: Some(WafTerminalResponse::new(
          StatusCode::BAD_GATEWAY,
          "Blocked by CRS".to_string(),
        )),
      });
    }
    Ok(CrsDecision::default())
  }

  fn remember_scores(&self, inbound: i64, outbound: i64) {
    let mut scores = self
      .latest_scores
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    if inbound > 0 {
      scores.inbound = inbound;
    }
    if outbound > 0 {
      scores.outbound = outbound;
    }
  }

  fn evaluate_phase(
    &self,
    tx: &mut CrsTransaction<'_>,
    phase: u8,
    response: Option<WafResponseInput<'_>>,
  ) -> anyhow::Result<()> {
    let mut index = 0usize;
    while index < self.rules.len() {
      match &self.rules[index] {
        CrsEntry::Marker(_) => {
          index += 1;
        }
        CrsEntry::Rule(rule) if rule.phase != phase => {
          index += 1;
        }
        CrsEntry::Rule(rule) => {
          let matched = rule.matches(tx, response)?;
          if matched {
            self.record_hit(rule);
            rule.apply_actions(tx)?;
            if let Some(marker) = &rule.skip_after {
              index = self
                .rules
                .iter()
                .position(|entry| matches!(entry, CrsEntry::Marker(name) if name == marker))
                .map(|position| position + 1)
                .unwrap_or(index + 1);
              continue;
            }
          }
          index += 1;
        }
      }
    }
    Ok(())
  }

  fn record_hit(&self, rule: &CrsRule) {
    let Some(key) = &rule.hit_key else {
      return;
    };
    if let Some(counter) = self.counters.get(key) {
      counter.fetch_add(1, Ordering::Relaxed);
    }
  }
}

#[derive(Debug, Default)]
pub(crate) struct CrsDecision {
  pub(crate) terminal: Option<WafTerminalResponse>,
}

#[derive(Debug, Clone, Default)]
struct CrsLatestScores {
  inbound: i64,
  outbound: i64,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct CrsHitKey {
  phase: u8,
  id: String,
  name: Option<String>,
  mode: WafMode,
}
