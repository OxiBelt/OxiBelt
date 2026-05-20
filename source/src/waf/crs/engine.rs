use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;
use tracing::info;

use super::super::{
  WafMode, WafRequestInput, WafResponseInput, WafRuleHitSnapshot, WafTerminalResponse,
};
use super::config::{
  WafCrsAllowlistConfig, WafCrsConfig, WafCrsRuleOverrideConfig, WafCrsRuleOverrideMode,
  WafCrsRuleSelectorConfig, validate_config,
};
use super::model::{CrsAuditRuleMatch, CrsEntry, CrsResponseView, CrsRule, CrsTransaction};
use super::parser::CrsParser;
use super::utils::crs_phase_name;

#[derive(Clone)]
pub(crate) struct CrsEngine {
  enabled: bool,
  pub(super) mode: WafMode,
  pub(super) paranoia_level: u8,
  pub(super) inbound_threshold: i64,
  pub(super) outbound_threshold: i64,
  rules: Vec<CrsEntry>,
  phase_indices: Vec<CrsPhaseIndex>,
  requires_request_body_inspection: bool,
  requires_response_body_inspection: bool,
  counters: HashMap<CrsHitKey, Arc<AtomicU64>>,
  tuned_counters: HashMap<CrsHitKey, Arc<AtomicU64>>,
  rule_overrides: Vec<WafCrsRuleOverrideConfig>,
  allowlists: Vec<WafCrsAllowlistConfig>,
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
      phase_indices: default_phase_indices(),
      requires_request_body_inspection: false,
      requires_response_body_inspection: false,
      counters: HashMap::new(),
      tuned_counters: HashMap::new(),
      rule_overrides: Vec::new(),
      allowlists: Vec::new(),
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
    let mut tuned_counters = HashMap::new();
    for entry in &mut rules {
      if let CrsEntry::Rule(rule) = entry {
        let mode = mode_for_rule(rule, config.mode, &config.rule_overrides);
        let key = CrsHitKey {
          phase: rule.phase,
          id: rule.id.clone(),
          name: rule.msg.clone(),
          mode,
        };
        let counter = previous_counters.get(&key).cloned().unwrap_or_default();
        rule.hit_key = Some(key.clone());
        counters.insert(key.clone(), counter);
        tuned_counters.insert(key, Arc::new(AtomicU64::new(0)));
      }
    }
    let phase_indices = build_phase_indices(&rules);
    let requires_request_body_inspection = rules.iter().any(|entry| match entry {
      CrsEntry::Rule(rule) => matches!(rule.phase, 2) && rule.requires_request_body,
      CrsEntry::Marker(_) => false,
    });
    let requires_response_body_inspection = rules.iter().any(|entry| match entry {
      CrsEntry::Rule(rule) => matches!(rule.phase, 4) && rule.requires_response_body,
      CrsEntry::Marker(_) => false,
    });
    Ok(Self {
      enabled: true,
      mode: config.mode,
      paranoia_level: config.paranoia_level,
      inbound_threshold: config.inbound_anomaly_score_threshold,
      outbound_threshold: config.outbound_anomaly_score_threshold,
      rules,
      phase_indices,
      requires_request_body_inspection,
      requires_response_body_inspection,
      counters,
      tuned_counters,
      rule_overrides: config.rule_overrides.clone(),
      allowlists: config.allowlists.clone(),
      latest_scores: Arc::new(std::sync::Mutex::new(CrsLatestScores::default())),
    })
  }

  pub(crate) fn has_request_rules(&self) -> bool {
    self.has_phase_rule(1) || self.has_phase_rule(2)
  }

  pub(crate) fn has_response_rules(&self) -> bool {
    self.has_phase_rule(3) || self.has_phase_rule(4)
  }

  pub(crate) fn active_hit_counters(&self) -> HashMap<CrsHitKey, Arc<AtomicU64>> {
    self.counters.clone()
  }

  pub(crate) fn requires_request_body_inspection(&self) -> bool {
    self.enabled && self.requires_request_body_inspection
  }

  pub(crate) fn requires_response_body_inspection(&self) -> bool {
    self.enabled && self.requires_response_body_inspection
  }

  fn has_phase_rule(&self, phase: u8) -> bool {
    self.enabled
      && self
        .phase_indices
        .get(usize::from(phase))
        .map(|index| !index.rules.is_empty())
        .unwrap_or(false)
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
        tags: self.rule_tags(&key.id),
        effective_mode: key.mode.as_str().to_string(),
        hits: counter.load(Ordering::Relaxed),
        tuned_hits: self
          .tuned_counters
          .get(key)
          .map(|counter| counter.load(Ordering::Relaxed))
          .filter(|hits| *hits > 0),
        latest_inbound_anomaly_score: Some(scores.inbound),
        latest_outbound_anomaly_score: Some(scores.outbound),
        latest_inbound_blocking_score: Some(scores.inbound_blocking),
        latest_outbound_blocking_score: Some(scores.outbound_blocking),
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
    self.evaluate_phase(&mut tx, 1)?;
    self.evaluate_phase(&mut tx, 2)?;
    let score = tx.inbound_score();
    let blocking_score = tx.inbound_blocking_score();
    if score != 0 || blocking_score != 0 {
      self.remember_scores(score, 0, blocking_score, 0);
    }
    if blocking_score >= self.inbound_threshold {
      audit_crs_block(&tx, "request", score, 0, blocking_score, 0);
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
    self.evaluate_phase(&mut tx, 3)?;
    self.evaluate_phase(&mut tx, 4)?;
    let outbound = tx.outbound_score();
    let outbound_blocking = tx.outbound_blocking_score();
    if outbound != 0 || outbound_blocking != 0 {
      self.remember_scores(0, outbound, 0, outbound_blocking);
    }
    if outbound_blocking >= self.outbound_threshold {
      audit_crs_block(&tx, "response", 0, outbound, 0, outbound_blocking);
      return Ok(CrsDecision {
        terminal: Some(WafTerminalResponse::new(
          StatusCode::BAD_GATEWAY,
          "Blocked by CRS".to_string(),
        )),
      });
    }
    Ok(CrsDecision::default())
  }

  fn remember_scores(
    &self,
    inbound: i64,
    outbound: i64,
    inbound_blocking: i64,
    outbound_blocking: i64,
  ) {
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
    if inbound_blocking > 0 || inbound > 0 {
      scores.inbound_blocking = inbound_blocking;
    }
    if outbound_blocking > 0 || outbound > 0 {
      scores.outbound_blocking = outbound_blocking;
    }
  }

  fn evaluate_phase(&self, tx: &mut CrsTransaction<'_>, phase: u8) -> anyhow::Result<()> {
    let Some(phase_index) = self.phase_indices.get(usize::from(phase)) else {
      return Ok(());
    };
    let mut index = 0usize;
    while index < phase_index.rules.len() {
      let phase_rule = &phase_index.rules[index];
      match &self.rules[phase_rule.entry_index] {
        CrsEntry::Rule(rule) => {
          let matched = rule.matches(tx)?;
          if matched {
            self.record_hit(rule);
            let tuning = self.tuning_for_rule(rule, tx.request);
            if tuning.is_tuned() {
              self.record_tuned_hit(rule);
              audit_crs_tuned(tx, rule, phase, &tuning);
            }
            match tuning.effective_mode {
              WafCrsRuleOverrideMode::Enforcing => {
                tx.last_blocking_match = Some(CrsAuditRuleMatch {
                  id: rule.id.clone(),
                  msg: rule.msg.clone(),
                  mode: tuning.effective_mode.as_str().to_string(),
                  tuning_name: tuning.name.clone(),
                });
                rule.apply_actions(tx, true)?;
              }
              WafCrsRuleOverrideMode::Monitor => {
                rule.apply_actions(tx, false)?;
              }
              WafCrsRuleOverrideMode::Disabled => {}
            }
            if let Some(skip_to) = phase_rule.skip_to {
              index = skip_to;
              continue;
            }
          }
          index += 1;
        }
        CrsEntry::Marker(_) => {
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

  fn record_tuned_hit(&self, rule: &CrsRule) {
    let Some(key) = &rule.hit_key else {
      return;
    };
    if let Some(counter) = self.tuned_counters.get(key) {
      counter.fetch_add(1, Ordering::Relaxed);
    }
  }

  fn tuning_for_rule(&self, rule: &CrsRule, request: WafRequestInput<'_>) -> CrsRuleTuningDecision {
    if let Some(allowlist) = self.allowlists.iter().find(|allowlist| {
      rule_matches_selector(rule, &allowlist.selector) && traffic_matches(allowlist, request)
    }) {
      return CrsRuleTuningDecision {
        effective_mode: WafCrsRuleOverrideMode::Disabled,
        name: Some(allowlist.name.clone()),
        kind: Some("allowlist"),
      };
    }

    if let Some(override_config) = self
      .rule_overrides
      .iter()
      .find(|override_config| rule_matches_selector(rule, &override_config.selector))
    {
      return CrsRuleTuningDecision {
        effective_mode: override_config.mode,
        name: Some(override_config.name.clone()),
        kind: Some("rule_override"),
      };
    }

    CrsRuleTuningDecision {
      effective_mode: mode_from_waf_mode(self.mode),
      name: None,
      kind: None,
    }
  }

  fn rule_tags(&self, id: &str) -> Vec<String> {
    self
      .rules
      .iter()
      .find_map(|entry| match entry {
        CrsEntry::Rule(rule) if rule.id == id => Some(rule.tags.clone()),
        _ => None,
      })
      .unwrap_or_default()
  }
}

#[derive(Clone, Default)]
struct CrsPhaseIndex {
  rules: Vec<CrsPhaseRule>,
}

#[derive(Clone)]
struct CrsPhaseRule {
  entry_index: usize,
  skip_to: Option<usize>,
}

fn default_phase_indices() -> Vec<CrsPhaseIndex> {
  vec![CrsPhaseIndex::default(); 5]
}

fn build_phase_indices(entries: &[CrsEntry]) -> Vec<CrsPhaseIndex> {
  let mut markers = HashMap::new();
  let mut phase_indices = default_phase_indices();
  for (entry_index, entry) in entries.iter().enumerate() {
    match entry {
      CrsEntry::Marker(name) => {
        markers.entry(name.clone()).or_insert(entry_index);
      }
      CrsEntry::Rule(rule) => {
        if let Some(phase_index) = phase_indices.get_mut(usize::from(rule.phase)) {
          phase_index.rules.push(CrsPhaseRule {
            entry_index,
            skip_to: None,
          });
        }
      }
    }
  }

  for phase_index in &mut phase_indices {
    let rule_count = phase_index.rules.len();
    for rule_index in 0..rule_count {
      let entry_index = phase_index.rules[rule_index].entry_index;
      let Some(CrsEntry::Rule(rule)) = entries.get(entry_index) else {
        continue;
      };
      let Some(marker_index) = rule
        .skip_after
        .as_ref()
        .and_then(|marker| markers.get(marker))
      else {
        continue;
      };
      let skip_to = phase_index
        .rules
        .partition_point(|phase_rule| phase_rule.entry_index <= *marker_index);
      if skip_to > rule_index {
        phase_index.rules[rule_index].skip_to = Some(skip_to);
      }
    }
  }

  phase_indices
}

#[derive(Debug, Default)]
pub(crate) struct CrsDecision {
  pub(crate) terminal: Option<WafTerminalResponse>,
}

#[derive(Debug, Clone, Default)]
struct CrsLatestScores {
  inbound: i64,
  outbound: i64,
  inbound_blocking: i64,
  outbound_blocking: i64,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) struct CrsHitKey {
  phase: u8,
  id: String,
  name: Option<String>,
  mode: WafCrsRuleOverrideMode,
}

#[derive(Debug)]
struct CrsRuleTuningDecision {
  effective_mode: WafCrsRuleOverrideMode,
  name: Option<String>,
  kind: Option<&'static str>,
}

impl CrsRuleTuningDecision {
  fn is_tuned(&self) -> bool {
    self.name.is_some()
  }
}

fn mode_for_rule(
  rule: &CrsRule,
  default_mode: WafMode,
  overrides: &[WafCrsRuleOverrideConfig],
) -> WafCrsRuleOverrideMode {
  overrides
    .iter()
    .find(|override_config| rule_matches_selector(rule, &override_config.selector))
    .map(|override_config| override_config.mode)
    .unwrap_or_else(|| mode_from_waf_mode(default_mode))
}

fn mode_from_waf_mode(mode: WafMode) -> WafCrsRuleOverrideMode {
  match mode {
    WafMode::Enforcing => WafCrsRuleOverrideMode::Enforcing,
    WafMode::Monitor => WafCrsRuleOverrideMode::Monitor,
  }
}

fn rule_matches_selector(rule: &CrsRule, selector: &WafCrsRuleSelectorConfig) -> bool {
  selector.rule_ids.iter().any(|id| id == &rule.id)
    || selector
      .tags
      .iter()
      .any(|expected| rule.tags.iter().any(|tag| tag == expected))
    || selector.msg_contains.iter().any(|needle| {
      rule
        .msg
        .as_deref()
        .map(|message| message.contains(needle))
        .unwrap_or(false)
    })
}

fn traffic_matches(allowlist: &WafCrsAllowlistConfig, request: WafRequestInput<'_>) -> bool {
  if !allowlist.methods.is_empty()
    && !allowlist
      .methods
      .iter()
      .any(|method| method.eq_ignore_ascii_case(request.method.as_str()))
  {
    return false;
  }
  if !allowlist.routes.is_empty()
    && !allowlist
      .routes
      .iter()
      .any(|route| route == request.route_name)
  {
    return false;
  }
  if !allowlist.path_prefixes.is_empty()
    && !allowlist
      .path_prefixes
      .iter()
      .any(|prefix| request.uri.path().starts_with(prefix))
  {
    return false;
  }
  true
}

fn audit_crs_tuned(
  tx: &CrsTransaction<'_>,
  rule: &CrsRule,
  phase: u8,
  tuning: &CrsRuleTuningDecision,
) {
  info!(
    event = "oxibelt.waf.crs.audit",
    request_id = tx.request.request_id,
    transaction_id = tx.request.transaction_id,
    phase = crs_phase_name(phase),
    rule_id = rule.id.as_str(),
    rule_message = rule.msg.as_deref().unwrap_or_default(),
    effective_mode = tuning.effective_mode.as_str(),
    tuning_kind = tuning.kind.unwrap_or_default(),
    tuning_name = tuning.name.as_deref().unwrap_or_default(),
    decision = "tuned_suppressed",
    "CRS tuning audit"
  );
}

fn audit_crs_block(
  tx: &CrsTransaction<'_>,
  phase: &str,
  inbound_score: i64,
  outbound_score: i64,
  inbound_blocking_score: i64,
  outbound_blocking_score: i64,
) {
  let rule = tx.last_blocking_match.as_ref();
  info!(
    event = "oxibelt.waf.crs.audit",
    request_id = tx.request.request_id,
    transaction_id = tx.request.transaction_id,
    phase,
    rule_id = rule.map(|rule| rule.id.as_str()).unwrap_or_default(),
    rule_message = rule
      .and_then(|rule| rule.msg.as_deref())
      .unwrap_or_default(),
    effective_mode = rule.map(|rule| rule.mode.as_str()).unwrap_or("enforcing"),
    tuning_name = rule
      .and_then(|rule| rule.tuning_name.as_deref())
      .unwrap_or_default(),
    inbound_anomaly_score = inbound_score,
    outbound_anomaly_score = outbound_score,
    inbound_blocking_score,
    outbound_blocking_score,
    decision = "blocked",
    "CRS block audit"
  );
}
