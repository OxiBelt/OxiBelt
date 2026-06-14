use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context, bail};
use http::Method;
use oxibelt::admin_client::AdminClient;
use serde::Serialize;
use serde_json::Value;

use crate::cli::{
  Command, OutputFormat, RulepackApplyArgs, RulepackCatalogInstallArgs, RulepackInfoArgs,
  RulepackRepoCommand, RulepackRepoSubcommand, RulepackSearchArgs, RulepackSourceArgs,
  RulepackSubcommand, RulepackUpdateArgs,
};
use crate::rulepack_catalog_index::{
  CatalogRulepack, compare_versions, compatibility_error, is_compatible, load_repo_catalog,
};
use crate::rulepack_catalog_registry::{
  RulepackRepoConfig, ensure_repo_name, load_registry, registry_path, save_registry,
};

#[derive(Debug, Clone)]
pub(crate) struct CatalogEntrySelection {
  pub(crate) repo: String,
  pub(crate) repo_config: RulepackRepoConfig,
  pub(crate) entry: CatalogRulepack,
}

#[derive(Debug, Serialize)]
struct RepoMutationReport {
  ok: bool,
  name: String,
  path: String,
}

#[derive(Debug, Serialize)]
struct RepoListReport {
  path: String,
  repos: Vec<RepoReport>,
}

#[derive(Debug, Serialize)]
struct RepoReport {
  name: String,
  url: String,
  ca_certs: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  token_env: Option<String>,
  allow_insecure_rulepack_url: bool,
  require_openpgp_signature: bool,
  openpgp_key_files: Vec<String>,
  openpgp_keyring_dirs: Vec<String>,
  openpgp_fingerprints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SearchReport {
  query: String,
  rulepacks: Vec<CatalogEntryReport>,
  skipped_incompatible: usize,
}

#[derive(Debug, Serialize)]
struct InfoReport {
  rulepack: CatalogEntryReport,
}

#[derive(Debug, Serialize)]
struct CatalogEntryReport {
  repo: String,
  name: String,
  version: String,
  targets: Vec<String>,
  source: String,
  sha256: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  signature_type: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  signature: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  min_oxibelt_version: Option<String>,
  compatible: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  license: Option<String>,
  maintainers: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  description: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpdatePlanReport {
  updates: Vec<UpdatePlanEntry>,
  warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UpdatePlanEntry {
  name: String,
  current_version: String,
  new_version: String,
  repo: String,
  source: String,
  sha256: String,
  suggested_command: String,
}

#[derive(Debug)]
struct ActiveRulepack {
  name: String,
  version: String,
}

pub(crate) async fn run_local_if_requested(command: &Command) -> anyhow::Result<bool> {
  let Command::Rulepack(command) = command else {
    return Ok(false);
  };
  match &command.command {
    RulepackSubcommand::Repo(args) => {
      run_repo_command(args)?;
      Ok(true)
    }
    RulepackSubcommand::Search(args) => {
      print_search(args, Duration::from_secs(10)).await?;
      Ok(true)
    }
    RulepackSubcommand::Info(args) => {
      print_info(args, Duration::from_secs(10)).await?;
      Ok(true)
    }
    _ => Ok(false),
  }
}

pub(crate) async fn resolve_install_args(
  args: &RulepackCatalogInstallArgs,
  timeout: Duration,
) -> anyhow::Result<RulepackApplyArgs> {
  let selection = select_catalog_entry(
    &args.name,
    args.version.as_deref(),
    args.repo.as_deref(),
    timeout,
  )
  .await?;
  if let Some(error) = compatibility_error(&selection.entry) {
    bail!("{error}");
  }
  Ok(RulepackApplyArgs {
    source: source_args_for_selection(&selection),
    values: args.values.clone(),
    vars: args.vars.clone(),
    binds: args.binds.clone(),
    mode: args.mode,
    profile: args.profile.clone(),
    force_mode: args.force_mode,
    interactive: args.interactive,
    dry_run: args.dry_run,
    fixture: args.fixture.clone(),
    replay: args.replay.clone(),
  })
}

pub(crate) async fn print_update_plan(
  client: &AdminClient,
  args: &RulepackUpdateArgs,
  output: OutputFormat,
) -> anyhow::Result<()> {
  if !args.plan {
    bail!("rulepack update currently supports --plan only");
  }
  let entries = load_entries(args.repo.as_deref(), client.timeout()).await?;
  let active = active_rulepacks(client).await?;
  let mut updates = Vec::new();
  let mut warnings = Vec::new();
  for active in active {
    let candidates = entries
      .iter()
      .filter(|candidate| candidate.entry.name == active.name)
      .filter(|candidate| is_compatible(&candidate.entry))
      .collect::<Vec<_>>();
    if candidates.is_empty() {
      continue;
    }
    let newest = newest_entry(&candidates).context("compatible candidate list was empty")?;
    if compare_versions(&newest.entry.version, &active.version) != Ordering::Greater {
      continue;
    }
    updates.push(UpdatePlanEntry {
      name: active.name.clone(),
      current_version: active.version.clone(),
      new_version: newest.entry.version.clone(),
      repo: newest.repo.clone(),
      source: safe_url(&newest.entry.source),
      sha256: newest.entry.sha256.clone(),
      suggested_command: format!(
        "oxibeltctl rulepack install {} --version {} --repo {} --interactive --dry-run",
        shell_quote(&active.name),
        shell_quote(&newest.entry.version),
        shell_quote(&newest.repo)
      ),
    });
  }
  if entries.iter().any(|entry| !is_compatible(&entry.entry)) {
    warnings.push("incompatible catalog entries were ignored".to_string());
  }
  print_json(&UpdatePlanReport { updates, warnings }, output)
}

fn run_repo_command(args: &RulepackRepoCommand) -> anyhow::Result<()> {
  match &args.command {
    RulepackRepoSubcommand::Add(add) => {
      ensure_repo_name(&add.name)?;
      crate::rulepack_catalog_index::validate_catalog_url(
        &add.url,
        add.allow_insecure_rulepack_url,
      )?;
      let mut registry = load_registry()?;
      if registry.repos.contains_key(&add.name) {
        bail!("rulepack repo {} already exists", add.name);
      }
      registry
        .repos
        .insert(add.name.clone(), RulepackRepoConfig::from_add_args(add));
      let path = save_registry(&registry)?;
      print_json_pretty(&RepoMutationReport {
        ok: true,
        name: add.name.clone(),
        path: path.display().to_string(),
      })
    }
    RulepackRepoSubcommand::List => {
      let registry = load_registry()?;
      let report = RepoListReport {
        path: registry_path()?.display().to_string(),
        repos: registry
          .repos
          .iter()
          .map(|(name, repo)| repo_report(name, repo))
          .collect(),
      };
      print_json_pretty(&report)
    }
    RulepackRepoSubcommand::Remove(remove) => {
      ensure_repo_name(&remove.name)?;
      let mut registry = load_registry()?;
      if registry.repos.remove(&remove.name).is_none() {
        bail!("rulepack repo {} is not configured", remove.name);
      }
      let path = save_registry(&registry)?;
      print_json_pretty(&RepoMutationReport {
        ok: true,
        name: remove.name.clone(),
        path: path.display().to_string(),
      })
    }
  }
}

async fn print_search(args: &RulepackSearchArgs, timeout: Duration) -> anyhow::Result<()> {
  let query = args.query.to_ascii_lowercase();
  let entries = load_entries(args.repo.as_deref(), timeout).await?;
  let skipped_incompatible = entries
    .iter()
    .filter(|entry| !is_compatible(&entry.entry))
    .count();
  let mut rulepacks = entries
    .into_iter()
    .filter(|entry| is_compatible(&entry.entry))
    .filter(|entry| matches_query(entry, &query))
    .map(|entry| catalog_entry_report(&entry))
    .collect::<Vec<_>>();
  sort_reports(&mut rulepacks);
  print_json_pretty(&SearchReport {
    query: args.query.clone(),
    rulepacks,
    skipped_incompatible,
  })
}

async fn print_info(args: &RulepackInfoArgs, timeout: Duration) -> anyhow::Result<()> {
  let selection = select_catalog_entry(
    &args.name,
    args.version.as_deref(),
    args.repo.as_deref(),
    timeout,
  )
  .await?;
  if let Some(error) = compatibility_error(&selection.entry) {
    bail!("{error}");
  }
  print_json_pretty(&InfoReport {
    rulepack: catalog_entry_report(&selection),
  })
}

async fn select_catalog_entry(
  name: &str,
  version: Option<&str>,
  repo: Option<&str>,
  timeout: Duration,
) -> anyhow::Result<CatalogEntrySelection> {
  let entries = load_entries(repo, timeout).await?;
  let all_candidates = entries
    .into_iter()
    .filter(|candidate| candidate.entry.name == name)
    .filter(|candidate| version.is_none_or(|version| candidate.entry.version == version))
    .collect::<Vec<_>>();
  let candidates = all_candidates
    .iter()
    .filter(|candidate| is_compatible(&candidate.entry))
    .collect::<Vec<_>>();
  if candidates.is_empty() {
    if let Some(error) = all_candidates
      .iter()
      .find_map(|candidate| compatibility_error(&candidate.entry))
    {
      bail!("{error}");
    }
    bail!("no compatible catalog entry found for rulepack {name}");
  }
  let newest = newest_entry(&candidates)?;
  let ties = candidates
    .iter()
    .filter(|candidate| candidate.entry.version == newest.entry.version)
    .collect::<Vec<_>>();
  if ties.len() > 1 && repo.is_none() {
    bail!(
      "rulepack {name} {} exists in multiple repos; pass --repo",
      newest.entry.version
    );
  }
  Ok((*newest).clone())
}

async fn load_entries(
  repo_filter: Option<&str>,
  timeout: Duration,
) -> anyhow::Result<Vec<CatalogEntrySelection>> {
  let registry = load_registry()?;
  if registry.repos.is_empty() {
    bail!("no rulepack repos configured; run oxibeltctl rulepack repo add NAME URL");
  }
  if let Some(repo) = repo_filter {
    ensure_repo_name(repo)?;
    if !registry.repos.contains_key(repo) {
      bail!("rulepack repo {repo} is not configured");
    }
  }
  let mut entries = Vec::new();
  let mut seen = BTreeSet::new();
  for (repo_name, repo) in &registry.repos {
    if repo_filter.is_some_and(|wanted| wanted != repo_name) {
      continue;
    }
    let catalog = load_repo_catalog(repo_name, repo, timeout).await?;
    for entry in catalog.entries {
      let key = (
        catalog.repo.clone(),
        entry.name.clone(),
        entry.version.clone(),
      );
      if !seen.insert(key) {
        bail!(
          "rulepack repo {} contains duplicate {} {}",
          catalog.repo,
          entry.name,
          entry.version
        );
      }
      entries.push(CatalogEntrySelection {
        repo: catalog.repo.clone(),
        repo_config: repo.clone(),
        entry,
      });
    }
  }
  Ok(entries)
}

fn source_args_for_selection(selection: &CatalogEntrySelection) -> RulepackSourceArgs {
  let signature_url = selection.entry.signature.clone();
  RulepackSourceArgs {
    file: None,
    dir: None,
    url: Some(selection.entry.source.clone()),
    git: None,
    manifest: "rulepack.oxirule-rulepack.toml".into(),
    ca_certs: selection.repo_config.ca_certs.clone(),
    token_env: selection.repo_config.token_env.clone(),
    sha256: Some(selection.entry.sha256.clone()),
    allow_unpinned_rulepack: false,
    allow_insecure_rulepack_url: selection.repo_config.allow_insecure_rulepack_url,
    require_openpgp_signature: selection.repo_config.require_openpgp_signature
      || signature_url.is_some(),
    openpgp_signature_url: signature_url,
    openpgp_signature_file: None,
    openpgp_key_files: selection.repo_config.openpgp_key_files.clone(),
    openpgp_keyring_dirs: selection.repo_config.openpgp_keyring_dirs.clone(),
    openpgp_fingerprints: selection.repo_config.openpgp_fingerprints.clone(),
    git_ref: None,
  }
}

fn newest_entry<'entry>(
  entries: &[&'entry CatalogEntrySelection],
) -> anyhow::Result<&'entry CatalogEntrySelection> {
  entries
    .iter()
    .copied()
    .max_by(|left, right| {
      compare_versions(&left.entry.version, &right.entry.version)
        .then_with(|| right.repo.cmp(&left.repo))
    })
    .context("no catalog entries matched")
}

async fn active_rulepacks(client: &AdminClient) -> anyhow::Result<Vec<ActiveRulepack>> {
  let response = client
    .request_json(Method::GET, "/admin/v1/waf/rulepacks", None, None)
    .await?;
  if !response.status.is_success() {
    bail!("failed to fetch active rulepacks: {}", response.status);
  }
  let value: Value =
    serde_json::from_slice(&response.body).context("rulepack list response was not JSON")?;
  Ok(
    value
      .get("rulepacks")
      .and_then(Value::as_array)
      .into_iter()
      .flatten()
      .filter_map(|entry| {
        Some(ActiveRulepack {
          name: entry.get("name")?.as_str()?.to_string(),
          version: entry.get("version")?.as_str()?.to_string(),
        })
      })
      .collect(),
  )
}

fn matches_query(entry: &CatalogEntrySelection, query: &str) -> bool {
  entry.entry.name.to_ascii_lowercase().contains(query)
    || entry
      .entry
      .description
      .as_deref()
      .is_some_and(|description| description.to_ascii_lowercase().contains(query))
    || entry
      .entry
      .targets
      .iter()
      .any(|target| target.to_ascii_lowercase().contains(query))
}

fn catalog_entry_report(selection: &CatalogEntrySelection) -> CatalogEntryReport {
  CatalogEntryReport {
    repo: selection.repo.clone(),
    name: selection.entry.name.clone(),
    version: selection.entry.version.clone(),
    targets: selection.entry.targets.clone(),
    source: safe_url(&selection.entry.source),
    sha256: selection.entry.sha256.clone(),
    signature_type: selection.entry.signature_type.clone(),
    signature: selection.entry.signature.as_ref().map(safe_url),
    min_oxibelt_version: selection.entry.min_oxibelt_version.clone(),
    compatible: is_compatible(&selection.entry),
    license: selection.entry.license.clone(),
    maintainers: selection.entry.maintainers.clone(),
    description: selection.entry.description.clone(),
  }
}

fn repo_report(name: &str, repo: &RulepackRepoConfig) -> RepoReport {
  RepoReport {
    name: name.to_string(),
    url: safe_url(&repo.url),
    ca_certs: repo
      .ca_certs
      .iter()
      .map(|path| path.display().to_string())
      .collect(),
    token_env: repo.token_env.clone(),
    allow_insecure_rulepack_url: repo.allow_insecure_rulepack_url,
    require_openpgp_signature: repo.require_openpgp_signature,
    openpgp_key_files: repo
      .openpgp_key_files
      .iter()
      .map(|path| path.display().to_string())
      .collect(),
    openpgp_keyring_dirs: repo
      .openpgp_keyring_dirs
      .iter()
      .map(|path| path.display().to_string())
      .collect(),
    openpgp_fingerprints: repo.openpgp_fingerprints.clone(),
  }
}

fn sort_reports(reports: &mut [CatalogEntryReport]) {
  reports.sort_by(|left, right| {
    left
      .name
      .cmp(&right.name)
      .then_with(|| compare_versions(&right.version, &left.version))
      .then_with(|| left.repo.cmp(&right.repo))
  });
}

fn safe_url(url: &url::Url) -> String {
  let mut safe = url.clone();
  let _ = safe.set_username("");
  let _ = safe.set_password(None);
  safe.set_query(None);
  safe.set_fragment(None);
  safe.to_string()
}

fn shell_quote(value: &str) -> String {
  if value.bytes().all(|byte| {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'=')
  }) {
    return value.to_string();
  }
  format!("'{}'", value.replace('\'', "'\\''"))
}

fn print_json<T: Serialize>(value: &T, output: OutputFormat) -> anyhow::Result<()> {
  match output {
    OutputFormat::PrettyJson => print_json_pretty(value),
    OutputFormat::Json => {
      println!("{}", serde_json::to_string(value)?);
      Ok(())
    }
  }
}

fn print_json_pretty<T: Serialize>(value: &T) -> anyhow::Result<()> {
  println!("{}", serde_json::to_string_pretty(value)?);
  Ok(())
}

#[cfg(test)]
#[path = "rulepack_catalog_tests.rs"]
mod tests;
