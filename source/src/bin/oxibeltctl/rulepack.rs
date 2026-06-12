use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::Duration;

use anyhow::{Context, bail};
use http::{Method, StatusCode};
use oxibelt::admin_client::{AdminClient, AdminResponse};
use oxibelt::waf::{
  RULEPACK_FILE_SUFFIX, RulepackModeOverride, RulepackReferencedFileKind, RulepackRenderOptions,
  RulepackSourceProvenance, inspect_rulepack, referenced_rulepack_files,
  render_rulepack_for_install, validate_rulepack_manifest,
};
use serde_json::{Value, json};
use url::Url;

use crate::cli::{
  Command, OutputFormat, RulepackApplyArgs, RulepackCommand, RulepackFitArgs, RulepackModeArg,
  RulepackRemoveArgs, RulepackSourceArgs, RulepackSubcommand,
};
use crate::output::{print_permission_hint, print_response};
use crate::plan::{PermissionHint, RequestPlan};
use crate::rulepack_install::{
  RulepackInstallLockInput, installed_rulepack_lock_path, installed_rulepack_path,
  render_install_lock,
};
use crate::rulepack_url::load_url_source;
#[cfg(test)]
use crate::rulepack_url::{
  ensure_manifest_url_suffix, same_origin, validate_rulepack_signature_url, validate_rulepack_url,
};

pub(crate) async fn run_local_if_requested(command: &Command) -> anyhow::Result<bool> {
  let Command::Rulepack(command) = command else {
    return Ok(false);
  };
  match &command.command {
    RulepackSubcommand::Inspect(args) => {
      let loaded = load_rulepack_source(&args.source, Duration::from_secs(10), false).await?;
      let report = inspect_rulepack(
        &loaded.manifest,
        &loaded.source_label,
        RulepackRenderOptions::default(),
      )?;
      println!("{}", serde_json::to_string_pretty(&report.summary)?);
      Ok(true)
    }
    RulepackSubcommand::Render(args) => {
      let loaded = load_rulepack_source(&args.source, Duration::from_secs(10), false).await?;
      let cli_vars = crate::rulepack_fit::parse_key_values(&args.vars, "--var")?;
      let cli_binds = crate::rulepack_fit::parse_key_values(&args.binds, "--bind")?;
      let resolved = crate::rulepack_values::resolve_rulepack_inputs(
        crate::rulepack_values::RulepackResolveRequest {
          raw: &loaded.manifest,
          source: &loaded.source_label,
          values_file: args.values.as_deref(),
          cli_vars: &cli_vars,
          cli_binds: &cli_binds,
          cli_profile: args.profile.as_deref(),
          cli_mode: args.mode,
          cli_force_mode: args.force_mode,
          default_mode: None,
        },
      )?;
      let render_vars = crate::rulepack_fit::resolve_render_variables(
        &loaded.manifest,
        &loaded.source_label,
        &resolved.vars,
        &resolved.binds,
        true,
      )?;
      let rendered = render_rulepack_for_install(
        &loaded.manifest,
        &loaded.source_label,
        render_options(
          render_vars,
          resolved.mode,
          resolved.force_mode,
          loaded.git_commit.clone(),
          loaded.source_provenance.clone(),
        ),
      )?;
      print!("{rendered}");
      Ok(true)
    }
    RulepackSubcommand::Check(args) => {
      let loaded = load_rulepack_source(&args.source, Duration::from_secs(10), false).await?;
      let cli_vars = crate::rulepack_fit::parse_key_values(&args.vars, "--var")?;
      let cli_binds = crate::rulepack_fit::parse_key_values(&args.binds, "--bind")?;
      let resolved = crate::rulepack_values::resolve_rulepack_inputs(
        crate::rulepack_values::RulepackResolveRequest {
          raw: &loaded.manifest,
          source: &loaded.source_label,
          values_file: args.values.as_deref(),
          cli_vars: &cli_vars,
          cli_binds: &cli_binds,
          cli_profile: args.profile.as_deref(),
          cli_mode: None,
          cli_force_mode: false,
          default_mode: None,
        },
      )?;
      let render_vars = crate::rulepack_fit::resolve_render_variables(
        &loaded.manifest,
        &loaded.source_label,
        &resolved.vars,
        &resolved.binds,
        true,
      )?;
      let options = render_options(
        render_vars,
        resolved.mode,
        resolved.force_mode,
        loaded.git_commit.clone(),
        loaded.source_provenance.clone(),
      );
      let rendered_manifest =
        render_rulepack_for_install(&loaded.manifest, &loaded.source_label, options.clone())?;
      validate_rulepack_manifest(&rendered_manifest)?;
      let refs = referenced_rulepack_files(&loaded.manifest, &loaded.source_label, options)?;
      if let Some(base_dir) = loaded.base_dir.as_deref() {
        for referenced in &refs {
          resolve_existing_local_source_file(base_dir, &referenced.path)?;
        }
      } else if !refs.is_empty() {
        bail!("remote single-file rulepacks must embed rule and group content");
      }
      println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "ok": true, "referenced_files": refs }))?
      );
      Ok(true)
    }
    RulepackSubcommand::List
    | RulepackSubcommand::Fit(_)
    | RulepackSubcommand::Apply(_)
    | RulepackSubcommand::Remove(_) => Ok(false),
  }
}

pub(crate) async fn run_remote_if_requested(
  client: &AdminClient,
  command: &Command,
  output: OutputFormat,
) -> anyhow::Result<bool> {
  let Command::Rulepack(command) = command else {
    return Ok(false);
  };
  match &command.command {
    RulepackSubcommand::List => {
      let plan = plan_rulepack(client, command).await?;
      send_and_print(client, &plan, output).await?;
      Ok(true)
    }
    RulepackSubcommand::Fit(args) => {
      print_fit_report(client, args, output).await?;
      Ok(true)
    }
    RulepackSubcommand::Apply(args) => {
      let (plan, installed_name) = plan_rulepack_apply(client, args).await?;
      send_and_print(client, &plan, output).await?;
      verify_rulepack_active(client, &installed_name).await?;
      Ok(true)
    }
    RulepackSubcommand::Remove(args) => {
      let plan = plan_rulepack_remove(client, args).await?;
      send_and_print(client, &plan, output).await?;
      Ok(true)
    }
    RulepackSubcommand::Inspect(_)
    | RulepackSubcommand::Render(_)
    | RulepackSubcommand::Check(_) => Ok(false),
  }
}

pub(crate) async fn plan_rulepack(
  client: &AdminClient,
  command: &RulepackCommand,
) -> anyhow::Result<RequestPlan> {
  match &command.command {
    RulepackSubcommand::List => Ok(RequestPlan {
      method: Method::GET,
      endpoint: "/admin/v1/waf/rulepacks".to_string(),
      body: None,
      if_match: None,
      permission: permission("waf:ListOxiRulePacks", "*"),
      filter: crate::plan::ResponseFilter::None,
    }),
    RulepackSubcommand::Apply(args) => plan_rulepack_apply(client, args)
      .await
      .map(|(plan, _)| plan),
    RulepackSubcommand::Remove(args) => plan_rulepack_remove(client, args).await,
    RulepackSubcommand::Fit(_)
    | RulepackSubcommand::Inspect(_)
    | RulepackSubcommand::Render(_)
    | RulepackSubcommand::Check(_) => {
      bail!("rulepack local command should run before Admin planning")
    }
  }
}

async fn plan_rulepack_apply(
  client: &AdminClient,
  args: &RulepackApplyArgs,
) -> anyhow::Result<(RequestPlan, String)> {
  let loaded = load_rulepack_source(&args.source, client.timeout(), true).await?;
  let cli_vars = crate::rulepack_fit::parse_key_values(&args.vars, "--var")?;
  let cli_binds = crate::rulepack_fit::parse_key_values(&args.binds, "--bind")?;
  let resolved = crate::rulepack_values::resolve_rulepack_inputs(
    crate::rulepack_values::RulepackResolveRequest {
      raw: &loaded.manifest,
      source: &loaded.source_label,
      values_file: args.values.as_deref(),
      cli_vars: &cli_vars,
      cli_binds: &cli_binds,
      cli_profile: args.profile.as_deref(),
      cli_mode: args.mode,
      cli_force_mode: args.force_mode,
      default_mode: Some(RulepackModeArg::Monitor),
    },
  )?;
  let mut vars = resolved.vars.clone();
  let mut binds = resolved.binds.clone();
  let effective_mode = resolved.mode.unwrap_or(RulepackModeArg::Monitor);
  if args.interactive {
    crate::rulepack_prompt::complete_interactive_apply(
      client,
      &loaded,
      &args.source,
      &mut vars,
      &mut binds,
      effective_mode,
      resolved.force_mode,
    )
    .await?;
  }
  let render_vars = crate::rulepack_fit::resolve_render_variables(
    &loaded.manifest,
    &loaded.source_label,
    &vars,
    &binds,
    true,
  )?;
  let options = render_options(
    render_vars.clone(),
    Some(effective_mode),
    resolved.force_mode,
    loaded.git_commit.clone(),
    loaded.source_provenance.clone(),
  );
  let rendered_manifest =
    render_rulepack_for_install(&loaded.manifest, &loaded.source_label, options.clone())?;
  let inspection = inspect_rulepack(
    &rendered_manifest,
    &loaded.source_label,
    RulepackRenderOptions::default(),
  )?;
  let name = inspection.summary.name.clone();
  let mut operations = Vec::new();
  for referenced in referenced_rulepack_files(&loaded.manifest, &loaded.source_label, options)? {
    let Some(base_dir) = loaded.base_dir.as_deref() else {
      bail!("remote single-file rulepacks must embed rule and group content");
    };
    let path = resolve_existing_local_source_file(base_dir, &referenced.path)?;
    let raw = std::fs::read_to_string(&path)
      .with_context(|| format!("failed to read referenced rulepack file {}", path.display()))?;
    operations.push(json!({
      "op": "put",
      "root": match referenced.kind {
        RulepackReferencedFileKind::Rule => "oxirule",
        RulepackReferencedFileKind::Group => "oxirule_group",
      },
      "path": referenced.path.to_string_lossy(),
      "content": render_text(&raw, &render_vars),
    }));
  }
  operations.push(json!({
    "op": "put",
    "root": "oxirule_rulepack",
    "path": installed_rulepack_path(&name)?,
    "content": rendered_manifest,
  }));
  let input_metadata =
    oxibelt::waf::inspect_rulepack_inputs(&loaded.manifest, &loaded.source_label)?;
  let lock_values = input_metadata
    .variables
    .iter()
    .filter_map(|variable| {
      render_vars
        .get(&variable.name)
        .map(|value| (variable.name.clone(), value.clone()))
    })
    .collect::<BTreeMap<_, _>>();
  operations.push(json!({
    "op": "put",
    "root": "oxirule_rulepack_install",
    "path": installed_rulepack_lock_path(&name)?,
    "content": render_install_lock(RulepackInstallLockInput {
      name: &name,
      version: &inspection.summary.version,
      source: &loaded.source_label,
      source_commit: loaded.git_commit.as_deref(),
      source_provenance: loaded.source_provenance.as_ref(),
      selected_profile: resolved.selected_profile.as_deref(),
      effective_mode,
      force_mode: resolved.force_mode,
      bindings: &binds,
      values: &lock_values,
    })?,
  }));
  let etag = current_etag(client).await?;
  Ok((
    RequestPlan {
      method: Method::POST,
      endpoint: "/admin/v1/files/sync".to_string(),
      body: Some(json!({ "apply": "oxirule", "operations": operations })),
      if_match: Some(etag),
      permission: permission("waf:PutOxiRulePack", &format!("oxirule-rulepack/{name}")),
      filter: crate::plan::ResponseFilter::None,
    },
    name,
  ))
}

async fn print_fit_report(
  client: &AdminClient,
  args: &RulepackFitArgs,
  output: OutputFormat,
) -> anyhow::Result<()> {
  let loaded = load_rulepack_source(&args.source, client.timeout(), false).await?;
  let cli_vars = crate::rulepack_fit::parse_key_values(&args.vars, "--var")?;
  let cli_binds = crate::rulepack_fit::parse_key_values(&args.binds, "--bind")?;
  let resolved = crate::rulepack_values::resolve_rulepack_inputs(
    crate::rulepack_values::RulepackResolveRequest {
      raw: &loaded.manifest,
      source: &loaded.source_label,
      values_file: args.values.as_deref(),
      cli_vars: &cli_vars,
      cli_binds: &cli_binds,
      cli_profile: args.profile.as_deref(),
      cli_mode: args.mode,
      cli_force_mode: args.force_mode,
      default_mode: None,
    },
  )?;
  let evaluation = crate::rulepack_fit::evaluate_fit(
    client,
    &loaded,
    &args.source,
    crate::rulepack_fit::RulepackFitOptions {
      vars: &resolved.vars,
      binds: &resolved.binds,
      command_vars: &cli_vars,
      command_binds: &cli_binds,
      values_file: resolved.values_file.as_deref(),
      profile_arg: args.profile.as_deref(),
      mode: resolved.mode,
      force_mode: resolved.force_mode,
    },
  )
  .await?;
  match output {
    OutputFormat::PrettyJson => println!("{}", serde_json::to_string_pretty(&evaluation.report)?),
    OutputFormat::Json => println!("{}", serde_json::to_string(&evaluation.report)?),
  }
  Ok(())
}

async fn plan_rulepack_remove(
  client: &AdminClient,
  args: &RulepackRemoveArgs,
) -> anyhow::Result<RequestPlan> {
  if !args.apply {
    bail!("rulepack remove requires --apply");
  }
  let path = installed_rulepack_path(&args.name)?;
  let lock_path = installed_rulepack_lock_path(&args.name)?;
  let etag = current_etag(client).await?;
  Ok(RequestPlan {
    method: Method::POST,
    endpoint: "/admin/v1/files/sync".to_string(),
    body: Some(json!({
      "apply": "oxirule",
      "operations": [
        {
          "op": "delete",
          "root": "oxirule_rulepack",
          "path": path,
        },
        {
          "op": "delete",
          "root": "oxirule_rulepack_install",
          "path": lock_path,
        },
      ],
    })),
    if_match: Some(etag),
    permission: permission(
      "waf:DeleteOxiRulePack",
      &format!("oxirule-rulepack/{}", args.name),
    ),
    filter: crate::plan::ResponseFilter::None,
  })
}

async fn send_and_print(
  client: &AdminClient,
  plan: &RequestPlan,
  output: OutputFormat,
) -> anyhow::Result<AdminResponse> {
  let response = client
    .request_json(
      plan.method.clone(),
      &plan.endpoint,
      plan.body.clone(),
      plan.if_match.as_deref(),
    )
    .await?;
  print_response(&response, output, &plan.filter)?;
  if response.status == StatusCode::FORBIDDEN {
    print_permission_hint(&plan.permission);
  }
  if !response.status.is_success() {
    bail!("Admin request failed with {}", response.status);
  }
  Ok(response)
}

async fn verify_rulepack_active(client: &AdminClient, name: &str) -> anyhow::Result<()> {
  let response = client
    .request_json(Method::GET, "/admin/v1/waf/rulepacks", None, None)
    .await?;
  if !response.status.is_success() {
    bail!("failed to verify active rulepacks: {}", response.status);
  }
  let value: Value =
    serde_json::from_slice(&response.body).context("rulepack list response was not JSON")?;
  let active = value
    .get("rulepacks")
    .and_then(Value::as_array)
    .is_some_and(|rulepacks| {
      rulepacks
        .iter()
        .any(|rulepack| rulepack.get("name").and_then(Value::as_str) == Some(name))
    });
  if !active {
    bail!(
      "rulepack {name} was installed but is not active; ensure [waf].rulepack_files includes rulepacks/*.oxirule-rulepack.toml"
    );
  }
  Ok(())
}

#[derive(Debug)]
pub(crate) struct LoadedRulepackSource {
  pub(crate) manifest: String,
  pub(crate) base_dir: Option<PathBuf>,
  pub(crate) source_label: String,
  pub(crate) git_commit: Option<String>,
  pub(crate) source_provenance: Option<RulepackSourceProvenance>,
  _temp_dir: Option<TempTree>,
}

impl LoadedRulepackSource {
  pub(crate) fn from_url(
    manifest: String,
    source_label: String,
    source_provenance: RulepackSourceProvenance,
  ) -> anyhow::Result<Self> {
    Ok(Self {
      manifest,
      base_dir: None,
      source_label,
      git_commit: None,
      source_provenance: Some(source_provenance),
      _temp_dir: None,
    })
  }
}

async fn load_rulepack_source(
  args: &RulepackSourceArgs,
  timeout: Duration,
  require_pin: bool,
) -> anyhow::Result<LoadedRulepackSource> {
  match (&args.file, &args.dir, &args.url, &args.git) {
    (Some(path), None, None, None) => load_file_source(path),
    (None, Some(dir), None, None) => load_dir_source(dir, &args.manifest, None),
    (None, None, Some(url), None) => load_url_source(args, url, timeout, require_pin).await,
    (None, None, None, Some(git)) => load_git_source(args, git, require_pin),
    _ => bail!("rulepack source requires exactly one of --file, --dir, --url, or --git"),
  }
}

fn load_file_source(path: &Path) -> anyhow::Result<LoadedRulepackSource> {
  ensure_manifest_suffix(path)?;
  let manifest =
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
  Ok(LoadedRulepackSource {
    manifest,
    base_dir: path.parent().map(Path::to_path_buf),
    source_label: format!("file {}", path.display()),
    git_commit: None,
    source_provenance: None,
    _temp_dir: None,
  })
}

fn load_dir_source(
  dir: &Path,
  manifest: &Path,
  temp_dir: Option<TempTree>,
) -> anyhow::Result<LoadedRulepackSource> {
  ensure_manifest_suffix(manifest)?;
  let manifest_path = resolve_existing_local_source_file(dir, manifest)?;
  let manifest = std::fs::read_to_string(&manifest_path)
    .with_context(|| format!("failed to read {}", manifest_path.display()))?;
  Ok(LoadedRulepackSource {
    manifest,
    base_dir: Some(dir.to_path_buf()),
    source_label: format!("directory {}", dir.display()),
    git_commit: temp_dir.as_ref().and_then(|temp| temp.commit.clone()),
    source_provenance: None,
    _temp_dir: temp_dir,
  })
}

fn load_git_source(
  args: &RulepackSourceArgs,
  git: &str,
  require_pin: bool,
) -> anyhow::Result<LoadedRulepackSource> {
  let git_ref = args.git_ref.as_deref();
  if require_pin && git_ref.is_none() {
    bail!("rulepack apply from git requires --git-ref");
  }
  let clone_url = validate_git_url(git)?;
  let temp = clone_git_source(&clone_url, git_ref)?;
  let dir = temp.path().to_path_buf();
  load_dir_source(&dir, &args.manifest, Some(temp))
}

fn clone_git_source(clone_url: &str, git_ref: Option<&str>) -> anyhow::Result<TempTree> {
  let mut temp = TempTree::new()?;
  let mut clone = ProcessCommand::new("git");
  clone.arg("clone").arg("--depth").arg("1");
  if let Some(git_ref) = git_ref {
    clone.arg("--branch").arg(git_ref);
  }
  clone.arg(clone_url).arg(temp.path());
  run_git_command(&mut clone, "git clone")?;
  let mut rev_parse = ProcessCommand::new("git");
  rev_parse
    .arg("-C")
    .arg(temp.path())
    .arg("rev-parse")
    .arg("HEAD");
  let output = rev_parse
    .output()
    .context("failed to run git rev-parse for rulepack source")?;
  if !output.status.success() {
    bail!("git rev-parse failed for rulepack source");
  }
  let commit = String::from_utf8(output.stdout)
    .context("git rev-parse output was not UTF-8")?
    .trim()
    .to_string();
  temp.commit = Some(commit);
  Ok(temp)
}

fn run_git_command(command: &mut ProcessCommand, label: &str) -> anyhow::Result<()> {
  let status = command
    .status()
    .with_context(|| format!("failed to run {label} for rulepack source"))?;
  if !status.success() {
    bail!("{label} failed for rulepack source");
  }
  Ok(())
}

fn validate_git_url(git: &str) -> anyhow::Result<String> {
  let Some(clone_url) = git.strip_prefix("git+") else {
    bail!("--git must use git+https:// URLs");
  };
  let url = Url::parse(clone_url).context("invalid git rulepack URL")?;
  if url.scheme() != "https" {
    bail!("--git must use git+https:// URLs");
  }
  if !url.username().is_empty() || url.password().is_some() {
    bail!("git rulepack URL must not include username or password");
  }
  Ok(clone_url.to_string())
}

fn render_options(
  variables: BTreeMap<String, String>,
  mode: Option<RulepackModeArg>,
  force_mode: bool,
  source_commit: Option<String>,
  source_provenance: Option<RulepackSourceProvenance>,
) -> RulepackRenderOptions {
  RulepackRenderOptions {
    variables,
    mode_override: mode.map(|mode| RulepackModeOverride {
      mode: mode_arg(mode),
      force: force_mode,
    }),
    source_commit,
    source_provenance,
    pin_variables: false,
  }
}

fn render_text(raw: &str, variables: &BTreeMap<String, String>) -> String {
  let mut rendered = raw.to_string();
  for (name, value) in variables {
    rendered = rendered.replace(&format!("{{{{{name}}}}}"), value);
  }
  rendered
}

fn mode_arg(mode: RulepackModeArg) -> oxibelt::waf::WafMode {
  match mode {
    RulepackModeArg::Monitor => oxibelt::waf::WafMode::Monitor,
    RulepackModeArg::Enforcing => oxibelt::waf::WafMode::Enforcing,
  }
}

async fn current_etag(client: &AdminClient) -> anyhow::Result<String> {
  let response = client
    .request_json(Method::GET, "/admin/v1/config/status", None, None)
    .await?;
  if !response.status.is_success() {
    bail!("failed to fetch current config ETag: {}", response.status);
  }
  let value: Value =
    serde_json::from_slice(&response.body).context("config status was not JSON")?;
  value
    .get("etag")
    .and_then(Value::as_str)
    .map(str::to_string)
    .context("config status response did not include etag")
}

fn ensure_manifest_suffix(path: &Path) -> anyhow::Result<()> {
  let Some(value) = path.to_str() else {
    bail!(
      "rulepack manifest path is not valid UTF-8: {}",
      path.display()
    );
  };
  if !value.ends_with(RULEPACK_FILE_SUFFIX) {
    bail!("rulepack manifest path must end with {RULEPACK_FILE_SUFFIX}");
  }
  Ok(())
}

fn resolve_existing_local_source_file(base_dir: &Path, relative: &Path) -> anyhow::Result<PathBuf> {
  let candidate = join_local_source_path(base_dir, relative)?;
  let canonical_base = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve rulepack source directory {}",
      base_dir.display()
    )
  })?;
  let canonical_candidate = candidate.canonicalize().with_context(|| {
    format!(
      "failed to resolve rulepack source path {}",
      candidate.display()
    )
  })?;
  if !canonical_candidate.starts_with(&canonical_base) {
    bail!("rulepack source paths must stay within the rulepack source directory");
  }
  let metadata = canonical_candidate.metadata().with_context(|| {
    format!(
      "failed to inspect rulepack source path {}",
      canonical_candidate.display()
    )
  })?;
  if !metadata.is_file() {
    bail!(
      "rulepack source path must be a regular file: {}",
      canonical_candidate.display()
    );
  }
  Ok(canonical_candidate)
}

fn join_local_source_path(base_dir: &Path, relative: &Path) -> anyhow::Result<PathBuf> {
  if relative.as_os_str().is_empty() {
    bail!("rulepack source paths must not be empty");
  }
  if relative.is_absolute() {
    bail!("rulepack source paths must be relative");
  }
  let mut parts = Vec::new();
  for component in relative.components() {
    match component {
      std::path::Component::Normal(part) => parts.push(part),
      std::path::Component::CurDir
      | std::path::Component::ParentDir
      | std::path::Component::RootDir
      | std::path::Component::Prefix(_) => {
        bail!("rulepack source paths must not contain ., .., or absolute components");
      }
    }
  }
  let mut path = base_dir.to_path_buf();
  for part in parts {
    path.push(part);
  }
  Ok(path)
}

fn permission(action: &str, resource: &str) -> PermissionHint {
  PermissionHint::new(action, resource)
}

#[derive(Debug)]
struct TempTree {
  dir: tempfile::TempDir,
  commit: Option<String>,
}

impl TempTree {
  fn new() -> anyhow::Result<Self> {
    let dir = tempfile::Builder::new()
      .prefix("oxibelt-rulepack-")
      .tempdir()
      .context("failed to create temporary rulepack directory")?;
    Ok(Self { dir, commit: None })
  }

  fn path(&self) -> &Path {
    self.dir.path()
  }
}

#[cfg(test)]
#[path = "rulepack_tests.rs"]
mod tests;
