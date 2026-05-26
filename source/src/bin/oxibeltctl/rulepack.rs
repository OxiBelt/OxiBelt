use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use http::{HeaderValue, Method, Request, StatusCode};
use oxibelt::admin_client::{AdminClient, AdminResponse};
use oxibelt::control_http::{ControlHttpClient, empty_body};
use oxibelt::waf::{
  RULEPACK_FILE_SUFFIX, RulepackModeOverride, RulepackReferencedFileKind, RulepackRenderOptions,
  inspect_rulepack, referenced_rulepack_files, render_rulepack_for_install,
  validate_rulepack_manifest,
};
use ring::digest;
use serde_json::{Value, json};
use url::Url;

use crate::cli::{
  Command, OutputFormat, RulepackApplyArgs, RulepackCommand, RulepackModeArg, RulepackRemoveArgs,
  RulepackSourceArgs, RulepackSubcommand,
};
use crate::output::{print_permission_hint, print_response};
use crate::plan::{PermissionHint, RequestPlan};

const MAX_RULEPACK_BYTES: usize = 1024 * 1024;

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
      let rendered = render_rulepack_for_install(
        &loaded.manifest,
        &loaded.source_label,
        render_options(
          &args.vars,
          args.mode,
          args.force_mode,
          loaded.git_commit.clone(),
        )?,
      )?;
      print!("{rendered}");
      Ok(true)
    }
    RulepackSubcommand::Check(args) => {
      let loaded = load_rulepack_source(&args.source, Duration::from_secs(10), false).await?;
      validate_rulepack_manifest(&loaded.manifest)?;
      let options = render_options(&args.vars, None, false, loaded.git_commit.clone())?;
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
    RulepackSubcommand::List | RulepackSubcommand::Apply(_) | RulepackSubcommand::Remove(_) => {
      Ok(false)
    }
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
    RulepackSubcommand::Inspect(_)
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
  let options = render_options(
    &args.vars,
    Some(args.mode),
    args.force_mode,
    loaded.git_commit.clone(),
  )?;
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
      "content": render_text(&raw, &parse_vars(&args.vars)?),
    }));
  }
  operations.push(json!({
    "op": "put",
    "root": "oxirule_rulepack",
    "path": installed_rulepack_path(&name)?,
    "content": rendered_manifest,
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

async fn plan_rulepack_remove(
  client: &AdminClient,
  args: &RulepackRemoveArgs,
) -> anyhow::Result<RequestPlan> {
  if !args.apply {
    bail!("rulepack remove requires --apply");
  }
  let path = installed_rulepack_path(&args.name)?;
  let etag = current_etag(client).await?;
  Ok(RequestPlan {
    method: Method::POST,
    endpoint: "/admin/v1/files/sync".to_string(),
    body: Some(json!({
      "apply": "oxirule",
      "operations": [{
        "op": "delete",
        "root": "oxirule_rulepack",
        "path": path,
      }],
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
struct LoadedRulepackSource {
  manifest: String,
  base_dir: Option<PathBuf>,
  source_label: String,
  git_commit: Option<String>,
  _temp_dir: Option<TempTree>,
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
    _temp_dir: temp_dir,
  })
}

async fn load_url_source(
  args: &RulepackSourceArgs,
  url: &Url,
  timeout: Duration,
  require_pin: bool,
) -> anyhow::Result<LoadedRulepackSource> {
  validate_rulepack_url(url, args.allow_insecure_rulepack_url)?;
  ensure_manifest_url_suffix(url)?;
  if require_pin && args.sha256.is_none() && !args.allow_unpinned_rulepack {
    bail!("rulepack apply from URL requires --sha256 unless --allow-unpinned-rulepack is set");
  }
  let bytes = download_rulepack(url, &args.ca_certs, args.token_env.as_deref(), timeout).await?;
  if let Some(expected) = args.sha256.as_deref() {
    verify_sha256(expected, &bytes)?;
  }
  Ok(LoadedRulepackSource {
    manifest: String::from_utf8(bytes).context("rulepack URL body was not UTF-8")?,
    base_dir: None,
    source_label: format!("URL {}", diagnostic_url(url)),
    git_commit: None,
    _temp_dir: None,
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
  let dir = temp.path.clone();
  load_dir_source(&dir, &args.manifest, Some(temp))
}

async fn download_rulepack(
  url: &Url,
  ca_certs: &[PathBuf],
  token_env: Option<&str>,
  timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
  let client = ControlHttpClient::new(ca_certs).context("failed to build rulepack HTTP client")?;
  let uri = oxibelt::control_http::uri_from_url(&request_url(url))?;
  let mut builder = Request::builder()
    .method(Method::GET)
    .uri(uri)
    .header(http::header::ACCEPT, "application/toml, text/plain");
  if let Some(token_env) = token_env {
    builder = builder.header(http::header::AUTHORIZATION, bearer_header(token_env)?);
  }
  let request = builder
    .body(empty_body())
    .context("failed to build rulepack request")?;
  let response = client
    .request(request, timeout, MAX_RULEPACK_BYTES)
    .await
    .with_context(|| format!("failed to download rulepack from {}", diagnostic_url(url)))?;
  if !response.status.is_success() {
    bail!(
      "rulepack download from {} failed with {}",
      diagnostic_url(url),
      response.status
    );
  }
  Ok(response.body.to_vec())
}

fn clone_git_source(clone_url: &str, git_ref: Option<&str>) -> anyhow::Result<TempTree> {
  let mut temp = TempTree::new()?;
  let mut clone = ProcessCommand::new("git");
  clone.arg("clone").arg("--depth").arg("1");
  if let Some(git_ref) = git_ref {
    clone.arg("--branch").arg(git_ref);
  }
  clone.arg(clone_url).arg(&temp.path);
  run_git_command(&mut clone, "git clone")?;
  let mut rev_parse = ProcessCommand::new("git");
  rev_parse
    .arg("-C")
    .arg(&temp.path)
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

fn validate_rulepack_url(url: &Url, allow_insecure: bool) -> anyhow::Result<()> {
  if !url.username().is_empty() || url.password().is_some() {
    bail!("rulepack URL must not include username or password; use --rulepack-token-env");
  }
  match url.scheme() {
    "https" => Ok(()),
    "http" if allow_insecure => Ok(()),
    "http" => bail!("rulepack URL requires https unless --allow-insecure-rulepack-url is set"),
    scheme => bail!("rulepack URL must use http or https, got {scheme}"),
  }
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
  vars: &[String],
  mode: Option<RulepackModeArg>,
  force_mode: bool,
  source_commit: Option<String>,
) -> anyhow::Result<RulepackRenderOptions> {
  Ok(RulepackRenderOptions {
    variables: parse_vars(vars)?,
    mode_override: mode.map(|mode| RulepackModeOverride {
      mode: mode_arg(mode),
      force: force_mode,
    }),
    source_commit,
    pin_variables: false,
  })
}

fn parse_vars(vars: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
  let mut parsed = BTreeMap::new();
  for item in vars {
    let Some((key, value)) = item.split_once('=') else {
      bail!("--var must use KEY=VALUE");
    };
    if key.trim().is_empty() {
      bail!("--var key must not be empty");
    }
    parsed.insert(key.to_string(), value.to_string());
  }
  Ok(parsed)
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

fn installed_rulepack_path(name: &str) -> anyhow::Result<String> {
  if name.trim().is_empty()
    || name
      .chars()
      .any(|character| matches!(character, '/' | '\\' | '?' | '#'))
  {
    bail!("rulepack name is not valid for an install path");
  }
  Ok(format!("rulepacks/{name}{RULEPACK_FILE_SUFFIX}"))
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

fn ensure_manifest_url_suffix(url: &Url) -> anyhow::Result<()> {
  if !url.path().ends_with(RULEPACK_FILE_SUFFIX) {
    bail!("rulepack URL path must end with {RULEPACK_FILE_SUFFIX}");
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

fn verify_sha256(expected: &str, bytes: &[u8]) -> anyhow::Result<()> {
  let expected = expected.trim();
  if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("--sha256 must be a 64-character hex SHA-256 digest");
  }
  let actual = hex_encode(digest::digest(&digest::SHA256, bytes).as_ref());
  if !actual.eq_ignore_ascii_case(expected) {
    bail!("rulepack SHA-256 mismatch: expected {expected}, got {actual}");
  }
  Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write;
    write!(&mut out, "{byte:02x}").expect("hex write should succeed");
  }
  out
}

fn bearer_header(token_env: &str) -> anyhow::Result<HeaderValue> {
  let token = std::env::var(token_env)
    .with_context(|| format!("rulepack token environment variable {token_env} is not set"))?;
  let token = token.trim();
  if token.is_empty() {
    bail!("rulepack token environment variable {token_env} is empty");
  }
  HeaderValue::from_str(&format!("Bearer {token}"))
    .context("rulepack bearer token is not header-safe")
}

fn request_url(url: &Url) -> Url {
  let mut request_url = url.clone();
  request_url.set_fragment(None);
  request_url
}

fn diagnostic_url(url: &Url) -> String {
  let mut diagnostic_url = url.clone();
  let _ = diagnostic_url.set_username("");
  let _ = diagnostic_url.set_password(None);
  diagnostic_url.set_query(None);
  diagnostic_url.set_fragment(None);
  diagnostic_url.to_string()
}

fn permission(action: &str, resource: &str) -> PermissionHint {
  PermissionHint {
    action: action.to_string(),
    resource: resource.to_string(),
  }
}

#[derive(Debug)]
struct TempTree {
  path: PathBuf,
  commit: Option<String>,
}

impl TempTree {
  fn new() -> anyhow::Result<Self> {
    let stamp = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos();
    let path =
      std::env::temp_dir().join(format!("oxibelt-rulepack-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&path)
      .with_context(|| format!("failed to create temporary directory {}", path.display()))?;
    Ok(Self { path, commit: None })
  }
}

impl Drop for TempTree {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.path);
  }
}

#[cfg(test)]
#[path = "rulepack_tests.rs"]
mod tests;
