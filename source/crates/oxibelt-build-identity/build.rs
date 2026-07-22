#[path = "src/semver.rs"]
mod semver;

use semver::{compare_semver, is_release_version, parse_semver, release_build_revision};
use std::cmp::Ordering;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const INPUTS: [&str; 5] = [
  "OXIBELT_BUILD_KIND",
  "OXIBELT_BUILD_VERSION",
  "OXIBELT_BUILD_REVISION",
  "OXIBELT_BUILD_REF",
  "OXIBELT_BUILD_DIRTY",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cleanliness {
  Clean,
  Dirty,
  Unknown,
}

impl Cleanliness {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "clean" => Ok(Self::Clean),
      "dirty" => Ok(Self::Dirty),
      "unknown" => Ok(Self::Unknown),
      _ => Err("OXIBELT_BUILD_DIRTY must be clean, dirty, or unknown".to_string()),
    }
  }

  const fn as_str(self) -> &'static str {
    match self {
      Self::Clean => "clean",
      Self::Dirty => "dirty",
      Self::Unknown => "unknown",
    }
  }

  const fn rust_variant(self) -> &'static str {
    match self {
      Self::Clean => "DirtyState::Clean",
      Self::Dirty => "DirtyState::Dirty",
      Self::Unknown => "DirtyState::Unknown",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
  OfficialRelease,
  TaggedDevelopment,
  GitDevelopment,
  SourceArchive,
}

impl Kind {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "official_release" => Ok(Self::OfficialRelease),
      "tagged_development" => Ok(Self::TaggedDevelopment),
      "git_development" => Ok(Self::GitDevelopment),
      "source_archive" => Ok(Self::SourceArchive),
      _ => Err("OXIBELT_BUILD_KIND is not a supported identity kind".to_string()),
    }
  }

  const fn as_str(self) -> &'static str {
    match self {
      Self::OfficialRelease => "official_release",
      Self::TaggedDevelopment => "tagged_development",
      Self::GitDevelopment => "git_development",
      Self::SourceArchive => "source_archive",
    }
  }

  const fn rust_variant(self) -> &'static str {
    match self {
      Self::OfficialRelease => "BuildKind::OfficialRelease",
      Self::TaggedDevelopment => "BuildKind::TaggedDevelopment",
      Self::GitDevelopment => "BuildKind::GitDevelopment",
      Self::SourceArchive => "BuildKind::SourceArchive",
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Identity {
  version: String,
  revision: Option<String>,
  source_ref: Option<String>,
  dirty: Cleanliness,
  kind: Kind,
  compatibility: Option<String>,
}

fn main() {
  for input in INPUTS {
    println!("cargo:rerun-if-env-changed={input}");
  }
  println!("cargo:rerun-if-env-changed=OXIBELT_SOURCE_REVISION");
  assert!(
    env::var_os("OXIBELT_SOURCE_REVISION").is_none(),
    "OXIBELT_SOURCE_REVISION is obsolete; provide the complete OXIBELT_BUILD_* identity tuple"
  );

  let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest dir"));
  let workspace = workspace_root(&manifest_dir);
  let git_present = find_git_marker(&workspace).is_some();
  let identity = explicit_identity()
    .map(|identity| {
      let identity = identity.unwrap_or_else(|error| panic!("invalid build identity: {error}"));
      if git_present {
        cross_check_git(&workspace, &identity)
          .unwrap_or_else(|error| panic!("explicit build identity does not match Git: {error}"));
      }
      identity
    })
    .unwrap_or_else(|| {
      if git_present {
        discover_git_identity(&workspace)
          .unwrap_or_else(|error| panic!("failed to resolve Git build identity: {error}"))
      } else {
        archive_identity()
      }
    });

  if git_present {
    emit_git_rerun_inputs(&workspace)
      .unwrap_or_else(|error| panic!("failed to register Git build inputs: {error}"));
  }
  write_generated(&identity);
}

fn explicit_identity() -> Option<Result<Identity, String>> {
  let values = match INPUTS
    .map(|name| match env::var(name) {
      Ok(value) => Ok(Some(value)),
      Err(env::VarError::NotPresent) => Ok(None),
      Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    })
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
  {
    Ok(values) => values,
    Err(error) => return Some(Err(error)),
  };
  if values.iter().all(Option::is_none) {
    return None;
  }
  if values.iter().any(Option::is_none) {
    return Some(Err(format!(
      "setting any identity input requires all of {}",
      INPUTS.join(", ")
    )));
  }
  let values = values
    .into_iter()
    .map(|value| value.expect("all tuple values were checked"))
    .collect::<Vec<_>>();
  Some(validate_explicit(
    &values[0],
    &values[1],
    &values[2],
    &values[3],
    &values[4],
    &env::var("CARGO_PKG_VERSION").expect("Cargo package version"),
  ))
}

fn validate_explicit(
  kind: &str,
  version: &str,
  revision: &str,
  source_ref: &str,
  dirty: &str,
  cargo_package_version: &str,
) -> Result<Identity, String> {
  for (name, value) in INPUTS
    .into_iter()
    .zip([kind, version, revision, source_ref, dirty])
  {
    if value.is_empty() || value.trim() != value {
      return Err(format!(
        "{name} must be non-empty and have no surrounding whitespace"
      ));
    }
  }
  parse_semver(version).map_err(|error| format!("OXIBELT_BUILD_VERSION: {error}"))?;
  let kind = Kind::parse(kind)?;
  let dirty = Cleanliness::parse(dirty)?;

  match kind {
    Kind::OfficialRelease => {
      validate_revision(revision)?;
      validate_source_ref(source_ref)?;
      if dirty != Cleanliness::Clean {
        return Err("official releases must be clean".to_string());
      }
      if !is_release_version(version) {
        return Err(
          "official release version does not match repository release grammar".to_string(),
        );
      }
      if source_ref != format!("refs/tags/{version}") {
        return Err("official release source ref must be refs/tags/<version>".to_string());
      }
      if cargo_package_version != version {
        return Err("official release version must equal the Cargo package version".to_string());
      }
      validate_build_suffix(version, revision)?;
      Ok(Identity {
        version: version.to_string(),
        revision: Some(revision.to_string()),
        source_ref: Some(source_ref.to_string()),
        dirty,
        kind,
        compatibility: Some(version.to_string()),
      })
    }
    Kind::TaggedDevelopment => {
      validate_revision(revision)?;
      validate_source_ref(source_ref)?;
      let tag = version.strip_suffix("+dirty").unwrap_or(version);
      if !is_release_version(tag) || source_ref != format!("refs/tags/{tag}") {
        return Err(
          "tagged development identity must name the exact repository release tag".to_string(),
        );
      }
      validate_build_suffix(tag, revision)?;
      match dirty {
        Cleanliness::Clean if tag != version => {
          return Err("clean tagged builds must not use +dirty".to_string());
        }
        Cleanliness::Dirty if tag == version => {
          return Err("dirty tagged builds must use +dirty".to_string());
        }
        Cleanliness::Unknown => {
          return Err("tagged development dirty state cannot be unknown".to_string());
        }
        _ => {}
      }
      Ok(Identity {
        version: version.to_string(),
        revision: Some(revision.to_string()),
        source_ref: Some(source_ref.to_string()),
        dirty,
        kind,
        compatibility: (dirty == Cleanliness::Clean).then(|| tag.to_string()),
      })
    }
    Kind::GitDevelopment => {
      validate_revision(revision)?;
      let source_ref = if source_ref == "unknown" {
        None
      } else {
        validate_source_ref(source_ref)?;
        Some(source_ref.to_string())
      };
      if dirty == Cleanliness::Unknown {
        return Err("Git development dirty state cannot be unknown".to_string());
      }
      let expected = format!(
        "0.0.0-dev.{}{}",
        &revision[..8],
        if dirty == Cleanliness::Dirty {
          "+dirty"
        } else {
          ""
        }
      );
      if version != expected {
        return Err(format!("Git development version must be {expected}"));
      }
      Ok(Identity {
        version: version.to_string(),
        revision: Some(revision.to_string()),
        source_ref,
        dirty,
        kind,
        compatibility: None,
      })
    }
    Kind::SourceArchive => {
      if version != "0.0.0-dev.archive"
        || revision != "unknown"
        || source_ref != "unknown"
        || dirty != Cleanliness::Unknown
      {
        return Err(
          "source archives require version 0.0.0-dev.archive and unknown revision/ref/dirty"
            .to_string(),
        );
      }
      Ok(archive_identity())
    }
  }
}

fn discover_git_identity(workspace: &Path) -> Result<Identity, String> {
  let revision = git(workspace, &["rev-parse", "--verify", "HEAD"])?;
  validate_revision(&revision)?;
  let dirty = if git(
    workspace,
    &["status", "--porcelain", "--untracked-files=no"],
  )?
  .is_empty()
  {
    Cleanliness::Clean
  } else {
    Cleanliness::Dirty
  };
  let tags = git(workspace, &["tag", "--points-at", "HEAD"])?;
  let mut selected: Option<String> = None;
  for tag in tags.lines().filter(|tag| is_release_version(tag)) {
    validate_build_suffix(tag, &revision)?;
    match selected.as_deref() {
      None => selected = Some(tag.to_string()),
      Some(current) => match compare_semver(tag, current).expect("release tags are valid SemVer") {
        Ordering::Greater => selected = Some(tag.to_string()),
        Ordering::Equal => {
          return Err(format!(
            "ambiguous equal-precedence release tags at HEAD: {current}, {tag}"
          ));
        }
        Ordering::Less => {}
      },
    }
  }

  if let Some(tag) = selected {
    let version = format!(
      "{tag}{}",
      if dirty == Cleanliness::Dirty {
        "+dirty"
      } else {
        ""
      }
    );
    return Ok(Identity {
      version,
      revision: Some(revision),
      source_ref: Some(format!("refs/tags/{tag}")),
      dirty,
      kind: Kind::TaggedDevelopment,
      compatibility: (dirty == Cleanliness::Clean).then_some(tag),
    });
  }

  let source_ref = match git_optional(workspace, &["symbolic-ref", "-q", "HEAD"])? {
    Some(value) => {
      validate_source_ref(&value)?;
      Some(value)
    }
    None => None,
  };
  Ok(Identity {
    version: format!(
      "0.0.0-dev.{}{}",
      &revision[..8],
      if dirty == Cleanliness::Dirty {
        "+dirty"
      } else {
        ""
      }
    ),
    revision: Some(revision),
    source_ref,
    dirty,
    kind: Kind::GitDevelopment,
    compatibility: None,
  })
}

fn cross_check_git(workspace: &Path, identity: &Identity) -> Result<(), String> {
  if identity.kind == Kind::SourceArchive {
    return Err("source_archive cannot be asserted from a Git checkout".to_string());
  }
  let head = git(workspace, &["rev-parse", "--verify", "HEAD"])?;
  if identity.revision.as_deref() != Some(head.as_str()) {
    return Err("revision does not equal Git HEAD".to_string());
  }
  let actual_dirty = if git(
    workspace,
    &["status", "--porcelain", "--untracked-files=no"],
  )?
  .is_empty()
  {
    Cleanliness::Clean
  } else {
    Cleanliness::Dirty
  };
  if identity.dirty != actual_dirty {
    return Err("dirty state does not match tracked Git changes".to_string());
  }
  if let Some(source_ref) = identity.source_ref.as_deref() {
    if source_ref.starts_with("refs/tags/") {
      let target = git(
        workspace,
        &["rev-parse", &format!("{source_ref}^{{commit}}")],
      )?;
      if target != head {
        return Err("tag source ref does not resolve to Git HEAD".to_string());
      }
    } else {
      let current = git(workspace, &["symbolic-ref", "-q", "HEAD"])?;
      if current != source_ref {
        return Err("branch source ref does not equal the current symbolic ref".to_string());
      }
    }
  }
  Ok(())
}

fn archive_identity() -> Identity {
  Identity {
    version: "0.0.0-dev.archive".to_string(),
    revision: None,
    source_ref: None,
    dirty: Cleanliness::Unknown,
    kind: Kind::SourceArchive,
    compatibility: None,
  }
}

fn validate_revision(value: &str) -> Result<(), String> {
  if value.len() == 40
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    Ok(())
  } else {
    Err("revision must be an exact 40-character lowercase hexadecimal commit".to_string())
  }
}

fn validate_source_ref(value: &str) -> Result<(), String> {
  let suffix = value
    .strip_prefix("refs/heads/")
    .or_else(|| value.strip_prefix("refs/tags/"))
    .ok_or_else(|| "source ref must be under refs/heads/ or refs/tags/".to_string())?;
  if suffix.is_empty()
    || suffix.starts_with('.')
    || suffix.ends_with('.')
    || suffix.ends_with('/')
    || suffix.contains("..")
    || suffix.contains("@{")
    || suffix.contains("//")
    || suffix
      .split('/')
      .any(|component| component.starts_with('.') || component.ends_with(".lock"))
    || suffix
      .bytes()
      .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')))
  {
    return Err("source ref contains an unsafe or non-canonical component".to_string());
  }
  Ok(())
}

fn validate_build_suffix(version: &str, revision: &str) -> Result<(), String> {
  if let Some(suffix) = release_build_revision(version)
    && suffix != &revision[..8]
  {
    return Err("release build suffix does not match the revision prefix".to_string());
  }
  Ok(())
}

fn workspace_root(manifest_dir: &Path) -> PathBuf {
  manifest_dir
    .ancestors()
    .find(|path| {
      fs::read_to_string(path.join("Cargo.toml"))
        .is_ok_and(|manifest| manifest.starts_with("[workspace]"))
    })
    .unwrap_or_else(|| {
      panic!(
        "failed to locate workspace root from {}",
        manifest_dir.display()
      )
    })
    .to_path_buf()
}

fn find_git_marker(workspace: &Path) -> Option<PathBuf> {
  let marker = workspace.join(".git");
  marker.exists().then_some(marker)
}

fn git(workspace: &Path, arguments: &[&str]) -> Result<String, String> {
  git_optional(workspace, arguments)?.ok_or_else(|| format!("git {} failed", arguments.join(" ")))
}

fn git_optional(workspace: &Path, arguments: &[&str]) -> Result<Option<String>, String> {
  let output = Command::new("git")
    .args(arguments)
    .current_dir(workspace)
    .output()
    .map_err(|error| format!("could not execute git: {error}"))?;
  if output.status.success() {
    let value = String::from_utf8(output.stdout)
      .map_err(|_| "git output was not UTF-8".to_string())?
      .trim()
      .to_string();
    Ok(Some(value))
  } else if output.status.code() == Some(1) {
    Ok(None)
  } else {
    Err(format!(
      "git {} exited with {}: {}",
      arguments.join(" "),
      output.status,
      String::from_utf8_lossy(&output.stderr).trim()
    ))
  }
}

fn emit_git_rerun_inputs(workspace: &Path) -> Result<(), String> {
  for path in [
    ".git/HEAD",
    ".git/index",
    ".git/packed-refs",
    ".git/refs/heads",
    ".git/refs/tags",
  ] {
    println!("cargo:rerun-if-changed={}", workspace.join(path).display());
  }
  let output = Command::new("git")
    .args(["ls-files", "-z"])
    .current_dir(workspace)
    .output()
    .map_err(|error| format!("could not execute git ls-files: {error}"))?;
  if !output.status.success() {
    return Err(format!(
      "git ls-files exited with {}: {}",
      output.status,
      String::from_utf8_lossy(&output.stderr).trim()
    ));
  }
  let tracked = String::from_utf8(output.stdout)
    .map_err(|_| "tracked Git paths must be UTF-8 for Cargo rebuild tracking".to_string())?;
  for relative in tracked.split('\0').filter(|path| !path.is_empty()) {
    if relative.contains('\n')
      || relative.contains('\r')
      || Path::new(relative)
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
      return Err(format!(
        "tracked path is unsafe for a Cargo directive: {relative:?}"
      ));
    }
    println!(
      "cargo:rerun-if-changed={}",
      workspace.join(relative).display()
    );
  }
  Ok(())
}

fn write_generated(identity: &Identity) {
  let revision = identity.revision.as_deref().unwrap_or("unknown");
  let source_ref = identity.source_ref.as_deref().unwrap_or("unknown");
  let marker = format!(
    "OXIBELT_BUILD_IDENTITY_V1={{\"version\":{},\"revision\":{},\"source_ref\":{},\"dirty\":{},\"kind\":{}}}",
    json_string(&identity.version),
    json_string(revision),
    json_string(source_ref),
    json_string(identity.dirty.as_str()),
    json_string(identity.kind.as_str()),
  );
  let long_version = format!("{}\n{marker}", identity.version);
  let revision = option_literal(identity.revision.as_deref());
  let source_ref = option_literal(identity.source_ref.as_deref());
  let compatibility = option_literal(identity.compatibility.as_deref());
  let generated = format!(
    "pub const SHORT_VERSION: &str = {version:?};\n\
     pub const MACHINE_IDENTITY_MARKER: &str = {marker:?};\n\
     pub const LONG_VERSION: &str = {long_version:?};\n\
     pub const BUILD_IDENTITY: BuildIdentity = BuildIdentity {{\n\
       effective_version: {version:?},\n\
       source_revision: {revision},\n\
       source_ref: {source_ref},\n\
       dirty: {dirty},\n\
       kind: {kind},\n\
       compatibility_version: {compatibility},\n\
     }};\n",
    version = identity.version,
    dirty = identity.dirty.rust_variant(),
    kind = identity.kind.rust_variant(),
  );
  let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo build output dir"));
  fs::write(out.join("build_identity.rs"), generated).expect("write generated build identity");
}

fn option_literal(value: Option<&str>) -> String {
  value.map_or_else(|| "None".to_string(), |value| format!("Some({value:?})"))
}

fn json_string(value: &str) -> String {
  let mut result = String::with_capacity(value.len() + 2);
  result.push('"');
  for character in value.chars() {
    match character {
      '"' => result.push_str("\\\""),
      '\\' => result.push_str("\\\\"),
      '\n' => result.push_str("\\n"),
      '\r' => result.push_str("\\r"),
      '\t' => result.push_str("\\t"),
      character if character.is_control() => {
        use std::fmt::Write as _;
        write!(&mut result, "\\u{:04x}", character as u32).expect("write JSON escape");
      }
      character => result.push(character),
    }
  }
  result.push('"');
  result
}

#[cfg(test)]
mod tests {
  use super::{
    Cleanliness, Kind, archive_identity, discover_git_identity, find_git_marker, validate_explicit,
    validate_source_ref,
  };
  use std::fs;
  use std::path::{Path, PathBuf};
  use std::process::Command;
  use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

  const REVISION: &str = "abcdef0123456789abcdef0123456789abcdef01";
  static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);

  struct TemporaryWorkspace {
    path: PathBuf,
  }

  impl TemporaryWorkspace {
    fn new() -> Self {
      let sequence = NEXT_TEMPORARY.fetch_add(1, AtomicOrdering::Relaxed);
      let path = std::env::temp_dir().join(format!(
        "oxibelt-build-identity-{}-{sequence}",
        std::process::id()
      ));
      fs::create_dir(&path).expect("create isolated identity test workspace");
      Self { path }
    }

    fn git(&self, arguments: &[&str]) -> String {
      let output = Command::new("git")
        .arg("-C")
        .arg(&self.path)
        .args(arguments)
        .output()
        .expect("execute Git in identity test workspace");
      assert!(
        output.status.success(),
        "git {} failed: {}",
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr)
      );
      String::from_utf8(output.stdout)
        .expect("Git test output is UTF-8")
        .trim()
        .to_string()
    }

    fn initialize_git(&self) -> String {
      self.git(&["init", "--quiet"]);
      self.git(&["symbolic-ref", "HEAD", "refs/heads/main"]);
      fs::write(self.path.join("tracked.txt"), "clean\n").expect("write tracked fixture");
      self.git(&["add", "tracked.txt"]);
      self.git(&[
        "-c",
        "user.name=OxiBelt Tests",
        "-c",
        "user.email=tests@oxibelt.invalid",
        "commit",
        "--quiet",
        "-m",
        "identity fixture",
      ]);
      self.git(&["rev-parse", "HEAD"])
    }

    fn path(&self) -> &Path {
      &self.path
    }
  }

  impl Drop for TemporaryWorkspace {
    fn drop(&mut self) {
      let _ = fs::remove_dir_all(&self.path);
    }
  }

  #[test]
  fn validates_all_explicit_identity_kinds() {
    assert!(
      validate_explicit(
        "git_development",
        "0.0.0-dev.abcdef01",
        REVISION,
        "refs/heads/main",
        "clean",
        "0.0.0",
      )
      .is_ok()
    );
    let archive = validate_explicit(
      "source_archive",
      "0.0.0-dev.archive",
      "unknown",
      "unknown",
      "unknown",
      "0.0.0",
    )
    .expect("archive identity");
    assert_eq!(archive.kind, Kind::SourceArchive);
    assert_eq!(archive.dirty, Cleanliness::Unknown);

    for version in ["1.2.3", "1.2.3-beta.4", "1.2.3-build.abcdef01"] {
      let official = validate_explicit(
        "official_release",
        version,
        REVISION,
        &format!("refs/tags/{version}"),
        "clean",
        version,
      )
      .expect("valid official identity");
      assert_eq!(official.kind, Kind::OfficialRelease);
      assert_eq!(official.compatibility.as_deref(), Some(version));
    }

    let tagged = validate_explicit(
      "tagged_development",
      "1.2.3",
      REVISION,
      "refs/tags/1.2.3",
      "clean",
      "0.0.0",
    )
    .expect("clean exact-tag identity");
    assert_eq!(tagged.compatibility.as_deref(), Some("1.2.3"));
    let dirty_tagged = validate_explicit(
      "tagged_development",
      "1.2.3+dirty",
      REVISION,
      "refs/tags/1.2.3",
      "dirty",
      "0.0.0",
    )
    .expect("dirty exact-tag identity");
    assert_eq!(dirty_tagged.compatibility, None);
  }

  #[test]
  fn rejects_partial_shapes_and_unsafe_refs() {
    assert!(
      validate_explicit(
        "git_development",
        "0.0.0-dev.abcdef01",
        "ABCDEF0123456789abcdef0123456789abcdef01",
        "refs/heads/main",
        "clean",
        "0.0.0",
      )
      .is_err()
    );
    for source_ref in [
      "main",
      "refs/heads/../main",
      "refs/heads/a@{b",
      "refs/heads/a b",
    ] {
      assert!(validate_source_ref(source_ref).is_err(), "{source_ref}");
    }
    assert!(
      validate_explicit(
        "official_release",
        "1.2.3",
        REVISION,
        "refs/tags/1.2.3",
        "clean",
        "0.0.0",
      )
      .is_err(),
      "official version must equal Cargo package metadata"
    );
    assert!(
      validate_explicit(
        "official_release",
        "1.2.3-build.00000000",
        REVISION,
        "refs/tags/1.2.3-build.00000000",
        "clean",
        "1.2.3-build.00000000",
      )
      .is_err(),
      "release build suffix must bind the commit prefix"
    );
    assert!(
      validate_explicit(
        "source_archive",
        "0.0.0",
        "unknown",
        "unknown",
        "unknown",
        "0.0.0",
      )
      .is_err(),
      "Cargo sentinel must not identify an archive build"
    );
  }

  #[test]
  fn discovers_clean_and_dirty_untagged_git_identities() {
    let workspace = TemporaryWorkspace::new();
    let revision = workspace.initialize_git();

    let clean = discover_git_identity(workspace.path()).expect("clean Git identity");
    assert_eq!(clean.kind, Kind::GitDevelopment);
    assert_eq!(clean.dirty, Cleanliness::Clean);
    assert_eq!(clean.revision.as_deref(), Some(revision.as_str()));
    assert_eq!(clean.source_ref.as_deref(), Some("refs/heads/main"));
    assert_eq!(clean.version, format!("0.0.0-dev.{}", &revision[..8]));
    assert_eq!(clean.compatibility, None);

    fs::write(workspace.path().join("tracked.txt"), "dirty\n").expect("modify tracked fixture");
    let dirty = discover_git_identity(workspace.path()).expect("dirty Git identity");
    assert_eq!(dirty.kind, Kind::GitDevelopment);
    assert_eq!(dirty.dirty, Cleanliness::Dirty);
    assert_eq!(dirty.version, format!("0.0.0-dev.{}+dirty", &revision[..8]));
    assert_eq!(dirty.compatibility, None);
  }

  #[test]
  fn discovers_clean_exact_tag_identity() {
    let workspace = TemporaryWorkspace::new();
    let revision = workspace.initialize_git();
    workspace.git(&["tag", "1.2.3"]);

    let identity = discover_git_identity(workspace.path()).expect("tagged Git identity");
    assert_eq!(identity.kind, Kind::TaggedDevelopment);
    assert_eq!(identity.dirty, Cleanliness::Clean);
    assert_eq!(identity.version, "1.2.3");
    assert_eq!(identity.revision.as_deref(), Some(revision.as_str()));
    assert_eq!(identity.source_ref.as_deref(), Some("refs/tags/1.2.3"));
    assert_eq!(identity.compatibility.as_deref(), Some("1.2.3"));
  }

  #[test]
  fn identifies_source_archive_without_git_metadata() {
    let workspace = TemporaryWorkspace::new();
    assert_eq!(find_git_marker(workspace.path()), None);

    let identity = archive_identity();
    assert_eq!(identity.kind, Kind::SourceArchive);
    assert_eq!(identity.version, "0.0.0-dev.archive");
    assert_eq!(identity.revision, None);
    assert_eq!(identity.source_ref, None);
    assert_eq!(identity.dirty, Cleanliness::Unknown);
    assert_eq!(identity.compatibility, None);
  }
}
