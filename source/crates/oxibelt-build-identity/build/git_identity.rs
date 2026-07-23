use super::semver::{compare_semver, is_release_version};
use super::{
  Cleanliness, Identity, Kind, validate_build_suffix, validate_revision, validate_source_ref,
};
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) fn discover_git_identity(workspace: &Path) -> Result<Identity, String> {
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

pub(super) fn cross_check_git(workspace: &Path, identity: &Identity) -> Result<(), String> {
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

pub(super) fn workspace_root(manifest_dir: &Path) -> PathBuf {
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

pub(super) fn find_git_marker(workspace: &Path) -> Option<PathBuf> {
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

pub(super) fn emit_git_rerun_inputs(workspace: &Path) -> Result<(), String> {
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
