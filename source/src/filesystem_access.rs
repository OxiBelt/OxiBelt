//! Deterministic filesystem-access planning derived from resolved configuration.
//!
//! The manifest is intentionally separate from enforcement. Building or checking a
//! manifest never creates, removes, renames, or writes a filesystem object.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{
  BufferingMode, CacheStore, ClientIdentityAsnManagedStorage, ClientIdentityAsnMode, Config,
  CrliteConfig, CrliteManagedStorage, CrliteMode, RedisTrustStore, SharedStateBackendKind,
};
use crate::hardening::{
  LandlockFilesystemRight, LandlockManifestProjection, LandlockManifestRule,
  ReadOnlyRootfsCompatibility,
};

mod atomic_writer;

pub const FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION: u32 = 3;
const FILESYSTEM_ACCESS_MANIFEST_NORMALIZATION: &str =
  "canonical_enforcement_with_verified_kubernetes_atomic_writer_digest_identity_v3";
const MAX_MANIFEST_ENTRIES: usize = 8_192;
const MAX_FILESYSTEM_ACCESS_FINDINGS: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_MOUNTINFO_BYTES: u64 = 1024 * 1024;
const MAX_MOUNTINFO_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccessMode {
  ReadFile,
  ReadDirectory,
  WriteFile,
  CreateFile,
  RemoveFile,
  Rename,
  CreateDirectory,
  RemoveDirectory,
  ConnectUnixSocket,
  BindUnixSocket,
}

impl FilesystemAccessMode {
  pub fn requires_write(self) -> bool {
    matches!(
      self,
      Self::WriteFile
        | Self::CreateFile
        | Self::RemoveFile
        | Self::Rename
        | Self::CreateDirectory
        | Self::RemoveDirectory
        | Self::BindUnixSocket
    )
  }

  fn requires_read(self) -> bool {
    matches!(self, Self::ReadFile | Self::ReadDirectory)
  }
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccessPurpose {
  Configuration,
  GeneratedConfiguration,
  TlsCertificate,
  TlsPrivateKey,
  TlsTrustStore,
  TlsStatusData,
  WafRules,
  Discovery,
  Cache,
  RequestBuffer,
  AuditSpool,
  AuditAnchor,
  ClientIdentity,
  StaticContent,
  RuntimeSocket,
  RuntimeState,
  ExternalServiceCredential,
  SystemResolver,
  PlatformObservation,
  RuntimeDiagnostics,
  RuntimeData,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemPathType {
  RegularFile,
  Directory,
  UnixSocket,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemPathScope {
  Exact,
  Descendants,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FilesystemAccessEntry {
  path: PathBuf,
  /// Stable path identity used only for manifest ordering and digesting.
  ///
  /// Enforcement, checks, containment, and operator-visible paths always use
  /// `path`, which remains the canonical path resolved for the current
  /// filesystem generation.
  digest_identity_path: PathBuf,
  access: Vec<FilesystemAccessMode>,
  purpose: FilesystemAccessPurpose,
  source_config_path: Option<String>,
  expected_type: FilesystemPathType,
  scope: FilesystemPathScope,
  requires_parent_write: bool,
  optional: bool,
}

impl FilesystemAccessEntry {
  pub fn path(&self) -> &Path {
    &self.path
  }

  pub fn access(&self) -> &[FilesystemAccessMode] {
    &self.access
  }

  pub fn purpose(&self) -> FilesystemAccessPurpose {
    self.purpose
  }

  pub fn source_config_path(&self) -> Option<&str> {
    self.source_config_path.as_deref()
  }

  pub fn expected_type(&self) -> FilesystemPathType {
    self.expected_type
  }

  pub fn scope(&self) -> FilesystemPathScope {
    self.scope
  }

  pub fn requires_parent_write(&self) -> bool {
    self.requires_parent_write
  }

  pub fn optional(&self) -> bool {
    self.optional
  }

  pub fn requires_write(&self) -> bool {
    self.access.iter().any(|mode| mode.requires_write()) || self.requires_parent_write
  }

  fn covers(&self, required: &Self) -> bool {
    if required.requires_parent_write && !self.requires_parent_write {
      return false;
    }
    if !required
      .access
      .iter()
      .all(|mode| self.access.contains(mode))
    {
      return false;
    }
    match self.scope {
      FilesystemPathScope::Exact => {
        required.scope == FilesystemPathScope::Exact && self.path == required.path
      }
      FilesystemPathScope::Descendants => {
        required.path == self.path || required.path.starts_with(&self.path)
      }
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FilesystemAccessExpansionKind {
  PathAdded,
  RightsExpanded,
  ScopeExpanded,
  ParentWriteExpanded,
}

#[derive(Debug, Clone, Copy)]
pub struct FilesystemAccessExpansion<'a> {
  entry: &'a FilesystemAccessEntry,
  kind: FilesystemAccessExpansionKind,
}

impl<'a> FilesystemAccessExpansion<'a> {
  pub fn entry(self) -> &'a FilesystemAccessEntry {
    self.entry
  }

  pub fn kind(self) -> FilesystemAccessExpansionKind {
    self.kind
  }
}

fn expansion_from_entries<'a>(
  required: &'a FilesystemAccessEntry,
  installed: &[FilesystemAccessEntry],
) -> Option<FilesystemAccessExpansion<'a>> {
  if installed.iter().any(|entry| entry.covers(required)) {
    return None;
  }
  let mut same_path = installed.iter().filter(|entry| entry.path == required.path);
  let kind = if required.requires_parent_write
    && same_path.clone().any(|entry| !entry.requires_parent_write)
  {
    FilesystemAccessExpansionKind::ParentWriteExpanded
  } else if same_path.clone().any(|entry| {
    required
      .access
      .iter()
      .any(|mode| !entry.access.contains(mode))
  }) {
    FilesystemAccessExpansionKind::RightsExpanded
  } else if same_path.any(|entry| {
    entry.scope == FilesystemPathScope::Exact && required.scope == FilesystemPathScope::Descendants
  }) {
    FilesystemAccessExpansionKind::ScopeExpanded
  } else {
    FilesystemAccessExpansionKind::PathAdded
  };
  Some(FilesystemAccessExpansion {
    entry: required,
    kind,
  })
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FilesystemAccessManifest {
  schema_version: u32,
  entries: Vec<FilesystemAccessEntry>,
  digest: String,
}

impl FilesystemAccessManifest {
  pub fn from_config(config: &Config) -> anyhow::Result<Self> {
    ManifestBuilder::from_config(config)?.finish()
  }

  pub fn schema_version(&self) -> u32 {
    self.schema_version
  }

  pub fn entries(&self) -> &[FilesystemAccessEntry] {
    &self.entries
  }

  pub fn digest(&self) -> &str {
    &self.digest
  }

  /// Returns entries whose access is not covered by `installed`.
  ///
  /// Purpose and source metadata are explanatory and do not affect containment.
  pub fn access_expansion_from<'a>(
    &'a self,
    installed: &FilesystemAccessManifest,
  ) -> Vec<FilesystemAccessExpansion<'a>> {
    self
      .entries
      .iter()
      .filter_map(|required| expansion_from_entries(required, &installed.entries))
      .collect()
  }

  pub fn access_is_subset_of(&self, installed: &FilesystemAccessManifest) -> bool {
    self.access_expansion_from(installed).is_empty()
  }

  /// Returns candidate entries not covered by the installed manifest or by
  /// explicit operator Landlock additions. Write requirements are only
  /// covered by read-write roots; read requirements may use either class.
  pub fn access_expansion_from_landlock<'a>(
    &'a self,
    installed: Option<&FilesystemAccessManifest>,
    explicit_read_paths: &[PathBuf],
    explicit_read_write_paths: &[PathBuf],
  ) -> Vec<FilesystemAccessExpansion<'a>> {
    let explicit_read_paths = explicit_read_paths
      .iter()
      .map(|path| path.canonicalize().unwrap_or_else(|_| path.clone()))
      .collect::<Vec<_>>();
    let explicit_read_write_paths = explicit_read_write_paths
      .iter()
      .map(|path| path.canonicalize().unwrap_or_else(|_| path.clone()))
      .collect::<Vec<_>>();
    self
      .entries
      .iter()
      .filter_map(|required| {
        if installed
          .is_some_and(|installed| installed.entries.iter().any(|entry| entry.covers(required)))
        {
          return None;
        }
        let covered_by = |roots: &[PathBuf]| {
          roots
            .iter()
            .any(|root| required.path == *root || required.path.starts_with(root))
        };
        if required.requires_write() {
          if covered_by(&explicit_read_write_paths) {
            return None;
          }
        } else {
          if covered_by(&explicit_read_paths) || covered_by(&explicit_read_write_paths) {
            return None;
          }
        }
        let kind = installed
          .and_then(|installed| {
            expansion_from_entries(required, &installed.entries).map(|value| value.kind)
          })
          .unwrap_or_else(|| {
            if required.requires_write() && covered_by(&explicit_read_paths) {
              FilesystemAccessExpansionKind::RightsExpanded
            } else {
              FilesystemAccessExpansionKind::PathAdded
            }
          });
        Some(FilesystemAccessExpansion {
          entry: required,
          kind,
        })
      })
      .collect()
  }

  pub fn view(&self, show_paths: bool) -> FilesystemAccessManifestView {
    let path_ids = path_ids(&self.entries);
    let entries = self
      .entries
      .iter()
      .map(|entry| entry_view(entry, &path_ids, show_paths))
      .collect();
    FilesystemAccessManifestView {
      schema_version: self.schema_version,
      manifest_digest: show_paths.then(|| self.digest.clone()),
      manifest_digest_withheld: !show_paths,
      paths_redacted: !show_paths,
      normalization: FILESYSTEM_ACCESS_MANIFEST_NORMALIZATION,
      entries,
    }
  }

  pub fn check_current(&self, show_paths: bool) -> FilesystemAccessCheckReport {
    let mountinfo = read_current_mountinfo();
    self.check(show_paths, mountinfo.as_deref())
  }

  /// Projects the normalized manifest into the exact path classes consumed by
  /// Landlock installation. The projection never opens file contents.
  pub fn landlock_projection(&self) -> LandlockManifestProjection {
    let mut read_paths = Vec::new();
    let mut read_write_paths = Vec::new();
    let mut projected_rules = BTreeMap::<PathBuf, BTreeSet<LandlockFilesystemRight>>::new();
    let mut parent_scope_representable = true;
    for entry in &self.entries {
      let access = landlock_rights_for_entry(entry);
      if access.is_empty() {
        // Landlock filesystem ABIs do not mediate Unix-domain connect(2).
        // Keep the requirement in the operator manifest without inventing a
        // filesystem right or requiring the peer socket to exist at startup.
        continue;
      }
      if entry.requires_parent_write && !entry.path.exists() {
        parent_scope_representable = false;
      }
      if entry.optional && !entry.path.exists() {
        continue;
      }
      let path = entry.path.clone();
      if entry.requires_write() {
        read_write_paths.push(path);
      } else {
        read_paths.push(path);
      }
      projected_rules
        .entry(entry.path.clone())
        .or_default()
        .extend(access);
    }
    read_paths.sort();
    read_paths.dedup();
    read_write_paths.sort();
    read_write_paths.dedup();
    read_paths.retain(|path| read_write_paths.binary_search(path).is_err());
    let rules = projected_rules
      .into_iter()
      .map(|(path, access)| LandlockManifestRule {
        path,
        access: access.into_iter().collect(),
      })
      .collect();

    let read_only_rootfs = match self.check_current(false).read_only_rootfs_compatible {
      Some(true) => ReadOnlyRootfsCompatibility::Compatible,
      Some(false) => ReadOnlyRootfsCompatibility::Incompatible,
      None => ReadOnlyRootfsCompatibility::Unknown,
    };
    LandlockManifestProjection {
      manifest_digest: self.digest.clone(),
      read_paths,
      read_write_paths,
      rules,
      read_only_rootfs,
      parent_scope_representable,
    }
  }

  /// Checks current filesystem state without creating, changing, or connecting to an object.
  pub fn check(&self, show_paths: bool, mountinfo: Option<&str>) -> FilesystemAccessCheckReport {
    let path_ids = path_ids(&self.entries);
    let parsed_mounts = mountinfo.map(parse_mountinfo);
    let mounts = parsed_mounts
      .as_ref()
      .and_then(|result| result.as_ref().ok());
    let mut findings = FindingCollector::default();

    if let Some(Err(error)) = parsed_mounts.as_ref() {
      findings.push(FilesystemAccessFinding {
        severity: FilesystemAccessFindingSeverity::Warning,
        code: FilesystemAccessFindingCode::MountInfoUnavailable,
        path_id: None,
        path: None,
        source_config_path: None,
        detail: error.to_string(),
      });
    }

    for entry in &self.entries {
      check_entry(entry, &path_ids, show_paths, mounts, &mut findings);
    }
    find_conflicts_and_redundancy(&self.entries, &path_ids, show_paths, &mut findings);
    findings.findings.sort_by(|left, right| {
      (
        left.severity,
        left.code,
        left.path_id.as_deref(),
        left.source_config_path.as_deref(),
      )
        .cmp(&(
          right.severity,
          right.code,
          right.path_id.as_deref(),
          right.source_config_path.as_deref(),
        ))
    });

    let read_only_rootfs_compatible = mounts.map(|mounts| {
      self
        .entries
        .iter()
        .filter(|entry| entry.requires_write())
        .all(|entry| {
          find_mount(entry.path(), mounts)
            .is_some_and(|mount| mount.mount_point != Path::new("/") && !mount.read_only)
        })
    });
    let ok = !findings
      .findings
      .iter()
      .any(|finding| finding.severity == FilesystemAccessFindingSeverity::Error);
    let total_findings = findings.total;
    let findings_truncated = total_findings > findings.findings.len();

    FilesystemAccessCheckReport {
      schema_version: self.schema_version,
      manifest_digest: show_paths.then(|| self.digest.clone()),
      manifest_digest_withheld: !show_paths,
      paths_redacted: !show_paths,
      ok,
      read_only_rootfs_compatible,
      mountinfo_detected: mounts.is_some(),
      total_findings: u32::try_from(total_findings).unwrap_or(u32::MAX),
      findings_truncated,
      findings: findings.findings,
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FilesystemAccessManifestView {
  pub schema_version: u32,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub manifest_digest: Option<String>,
  pub manifest_digest_withheld: bool,
  pub paths_redacted: bool,
  pub normalization: &'static str,
  pub entries: Vec<FilesystemAccessEntryView>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FilesystemAccessEntryView {
  pub path_id: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  pub access: Vec<FilesystemAccessMode>,
  pub purpose: FilesystemAccessPurpose,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub source_config_path: Option<String>,
  pub expected_type: FilesystemPathType,
  pub scope: FilesystemPathScope,
  pub requires_parent_write: bool,
  pub optional: bool,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccessFindingSeverity {
  Error,
  Warning,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemAccessFindingCode {
  PathMissing,
  PathTypeMismatch,
  ReadDenied,
  WriteDenied,
  ParentMissing,
  ParentNotDirectory,
  ParentWriteDenied,
  ParentScopeUnrepresentable,
  ReadOnlyMount,
  MountInfoUnavailable,
  ConflictingExpectation,
  RedundantBroaderAccess,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FilesystemAccessFinding {
  pub severity: FilesystemAccessFindingSeverity,
  pub code: FilesystemAccessFindingCode,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub path_id: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub source_config_path: Option<String>,
  pub detail: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct FilesystemAccessCheckReport {
  pub schema_version: u32,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub manifest_digest: Option<String>,
  pub manifest_digest_withheld: bool,
  pub paths_redacted: bool,
  pub ok: bool,
  pub read_only_rootfs_compatible: Option<bool>,
  pub mountinfo_detected: bool,
  pub total_findings: u32,
  pub findings_truncated: bool,
  pub findings: Vec<FilesystemAccessFinding>,
}

#[derive(Debug, Default)]
struct FindingCollector {
  findings: Vec<FilesystemAccessFinding>,
  total: usize,
}

impl FindingCollector {
  fn push(&mut self, finding: FilesystemAccessFinding) {
    self.total = self.total.saturating_add(1);
    if self.findings.len() < MAX_FILESYSTEM_ACCESS_FINDINGS {
      self.findings.push(finding);
    }
  }
}

impl FilesystemAccessCheckReport {
  pub fn has_errors(&self) -> bool {
    !self.ok
  }
}

#[derive(Debug)]
struct ManifestBuilder {
  entries: Vec<FilesystemAccessEntry>,
  precise_read_paths: BTreeSet<PathBuf>,
  cwd: PathBuf,
}

struct ManifestEntrySpec<'a> {
  access: &'a [FilesystemAccessMode],
  purpose: FilesystemAccessPurpose,
  source_config_path: Option<String>,
  expected_type: FilesystemPathType,
  scope: FilesystemPathScope,
  requires_parent_write: bool,
  optional: bool,
}

impl ManifestBuilder {
  fn from_config(config: &Config) -> anyhow::Result<Self> {
    let mut builder = Self {
      entries: Vec::new(),
      precise_read_paths: BTreeSet::new(),
      cwd: std::env::current_dir().context("failed to resolve current directory")?,
    };

    builder.collect_configuration(config)?;
    builder.collect_downstream_tls(config)?;
    builder.collect_waf_and_discovery(config)?;
    builder.collect_trust_and_credentials(config)?;
    builder.collect_cache_and_buffering(config)?;
    builder.collect_crlite(config)?;
    builder.collect_client_identity(config)?;
    builder.collect_audit(config)?;
    builder.collect_sockets_and_generated_files(config)?;
    builder.collect_static_content(config)?;
    builder.collect_remaining_runtime_files(config)?;
    builder.collect_intrinsic_runtime_reads(config)?;
    Ok(builder)
  }

  fn finish(mut self) -> anyhow::Result<FilesystemAccessManifest> {
    self.entries.sort_by(entry_order);
    self.entries.dedup();
    if self.entries.len() > MAX_MANIFEST_ENTRIES {
      bail!(
        "filesystem access manifest has {} entries; maximum is {MAX_MANIFEST_ENTRIES}",
        self.entries.len()
      );
    }
    let digest = manifest_digest(&self.entries);
    Ok(FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: self.entries,
      digest,
    })
  }

  fn add(&mut self, path: &Path, spec: ManifestEntrySpec<'_>) -> anyhow::Result<()> {
    let ManifestEntrySpec {
      access,
      purpose,
      source_config_path,
      expected_type,
      scope,
      requires_parent_write,
      optional,
    } = spec;
    if self.entries.len() >= MAX_MANIFEST_ENTRIES {
      bail!("filesystem access manifest exceeds {MAX_MANIFEST_ENTRIES} entries");
    }
    if path.as_os_str().is_empty() {
      let source = source_config_path.as_deref().unwrap_or("unknown source");
      bail!("filesystem manifest path for {source} must not be empty");
    }
    let logical_path = lexical_absolute_path(path, &self.cwd).ok();
    let path = normalize_path(path, &self.cwd)?;
    let digest_identity_path = logical_path
      .as_deref()
      .and_then(|logical| atomic_writer::digest_identity_path(logical, &path))
      .unwrap_or_else(|| path.clone());
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
      bail!("filesystem manifest path exceeds {MAX_PATH_BYTES} bytes");
    }
    if digest_identity_path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
      bail!("filesystem manifest digest identity path exceeds {MAX_PATH_BYTES} bytes");
    }
    if source_config_path.as_deref().is_some_and(str::is_empty) {
      bail!("filesystem manifest source_config_path must not be empty");
    }
    let mut access = access.to_vec();
    access.sort();
    access.dedup();
    if access.is_empty() {
      bail!("filesystem manifest entry must request at least one access mode");
    }
    if scope == FilesystemPathScope::Descendants && expected_type != FilesystemPathType::Directory {
      bail!("descendant filesystem access must be rooted at a directory");
    }
    if access.iter().any(|mode| mode.requires_read()) {
      self.precise_read_paths.insert(path.clone());
    }
    self.entries.push(FilesystemAccessEntry {
      path,
      digest_identity_path,
      access,
      purpose,
      source_config_path,
      expected_type,
      scope,
      requires_parent_write,
      optional,
    });
    Ok(())
  }

  fn add_read_file(
    &mut self,
    path: &Path,
    purpose: FilesystemAccessPurpose,
    source: impl Into<String>,
    rotation_parent: bool,
  ) -> anyhow::Result<()> {
    let source = source.into();
    self.add(
      path,
      ManifestEntrySpec {
        access: &[FilesystemAccessMode::ReadFile],
        purpose,
        source_config_path: Some(source.clone()),
        expected_type: FilesystemPathType::RegularFile,
        scope: FilesystemPathScope::Exact,
        requires_parent_write: false,
        optional: false,
      },
    )?;
    if rotation_parent {
      let logical = lexical_absolute_path(path, &self.cwd)?;
      let logical_parent = logical.parent().ok_or_else(|| {
        anyhow!(
          "filesystem manifest path {} has no parent for rotation",
          logical.display()
        )
      })?;
      let parent = normalize_path(logical_parent, &self.cwd)?;
      self.add(
        &parent,
        ManifestEntrySpec {
          access: &[
            FilesystemAccessMode::ReadDirectory,
            FilesystemAccessMode::ReadFile,
          ],
          purpose,
          source_config_path: Some(source),
          expected_type: FilesystemPathType::Directory,
          scope: FilesystemPathScope::Descendants,
          requires_parent_write: false,
          optional: false,
        },
      )?;
    }
    Ok(())
  }

  fn add_write_directory(
    &mut self,
    path: &Path,
    purpose: FilesystemAccessPurpose,
    source: impl Into<String>,
    requires_parent_write: bool,
  ) -> anyhow::Result<()> {
    self.add(
      path,
      ManifestEntrySpec {
        access: &[
          FilesystemAccessMode::ReadFile,
          FilesystemAccessMode::ReadDirectory,
          FilesystemAccessMode::WriteFile,
          FilesystemAccessMode::CreateFile,
          FilesystemAccessMode::RemoveFile,
          FilesystemAccessMode::Rename,
          FilesystemAccessMode::CreateDirectory,
          FilesystemAccessMode::RemoveDirectory,
        ],
        purpose,
        source_config_path: Some(source.into()),
        expected_type: FilesystemPathType::Directory,
        scope: FilesystemPathScope::Descendants,
        requires_parent_write,
        optional: false,
      },
    )
  }

  fn add_optional_intrinsic_file(
    &mut self,
    path: &Path,
    purpose: FilesystemAccessPurpose,
    source: impl Into<String>,
  ) -> anyhow::Result<()> {
    self.add(
      path,
      ManifestEntrySpec {
        access: &[FilesystemAccessMode::ReadFile],
        purpose,
        source_config_path: Some(source.into()),
        expected_type: FilesystemPathType::RegularFile,
        scope: FilesystemPathScope::Exact,
        requires_parent_write: false,
        optional: true,
      },
    )
  }

  fn add_optional_intrinsic_directory(
    &mut self,
    path: &Path,
    purpose: FilesystemAccessPurpose,
    source: impl Into<String>,
  ) -> anyhow::Result<()> {
    self.add(
      path,
      ManifestEntrySpec {
        access: &[
          FilesystemAccessMode::ReadDirectory,
          FilesystemAccessMode::ReadFile,
        ],
        purpose,
        source_config_path: Some(source.into()),
        expected_type: FilesystemPathType::Directory,
        scope: FilesystemPathScope::Descendants,
        requires_parent_write: false,
        optional: true,
      },
    )
  }

  fn collect_configuration(&mut self, config: &Config) -> anyhow::Result<()> {
    if let Some(entry) = &config.source_paths.config_entry {
      self.add_read_file(
        entry,
        FilesystemAccessPurpose::Configuration,
        "config.entrypoint",
        true,
      )?;
    }
    for (index, path) in config.source_paths.config_files.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::Configuration,
        format!("config.includes[{index}]"),
        true,
      )?;
    }
    Ok(())
  }

  fn collect_downstream_tls(&mut self, config: &Config) -> anyhow::Result<()> {
    let paths = &config.source_paths;
    self.add_read_file(
      &config.tls.cert_chain,
      FilesystemAccessPurpose::TlsCertificate,
      "tls.cert_chain",
      true,
    )?;
    if let Some(path) = &config.tls.private_key {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsPrivateKey,
        "tls.private_key",
        true,
      )?;
    }
    for (index, certificate) in config.tls.certificates.iter().enumerate() {
      self.add_read_file(
        &certificate.cert_chain,
        FilesystemAccessPurpose::TlsCertificate,
        format!("tls.certificates[{index}].cert_chain"),
        true,
      )?;
      if let Some(path) = &certificate.private_key {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::TlsPrivateKey,
          format!("tls.certificates[{index}].private_key"),
          true,
        )?;
      }
      if let Some(path) = &certificate.ocsp.response_file {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::TlsStatusData,
          format!("tls.certificates[{index}].ocsp.response_file"),
          true,
        )?;
      }
    }
    if config.tls.remote_signer.enabled {
      self.add(
        &config.tls.remote_signer.socket_path,
        ManifestEntrySpec {
          access: &[FilesystemAccessMode::ConnectUnixSocket],
          purpose: FilesystemAccessPurpose::RuntimeSocket,
          source_config_path: Some("tls.remote_signer.socket_path".to_string()),
          expected_type: FilesystemPathType::UnixSocket,
          scope: FilesystemPathScope::Exact,
          requires_parent_write: false,
          optional: false,
        },
      )?;
      if let Some(path) = &config.tls.remote_signer.token_file {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::ExternalServiceCredential,
          "tls.remote_signer.token_file",
          true,
        )?;
      }
    }
    if let Some(path) = &config.tls.ocsp.response_file {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsStatusData,
        "tls.ocsp.response_file",
        true,
      )?;
    }
    for (index, path) in config.tls.client_auth.ca_certs.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsTrustStore,
        format!("tls.client_auth.ca_certs[{index}]"),
        true,
      )?;
    }
    if let Some(path) = &config.quic.host_key_file {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsPrivateKey,
        "quic.host_key_file",
        true,
      )?;
    }

    // Logical reload paths can differ from canonical targets when operators use symlinks.
    for (index, path) in paths.downstream_tls_files.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsStatusData,
        format!("config.source_paths.downstream_tls_files[{index}]"),
        true,
      )?;
    }
    Ok(())
  }

  fn collect_waf_and_discovery(&mut self, config: &Config) -> anyhow::Result<()> {
    for (index, path) in config.source_paths.oxirule_files.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::WafRules,
        format!("waf.loaded_rule_paths[{index}]"),
        true,
      )?;
    }
    for (index, path) in config.source_paths.discovery_files.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::Discovery,
        format!("upstream_pools[].discovery.files[{index}]"),
        true,
      )?;
    }
    Ok(())
  }

  fn collect_trust_and_credentials(&mut self, config: &Config) -> anyhow::Result<()> {
    for (index, path) in config.proxy.trusted_ca_certs.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsTrustStore,
        format!("proxy.trusted_ca_certs[{index}]"),
        false,
      )?;
    }
    for (upstream_index, upstream) in config.upstreams.iter().enumerate() {
      for (ca_index, path) in upstream.tls.trusted_ca_certs.iter().enumerate() {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::TlsTrustStore,
          format!("upstreams[{upstream_index}].tls.trusted_ca_certs[{ca_index}]"),
          false,
        )?;
      }
      if let Some(path) = &upstream.tls.ech.config_list_file {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::TlsStatusData,
          format!("upstreams[{upstream_index}].tls.ech.config_list_file"),
          false,
        )?;
      }
    }
    for (index, path) in config.access_log.otlp.trusted_ca_certs.iter().enumerate() {
      self.add_read_file(
        path,
        FilesystemAccessPurpose::TlsTrustStore,
        format!("access_log.otlp.trusted_ca_certs[{index}]"),
        false,
      )?;
    }
    for (index, signer) in config.admin.mutations.signers.iter().enumerate() {
      self.add_read_file(
        &signer.ed25519_public_key_file,
        FilesystemAccessPurpose::ExternalServiceCredential,
        format!("admin.mutations.signers[{index}].ed25519_public_key_file"),
        true,
      )?;
      if let Some(path) = &signer.ml_dsa_44_public_key_file {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::ExternalServiceCredential,
          format!("admin.mutations.signers[{index}].ml_dsa_44_public_key_file"),
          true,
        )?;
      }
    }
    Ok(())
  }

  fn collect_cache_and_buffering(&mut self, config: &Config) -> anyhow::Result<()> {
    if config.cache.enabled {
      let uses_tmpfs = config.cache.store == CacheStore::Tmpfs
        || config.cache.policies.iter().any(|policy| {
          policy.store == Some(CacheStore::Tmpfs)
            || policy
              .rules
              .iter()
              .any(|rule| rule.store == CacheStore::Tmpfs)
        });
      let uses_disk = config.cache.store.uses_disk()
        || config.cache.policies.iter().any(|policy| {
          policy.store.is_some_and(CacheStore::uses_disk)
            || policy.rules.iter().any(|rule| rule.store.uses_disk())
        });
      if uses_tmpfs {
        let path = config
          .cache
          .tmpfs_dir
          .clone()
          .unwrap_or_else(crate::config::default_cache_tmpfs_dir);
        self.add_write_directory(
          &path,
          FilesystemAccessPurpose::Cache,
          "cache.tmpfs_dir",
          false,
        )?;
      }
      if uses_disk && let Some(path) = &config.cache.disk_dir {
        self.add_write_directory(
          path,
          FilesystemAccessPurpose::Cache,
          "cache.disk_dir",
          false,
        )?;
      }
    }

    let uses_spool = config.proxy.buffering.request == BufferingMode::Spool
      || config.proxy.buffering.response == BufferingMode::Spool
      || config.routes.iter().any(|route| {
        route.buffering.request == Some(BufferingMode::Spool)
          || route.buffering.response == Some(BufferingMode::Spool)
      });
    if uses_spool && let Some(path) = &config.proxy.buffering.temp_dir {
      self.add_write_directory(
        path,
        FilesystemAccessPurpose::RequestBuffer,
        "proxy.buffering.temp_dir",
        false,
      )?;
    }
    Ok(())
  }

  fn collect_crlite(&mut self, config: &Config) -> anyhow::Result<()> {
    self.collect_crlite_config(&config.tls.crlite, "tls.crlite")?;
    self.collect_crlite_config(
      &config.proxy.upstream_revocation.crlite,
      "proxy.upstream_revocation.crlite",
    )?;
    for (index, upstream) in config.upstreams.iter().enumerate() {
      if let Some(revocation) = &upstream.tls.upstream_revocation {
        self.collect_crlite_config(
          &revocation.crlite,
          &format!("upstreams[{index}].tls.upstream_revocation.crlite"),
        )?;
      }
    }
    Ok(())
  }

  fn collect_crlite_config(&mut self, config: &CrliteConfig, source: &str) -> anyhow::Result<()> {
    match config.mode {
      CrliteMode::Disabled => Ok(()),
      CrliteMode::Enforce => {
        if let Some(path) = &config.filter_file {
          self.add_read_file(
            path,
            FilesystemAccessPurpose::TlsStatusData,
            format!("{source}.filter_file"),
            true,
          )?;
        }
        Ok(())
      }
      CrliteMode::Managed => match config.managed.storage {
        CrliteManagedStorage::Memory => Ok(()),
        CrliteManagedStorage::Tmpfs => self.add_write_directory(
          &config.managed.tmpfs_dir,
          FilesystemAccessPurpose::TlsStatusData,
          format!("{source}.managed.tmpfs_dir"),
          false,
        ),
        CrliteManagedStorage::Disk => self.add_write_directory(
          &config.managed.cache_dir,
          FilesystemAccessPurpose::TlsStatusData,
          format!("{source}.managed.cache_dir"),
          false,
        ),
      },
    }
  }

  fn collect_client_identity(&mut self, config: &Config) -> anyhow::Result<()> {
    let asn = &config.client_identity.asn;
    match asn.mode {
      ClientIdentityAsnMode::Disabled => {}
      ClientIdentityAsnMode::Local => {
        if let Some(path) = &asn.database_file {
          self.add_read_file(
            path,
            FilesystemAccessPurpose::ClientIdentity,
            "client_identity.asn.database_file",
            true,
          )?;
        }
      }
      ClientIdentityAsnMode::Managed => match asn.managed.storage {
        ClientIdentityAsnManagedStorage::Memory => {}
        ClientIdentityAsnManagedStorage::Tmpfs => self.add_write_directory(
          &asn.managed.tmpfs_dir,
          FilesystemAccessPurpose::ClientIdentity,
          "client_identity.asn.managed.tmpfs_dir",
          false,
        )?,
        ClientIdentityAsnManagedStorage::Disk => self.add_write_directory(
          &asn.managed.cache_dir,
          FilesystemAccessPurpose::ClientIdentity,
          "client_identity.asn.managed.cache_dir",
          false,
        )?,
      },
    }
    Ok(())
  }

  fn collect_audit(&mut self, config: &Config) -> anyhow::Result<()> {
    let audit = &config.admin.audit;
    if !config.admin.enabled || !audit.enabled {
      return Ok(());
    }
    if audit.spool.enabled
      && let Some(path) = &audit.spool.directory
    {
      self.add_write_directory(
        path,
        FilesystemAccessPurpose::AuditSpool,
        "admin.audit.spool.directory",
        true,
      )?;
    }
    if audit.anchor.enabled {
      self.add(
        &audit.anchor.signer.socket_path,
        ManifestEntrySpec {
          access: &[FilesystemAccessMode::ConnectUnixSocket],
          purpose: FilesystemAccessPurpose::RuntimeSocket,
          source_config_path: Some("admin.audit.anchor.signer.socket_path".to_string()),
          expected_type: FilesystemPathType::UnixSocket,
          scope: FilesystemPathScope::Exact,
          requires_parent_write: false,
          optional: false,
        },
      )?;
      self.add_read_file(
        &audit.anchor.signer.public_key_file,
        FilesystemAccessPurpose::AuditAnchor,
        "admin.audit.anchor.signer.public_key_file",
        true,
      )?;
      if let Some(path) = &audit.anchor.signer.token_file {
        self.add_read_file(
          path,
          FilesystemAccessPurpose::ExternalServiceCredential,
          "admin.audit.anchor.signer.token_file",
          true,
        )?;
      }
    }
    Ok(())
  }

  fn collect_sockets_and_generated_files(&mut self, config: &Config) -> anyhow::Result<()> {
    if config.runtime.netport_switcher.enabled {
      self.add(
        &config.runtime.netport_switcher.socket_dir,
        ManifestEntrySpec {
          access: &[
            FilesystemAccessMode::ReadDirectory,
            FilesystemAccessMode::CreateDirectory,
            FilesystemAccessMode::BindUnixSocket,
            FilesystemAccessMode::ConnectUnixSocket,
            FilesystemAccessMode::RemoveFile,
          ],
          purpose: FilesystemAccessPurpose::RuntimeSocket,
          source_config_path: Some("runtime.netport_switcher.socket_dir".to_string()),
          expected_type: FilesystemPathType::Directory,
          scope: FilesystemPathScope::Descendants,
          requires_parent_write: true,
          optional: false,
        },
      )?;
    }

    if config.admin.enabled && !config.rollout.blocks_per_pod_mutation() {
      if let Some(path) = &config.source_paths.config_dir {
        self.add_write_directory(
          path,
          FilesystemAccessPurpose::GeneratedConfiguration,
          "config.source_paths.config_dir",
          false,
        )?;
      }
      if let Some(path) = &config.source_paths.oxirule_dir {
        self.add_write_directory(
          path,
          FilesystemAccessPurpose::WafRules,
          "config.source_paths.oxirule_dir",
          false,
        )?;
      }
    }
    Ok(())
  }

  fn collect_static_content(&mut self, config: &Config) -> anyhow::Result<()> {
    for (index, route) in config.routes.iter().enumerate() {
      if let Some(path) = &route.static_root {
        self.add(
          path,
          ManifestEntrySpec {
            access: &[
              FilesystemAccessMode::ReadDirectory,
              FilesystemAccessMode::ReadFile,
            ],
            purpose: FilesystemAccessPurpose::StaticContent,
            source_config_path: Some(format!("routes[{index}].static_root")),
            expected_type: FilesystemPathType::Directory,
            scope: FilesystemPathScope::Descendants,
            requires_parent_write: false,
            optional: false,
          },
        )?;
      }
    }
    Ok(())
  }

  fn collect_remaining_runtime_files(&mut self, config: &Config) -> anyhow::Result<()> {
    for (index, path) in config.source_paths.runtime_files.iter().enumerate() {
      let normalized = normalize_path(path, &self.cwd)?;
      if self.precise_read_paths.contains(&normalized) {
        continue;
      }
      self.add_read_file(
        path,
        FilesystemAccessPurpose::RuntimeData,
        format!("config.source_paths.runtime_files[{index}]"),
        false,
      )?;
    }
    Ok(())
  }

  fn collect_intrinsic_runtime_reads(&mut self, config: &Config) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
      return Ok(());
    }

    for (path, source) in [
      ("/etc/resolv.conf", "runtime.system_resolver.resolv_conf"),
      ("/etc/hosts", "runtime.system_resolver.hosts"),
    ] {
      self.add_optional_intrinsic_file(
        Path::new(path),
        FilesystemAccessPurpose::SystemResolver,
        source,
      )?;
    }

    for (path, source) in [
      ("/proc/self/status", "runtime.platform.process_status"),
      ("/proc/self/limits", "runtime.platform.process_limits"),
      ("/proc/self/mountinfo", "runtime.platform.mountinfo"),
      ("/proc/self/cgroup", "runtime.platform.cgroup_membership"),
    ] {
      self.add_optional_intrinsic_file(
        Path::new(path),
        FilesystemAccessPurpose::PlatformObservation,
        source,
      )?;
    }
    if config.overload.enabled
      || config.circuit_breakers.enabled
      || config.cache.enabled
      || config.admin.enabled
      || config
        .routes
        .iter()
        .any(|route| route.static_root.is_some())
    {
      self.add_optional_intrinsic_directory(
        Path::new("/proc/self/fd"),
        FilesystemAccessPurpose::PlatformObservation,
        "runtime.platform.open_file_descriptors",
      )?;
      for (path, source) in [
        ("/proc/meminfo", "runtime.platform.host_memory"),
        (
          "/sys/fs/cgroup/memory.current",
          "runtime.platform.cgroup_memory_current",
        ),
        (
          "/sys/fs/cgroup/memory.max",
          "runtime.platform.cgroup_memory_max",
        ),
        (
          "/sys/fs/cgroup/memory/memory.limit_in_bytes",
          "runtime.platform.cgroup_v1_memory_limit",
        ),
        (
          "/sys/fs/cgroup/cpu.stat",
          "runtime.platform.cgroup_cpu_stat",
        ),
        ("/sys/fs/cgroup/cpu.max", "runtime.platform.cgroup_cpu_max"),
        (
          "/sys/fs/cgroup/cpuset.cpus.effective",
          "runtime.platform.cgroup_cpuset",
        ),
      ] {
        self.add_optional_intrinsic_file(
          Path::new(path),
          FilesystemAccessPurpose::PlatformObservation,
          source,
        )?;
      }
    }

    for path in [
      "/proc/sys/net/core/somaxconn",
      "/proc/sys/net/ipv4/ip_local_port_range",
      "/proc/sys/net/core/rmem_max",
      "/proc/sys/net/core/wmem_max",
      "/proc/sys/net/netfilter/nf_conntrack_max",
      "/proc/cpuinfo",
    ] {
      self.add_optional_intrinsic_file(
        Path::new(path),
        FilesystemAccessPurpose::RuntimeDiagnostics,
        format!(
          "runtime.diagnostics.platform.{}",
          path.trim_start_matches('/').replace('/', ".")
        ),
      )?;
    }

    if config.shared_state.enabled {
      for (index, backend) in config.shared_state.backends.iter().enumerate() {
        if backend.kind != SharedStateBackendKind::Redis
          || backend.redis_tls.trust_store != RedisTrustStore::Native
        {
          continue;
        }
        let source = format!("shared_state.backends[{index}].redis_tls.trust_store");
        for path in crate::tls::native_root_access_paths() {
          if path.is_dir() {
            self.add(
              &path,
              ManifestEntrySpec {
                access: &[
                  FilesystemAccessMode::ReadDirectory,
                  FilesystemAccessMode::ReadFile,
                ],
                purpose: FilesystemAccessPurpose::TlsTrustStore,
                source_config_path: Some(source.clone()),
                expected_type: FilesystemPathType::Directory,
                scope: FilesystemPathScope::Descendants,
                requires_parent_write: false,
                optional: true,
              },
            )?;
          } else {
            self.add_optional_intrinsic_file(
              &path,
              FilesystemAccessPurpose::TlsTrustStore,
              source.clone(),
            )?;
          }
        }
      }
    }
    Ok(())
  }
}

fn landlock_rights_for_entry(entry: &FilesystemAccessEntry) -> BTreeSet<LandlockFilesystemRight> {
  let mut rights = BTreeSet::new();
  for mode in &entry.access {
    match mode {
      FilesystemAccessMode::ReadFile => {
        rights.insert(LandlockFilesystemRight::ReadFile);
      }
      FilesystemAccessMode::ReadDirectory => {
        rights.insert(LandlockFilesystemRight::ReadDir);
      }
      FilesystemAccessMode::WriteFile => {
        rights.insert(LandlockFilesystemRight::WriteFile);
        rights.insert(LandlockFilesystemRight::Truncate);
      }
      FilesystemAccessMode::CreateFile => {
        rights.insert(LandlockFilesystemRight::MakeReg);
      }
      FilesystemAccessMode::RemoveFile => {
        rights.insert(LandlockFilesystemRight::RemoveFile);
      }
      FilesystemAccessMode::Rename => {
        rights.insert(LandlockFilesystemRight::Refer);
      }
      FilesystemAccessMode::CreateDirectory => {
        rights.insert(LandlockFilesystemRight::MakeDir);
      }
      FilesystemAccessMode::RemoveDirectory => {
        rights.insert(LandlockFilesystemRight::RemoveDir);
      }
      FilesystemAccessMode::BindUnixSocket => {
        rights.insert(LandlockFilesystemRight::MakeSock);
      }
      FilesystemAccessMode::ConnectUnixSocket => {}
    }
  }
  rights
}

fn entry_order(left: &FilesystemAccessEntry, right: &FilesystemAccessEntry) -> std::cmp::Ordering {
  (
    left.digest_identity_path.as_os_str().as_bytes(),
    &left.access,
    left.purpose,
    left.source_config_path.as_deref(),
    left.expected_type,
    left.scope,
    left.requires_parent_write,
    left.optional,
    left.path.as_os_str().as_bytes(),
  )
    .cmp(&(
      right.digest_identity_path.as_os_str().as_bytes(),
      &right.access,
      right.purpose,
      right.source_config_path.as_deref(),
      right.expected_type,
      right.scope,
      right.requires_parent_write,
      right.optional,
      right.path.as_os_str().as_bytes(),
    ))
}

fn normalize_path(path: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
  if path.as_os_str().is_empty() {
    bail!("filesystem manifest path must not be empty");
  }
  let absolute = if path.is_absolute() {
    path.to_path_buf()
  } else {
    cwd.join(path)
  };
  // `/proc/self` is a kernel-provided process-relative identity. Canonicalizing
  // it would bake the current PID into the otherwise deterministic manifest.
  if absolute.starts_with("/proc/self") {
    return Ok(absolute);
  }
  if let Ok(canonical) = absolute.canonicalize() {
    return Ok(canonical);
  }

  let mut suffix = Vec::new();
  let mut current = absolute.as_path();
  loop {
    match current.symlink_metadata() {
      Ok(_) => {
        let mut normalized = current.canonicalize().with_context(|| {
          format!(
            "failed to canonicalize existing filesystem manifest ancestor {}",
            current.display()
          )
        })?;
        for component in suffix.iter().rev() {
          normalized.push(component);
        }
        return Ok(normalized);
      }
      Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
        let component = current.file_name().ok_or_else(|| {
          anyhow!(
            "filesystem manifest path {} has no existing ancestor",
            absolute.display()
          )
        })?;
        suffix.push(component.to_os_string());
        current = current.parent().ok_or_else(|| {
          anyhow!(
            "filesystem manifest path {} has no parent",
            absolute.display()
          )
        })?;
      }
      Err(error) => {
        return Err(error).with_context(|| {
          format!(
            "failed to inspect filesystem manifest path {}",
            current.display()
          )
        });
      }
    }
  }
}

fn lexical_absolute_path(path: &Path, cwd: &Path) -> anyhow::Result<PathBuf> {
  use std::path::Component;

  let absolute = if path.is_absolute() {
    path.to_path_buf()
  } else {
    cwd.join(path)
  };
  let mut normalized = PathBuf::new();
  for component in absolute.components() {
    match component {
      Component::RootDir => normalized.push(Path::new("/")),
      Component::CurDir => {}
      Component::Normal(component) => normalized.push(component),
      Component::ParentDir => {
        bail!(
          "filesystem rotation path {} must not contain parent traversal",
          path.display()
        )
      }
      Component::Prefix(_) => bail!("filesystem rotation paths must use Unix path syntax"),
    }
  }
  if !normalized.is_absolute() {
    bail!("filesystem rotation path must resolve to an absolute path");
  }
  Ok(normalized)
}

fn manifest_digest(entries: &[FilesystemAccessEntry]) -> String {
  let mut hasher = Sha256::new();
  digest_part(&mut hasher, b"oxibelt-filesystem-access-manifest-v3");
  digest_part(
    &mut hasher,
    &FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION.to_be_bytes(),
  );
  for entry in entries {
    digest_part(
      &mut hasher,
      entry.digest_identity_path.as_os_str().as_bytes(),
    );
    for mode in &entry.access {
      digest_part(&mut hasher, format!("{mode:?}").as_bytes());
    }
    digest_part(&mut hasher, format!("{:?}", entry.purpose).as_bytes());
    digest_part(
      &mut hasher,
      entry.source_config_path.as_deref().unwrap_or("").as_bytes(),
    );
    digest_part(&mut hasher, format!("{:?}", entry.expected_type).as_bytes());
    digest_part(&mut hasher, format!("{:?}", entry.scope).as_bytes());
    digest_part(&mut hasher, &[u8::from(entry.requires_parent_write)]);
    digest_part(&mut hasher, &[u8::from(entry.optional)]);
  }
  format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn digest_part(hasher: &mut Sha256, bytes: &[u8]) {
  hasher.update((bytes.len() as u64).to_be_bytes());
  hasher.update(bytes);
}

fn hex_lower(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    encoded.push(HEX[(byte >> 4) as usize] as char);
    encoded.push(HEX[(byte & 0x0f) as usize] as char);
  }
  encoded
}

fn path_ids(entries: &[FilesystemAccessEntry]) -> BTreeMap<PathBuf, String> {
  entries
    .iter()
    .map(|entry| entry.path.clone())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .enumerate()
    .map(|(index, path)| (path, format!("path-{:04}", index + 1)))
    .collect()
}

fn entry_view(
  entry: &FilesystemAccessEntry,
  path_ids: &BTreeMap<PathBuf, String>,
  show_paths: bool,
) -> FilesystemAccessEntryView {
  FilesystemAccessEntryView {
    path_id: path_ids
      .get(&entry.path)
      .cloned()
      .unwrap_or_else(|| "path-unknown".to_string()),
    path: show_paths.then(|| display_path(&entry.path)),
    access: entry.access.clone(),
    purpose: entry.purpose,
    source_config_path: entry.source_config_path.clone(),
    expected_type: entry.expected_type,
    scope: entry.scope,
    requires_parent_write: entry.requires_parent_write,
    optional: entry.optional,
  }
}

fn display_path(path: &Path) -> String {
  match path.to_str() {
    Some(path) => path.to_string(),
    None => format!("unix-bytes:{}", hex_lower(path.as_os_str().as_bytes())),
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MountInfo {
  mount_point: PathBuf,
  read_only: bool,
}

fn read_current_mountinfo() -> Option<String> {
  let file = File::open("/proc/self/mountinfo").ok()?;
  let mut input = String::new();
  let mut bounded = file.take(MAX_MOUNTINFO_BYTES + 1);
  bounded.read_to_string(&mut input).ok()?;
  (input.len() as u64 <= MAX_MOUNTINFO_BYTES).then_some(input)
}

fn parse_mountinfo(input: &str) -> anyhow::Result<Vec<MountInfo>> {
  if input.len() as u64 > MAX_MOUNTINFO_BYTES {
    bail!("mountinfo exceeds {MAX_MOUNTINFO_BYTES} bytes");
  }
  let mut mounts = Vec::new();
  for (index, line) in input.lines().enumerate() {
    if index >= MAX_MOUNTINFO_ENTRIES {
      bail!("mountinfo exceeds {MAX_MOUNTINFO_ENTRIES} entries");
    }
    let separator = line
      .find(" - ")
      .ok_or_else(|| anyhow!("mountinfo entry {} is missing separator", index + 1))?;
    let fields = line[..separator]
      .split_ascii_whitespace()
      .collect::<Vec<_>>();
    if fields.len() < 6 {
      bail!("mountinfo entry {} has too few fields", index + 1);
    }
    let mount_point = decode_mountinfo_path(fields[4])?;
    let read_only = fields[5].split(',').any(|option| option == "ro");
    mounts.push(MountInfo {
      mount_point,
      read_only,
    });
  }
  mounts.sort_by(|left, right| {
    right
      .mount_point
      .as_os_str()
      .as_bytes()
      .len()
      .cmp(&left.mount_point.as_os_str().as_bytes().len())
      .then_with(|| left.mount_point.cmp(&right.mount_point))
  });
  Ok(mounts)
}

fn decode_mountinfo_path(raw: &str) -> anyhow::Result<PathBuf> {
  let bytes = raw.as_bytes();
  let mut decoded = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'\\' {
      if index + 3 >= bytes.len() {
        bail!("mountinfo path contains a truncated escape");
      }
      let escaped = &bytes[index + 1..index + 4];
      let value = match escaped {
        b"040" => b' ',
        b"011" => b'\t',
        b"012" => b'\n',
        b"134" => b'\\',
        _ => bail!("mountinfo path contains an unsupported escape"),
      };
      decoded.push(value);
      index += 4;
    } else {
      decoded.push(bytes[index]);
      index += 1;
    }
  }
  Ok(PathBuf::from(std::ffi::OsString::from_vec(decoded)))
}

fn find_mount<'a>(path: &Path, mounts: &'a [MountInfo]) -> Option<&'a MountInfo> {
  mounts
    .iter()
    .find(|mount| path == mount.mount_point || path.starts_with(&mount.mount_point))
}

fn check_entry(
  entry: &FilesystemAccessEntry,
  path_ids: &BTreeMap<PathBuf, String>,
  show_paths: bool,
  mounts: Option<&Vec<MountInfo>>,
  findings: &mut FindingCollector,
) {
  let path_id = path_ids.get(&entry.path).cloned();
  let visible_path = show_paths.then(|| display_path(&entry.path));
  let finding = |severity, code, detail| FilesystemAccessFinding {
    severity,
    code,
    path_id: path_id.clone(),
    path: visible_path.clone(),
    source_config_path: entry.source_config_path.clone(),
    detail,
  };

  let metadata = match fs::metadata(&entry.path) {
    Ok(metadata) => Some(metadata),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      if !entry.optional {
        findings.push(finding(
          FilesystemAccessFindingSeverity::Error,
          if entry.requires_parent_write {
            FilesystemAccessFindingCode::ParentScopeUnrepresentable
          } else {
            FilesystemAccessFindingCode::PathMissing
          },
          if entry.requires_parent_write {
            "required write root must be pre-created before manifest-mode confinement".to_string()
          } else {
            "required path does not exist".to_string()
          },
        ));
      }
      None
    }
    Err(error) => {
      findings.push(finding(
        FilesystemAccessFindingSeverity::Error,
        FilesystemAccessFindingCode::ReadDenied,
        format!("path metadata is unavailable: {error}"),
      ));
      None
    }
  };

  if let Some(metadata) = metadata.as_ref() {
    let matches_type = match entry.expected_type {
      FilesystemPathType::RegularFile => metadata.is_file(),
      FilesystemPathType::Directory => metadata.is_dir(),
      FilesystemPathType::UnixSocket => metadata.file_type().is_socket(),
    };
    if !matches_type {
      findings.push(finding(
        FilesystemAccessFindingSeverity::Error,
        FilesystemAccessFindingCode::PathTypeMismatch,
        format!("expected {:?}", entry.expected_type),
      ));
    }
    if matches_type && entry.access.iter().any(|mode| mode.requires_read()) {
      let readable = match entry.expected_type {
        FilesystemPathType::RegularFile => File::open(&entry.path).is_ok(),
        FilesystemPathType::Directory => fs::read_dir(&entry.path).is_ok(),
        FilesystemPathType::UnixSocket => true,
      };
      if !readable {
        findings.push(finding(
          FilesystemAccessFindingSeverity::Error,
          FilesystemAccessFindingCode::ReadDenied,
          "current process cannot open the path for the required read operation".to_string(),
        ));
      }
    }
    if entry.requires_write() && !current_process_can_write(&entry.path, metadata) {
      findings.push(finding(
        FilesystemAccessFindingSeverity::Error,
        FilesystemAccessFindingCode::WriteDenied,
        "current process identity lacks a writable mode bit on the path".to_string(),
      ));
    }
  }

  if entry.requires_parent_write {
    let parent = entry.path.parent();
    match parent.and_then(|path| fs::metadata(path).ok()) {
      None => findings.push(finding(
        FilesystemAccessFindingSeverity::Error,
        FilesystemAccessFindingCode::ParentMissing,
        "required parent directory does not exist or cannot be inspected".to_string(),
      )),
      Some(metadata) if !metadata.is_dir() => findings.push(finding(
        FilesystemAccessFindingSeverity::Error,
        FilesystemAccessFindingCode::ParentNotDirectory,
        "required parent is not a directory".to_string(),
      )),
      Some(metadata) if !parent.is_some_and(|path| current_process_can_write(path, &metadata)) => {
        findings.push(finding(
          FilesystemAccessFindingSeverity::Error,
          FilesystemAccessFindingCode::ParentWriteDenied,
          "current process cannot create entries in the required parent".to_string(),
        ))
      }
      Some(_) => {}
    }
  }

  if entry.requires_write()
    && let Some(mount) = mounts.and_then(|mounts| find_mount(&entry.path, mounts))
    && mount.read_only
  {
    findings.push(finding(
      FilesystemAccessFindingSeverity::Error,
      FilesystemAccessFindingCode::ReadOnlyMount,
      "required write access is on a read-only mount".to_string(),
    ));
  }
}

fn current_process_can_write(path: &Path, metadata: &fs::Metadata) -> bool {
  let mut access = nix::unistd::AccessFlags::W_OK;
  if metadata.is_dir() {
    access |= nix::unistd::AccessFlags::X_OK;
  }
  nix::unistd::eaccess(path, access).is_ok()
}

fn find_conflicts_and_redundancy(
  entries: &[FilesystemAccessEntry],
  path_ids: &BTreeMap<PathBuf, String>,
  show_paths: bool,
  findings: &mut FindingCollector,
) {
  let mut entries_by_path = BTreeMap::<&Path, Vec<&FilesystemAccessEntry>>::new();
  for entry in entries {
    entries_by_path.entry(&entry.path).or_default().push(entry);
  }

  for (path, same_path_entries) in &entries_by_path {
    let expected_types = same_path_entries
      .iter()
      .map(|entry| entry.expected_type)
      .collect::<BTreeSet<_>>();
    if expected_types.len() > 1 {
      let entry = same_path_entries[0];
      findings.push(FilesystemAccessFinding {
        severity: FilesystemAccessFindingSeverity::Error,
        code: FilesystemAccessFindingCode::ConflictingExpectation,
        path_id: path_ids.get(*path).cloned(),
        path: show_paths.then(|| display_path(path)),
        source_config_path: entry.source_config_path.clone(),
        detail: "the same normalized path has conflicting type expectations".to_string(),
      });
    }
  }

  for entry in entries {
    let mut ancestor = entry.path.parent();
    while let Some(path) = ancestor {
      if let Some(broader_entries) = entries_by_path.get(path)
        && broader_entries.iter().any(|broader| broader.covers(entry))
      {
        findings.push(FilesystemAccessFinding {
          severity: FilesystemAccessFindingSeverity::Warning,
          code: FilesystemAccessFindingCode::RedundantBroaderAccess,
          path_id: path_ids.get(&entry.path).cloned(),
          path: show_paths.then(|| display_path(&entry.path)),
          source_config_path: entry.source_config_path.clone(),
          detail: "a broader manifest entry already covers this access".to_string(),
        });
        break;
      }
      ancestor = path.parent();
    }
  }
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::os::unix::fs::symlink;

  use super::*;

  fn entry(path: &Path, access: &[FilesystemAccessMode]) -> FilesystemAccessEntry {
    FilesystemAccessEntry {
      path: path.to_path_buf(),
      digest_identity_path: path.to_path_buf(),
      access: access.to_vec(),
      purpose: FilesystemAccessPurpose::RuntimeData,
      source_config_path: Some("test.path".to_string()),
      expected_type: FilesystemPathType::RegularFile,
      scope: FilesystemPathScope::Exact,
      requires_parent_write: false,
      optional: false,
    }
  }

  #[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
  struct ManifestSnapshotEntry {
    source: String,
    purpose: FilesystemAccessPurpose,
    access: Vec<FilesystemAccessMode>,
    expected_type: FilesystemPathType,
    scope: FilesystemPathScope,
    requires_parent_write: bool,
  }

  fn resolved_config_fixture() -> (tempfile::TempDir, Config) {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join("config");
    let cert_dir = temp.path().join("cert");
    let oxirule_dir = temp.path().join("oxirule");
    fs::create_dir_all(&config_dir).expect("create config directory");
    fs::create_dir_all(&cert_dir).expect("create certificate directory");
    fs::create_dir_all(&oxirule_dir).expect("create OxiRule directory");
    fs::write(cert_dir.join("fullchain.pem"), b"test certificate").expect("write certificate");
    fs::write(cert_dir.join("privkey.pem"), b"test private key").expect("write private key");
    let config_path = config_dir.join("oxibelt.toml");
    fs::write(
      &config_path,
      r#"
[runtime]
linux_only = true
read_only_rootfs_compatible = true
memory_only_state = true
unprivileged_mode = true
worker_threads = 1
main_runtime = "tokio_hyper"

[runtime.accept]
workers = 1
reuse_port = false
backlog = 128
accept_error_backoff_ms = 10

[listeners]
https_bind = "127.0.0.1:18443"
http_bind = "127.0.0.1:18080"
http_mode = "proxy"
http1 = true
http2 = false
http3 = false

[tls]
cert_chain = "fullchain.pem"
private_key = "privkey.pem"
min_version = "tls1.3"
max_version = "tls1.3"

[tls.ocsp]
mode = "disabled"

[proxy]
trusted_ca_certs = []

[compression]
enabled = false

[waf]
enabled = false
mode = "enforcing"
fail_policy = "closed"

[[upstreams]]
name = "unused"
origin = "http://127.0.0.1:1"
max_http_version = "h1"

[[routes]]
name = "fixture"
hosts = ["fixture.oxibelt.test"]
path_prefix = "/"

[routes.actions.redirect]
status = 308
location_template = "/fixture"
"#,
    )
    .expect("write config");
    let config = Config::load(&config_path).expect("load resolved config fixture");
    (temp, config)
  }

  fn snapshot_sources(
    manifest: &FilesystemAccessManifest,
    sources: &[&str],
  ) -> Vec<ManifestSnapshotEntry> {
    let mut snapshot = manifest
      .entries()
      .iter()
      .filter_map(|entry| {
        let source = entry.source_config_path()?;
        sources.contains(&source).then(|| ManifestSnapshotEntry {
          source: source.to_string(),
          purpose: entry.purpose(),
          access: entry.access().to_vec(),
          expected_type: entry.expected_type(),
          scope: entry.scope(),
          requires_parent_write: entry.requires_parent_write(),
        })
      })
      .collect::<Vec<_>>();
    snapshot.sort();
    snapshot
  }

  fn rotated_read_snapshot(
    source: &str,
    purpose: FilesystemAccessPurpose,
  ) -> Vec<ManifestSnapshotEntry> {
    vec![
      ManifestSnapshotEntry {
        source: source.to_string(),
        purpose,
        access: vec![FilesystemAccessMode::ReadFile],
        expected_type: FilesystemPathType::RegularFile,
        scope: FilesystemPathScope::Exact,
        requires_parent_write: false,
      },
      ManifestSnapshotEntry {
        source: source.to_string(),
        purpose,
        access: vec![
          FilesystemAccessMode::ReadFile,
          FilesystemAccessMode::ReadDirectory,
        ],
        expected_type: FilesystemPathType::Directory,
        scope: FilesystemPathScope::Descendants,
        requires_parent_write: false,
      },
    ]
  }

  fn writable_directory_snapshot(
    source: &str,
    purpose: FilesystemAccessPurpose,
    requires_parent_write: bool,
  ) -> ManifestSnapshotEntry {
    ManifestSnapshotEntry {
      source: source.to_string(),
      purpose,
      access: vec![
        FilesystemAccessMode::ReadFile,
        FilesystemAccessMode::ReadDirectory,
        FilesystemAccessMode::WriteFile,
        FilesystemAccessMode::CreateFile,
        FilesystemAccessMode::RemoveFile,
        FilesystemAccessMode::Rename,
        FilesystemAccessMode::CreateDirectory,
        FilesystemAccessMode::RemoveDirectory,
      ],
      expected_type: FilesystemPathType::Directory,
      scope: FilesystemPathScope::Descendants,
      requires_parent_write,
    }
  }

  #[test]
  fn resolved_manifest_snapshots_cover_minimal_tls_waf_cache_audit_and_combined_configs() {
    let (temp, base) = resolved_config_fixture();
    let minimal_sources = ["config.entrypoint", "tls.cert_chain", "tls.private_key"];
    let minimal = FilesystemAccessManifest::from_config(&base).expect("minimal manifest");
    let mut expected_minimal =
      rotated_read_snapshot("config.entrypoint", FilesystemAccessPurpose::Configuration);
    expected_minimal.extend(rotated_read_snapshot(
      "tls.cert_chain",
      FilesystemAccessPurpose::TlsCertificate,
    ));
    expected_minimal.extend(rotated_read_snapshot(
      "tls.private_key",
      FilesystemAccessPurpose::TlsPrivateKey,
    ));
    expected_minimal.sort();
    assert_eq!(
      snapshot_sources(&minimal, &minimal_sources),
      expected_minimal
    );
    assert!(
      snapshot_sources(
        &minimal,
        &[
          "tls.ocsp.response_file",
          "waf.loaded_rule_paths[0]",
          "cache.disk_dir",
          "admin.audit.spool.directory",
        ],
      )
      .is_empty(),
      "disabled optional features must not add manifest authority"
    );

    let ocsp_file = temp.path().join("cert/ocsp.der");
    fs::write(&ocsp_file, b"test OCSP response").expect("write OCSP response");
    let mut tls = base.clone();
    tls.tls.ocsp.response_file = Some(ocsp_file.clone());
    let tls_manifest = FilesystemAccessManifest::from_config(&tls).expect("TLS manifest");
    assert_eq!(
      snapshot_sources(&tls_manifest, &["tls.ocsp.response_file"]),
      rotated_read_snapshot(
        "tls.ocsp.response_file",
        FilesystemAccessPurpose::TlsStatusData,
      )
    );

    let rule_file = temp.path().join("oxirule/fixture.oxirule");
    fs::write(&rule_file, b"rule fixture {}").expect("write OxiRule fixture");
    let mut waf = base.clone();
    waf.waf.enabled = true;
    waf.source_paths.oxirule_files = vec![rule_file.clone()];
    let waf_manifest = FilesystemAccessManifest::from_config(&waf).expect("WAF manifest");
    assert_eq!(
      snapshot_sources(&waf_manifest, &["waf.loaded_rule_paths[0]"]),
      rotated_read_snapshot(
        "waf.loaded_rule_paths[0]",
        FilesystemAccessPurpose::WafRules,
      )
    );

    let cache_dir = temp.path().join("cache");
    fs::create_dir(&cache_dir).expect("create cache directory");
    let mut cache = base.clone();
    cache.cache.enabled = true;
    cache.cache.store = CacheStore::Disk;
    cache.cache.disk_dir = Some(cache_dir.clone());
    let cache_manifest = FilesystemAccessManifest::from_config(&cache).expect("cache manifest");
    assert_eq!(
      snapshot_sources(&cache_manifest, &["cache.disk_dir"]),
      vec![writable_directory_snapshot(
        "cache.disk_dir",
        FilesystemAccessPurpose::Cache,
        false,
      )]
    );

    let audit_dir = temp.path().join("audit");
    fs::create_dir(&audit_dir).expect("create audit directory");
    let mut audit = base.clone();
    audit.admin.enabled = true;
    audit.admin.audit.enabled = true;
    audit.admin.audit.spool.enabled = true;
    audit.admin.audit.spool.directory = Some(audit_dir.clone());
    let audit_manifest = FilesystemAccessManifest::from_config(&audit).expect("audit manifest");
    assert_eq!(
      snapshot_sources(&audit_manifest, &["admin.audit.spool.directory"]),
      vec![writable_directory_snapshot(
        "admin.audit.spool.directory",
        FilesystemAccessPurpose::AuditSpool,
        true,
      )]
    );

    let mut combined = audit;
    combined.tls.ocsp.response_file = Some(ocsp_file);
    combined.waf.enabled = true;
    combined.source_paths.oxirule_files = vec![rule_file];
    combined.cache.enabled = true;
    combined.cache.store = CacheStore::Disk;
    combined.cache.disk_dir = Some(cache_dir);
    let combined_manifest =
      FilesystemAccessManifest::from_config(&combined).expect("combined manifest");
    let repeated_manifest =
      FilesystemAccessManifest::from_config(&combined).expect("repeat combined manifest");
    assert_eq!(combined_manifest, repeated_manifest);
    assert_eq!(combined_manifest.digest(), repeated_manifest.digest());

    let combined_sources = [
      "config.entrypoint",
      "tls.cert_chain",
      "tls.private_key",
      "tls.ocsp.response_file",
      "waf.loaded_rule_paths[0]",
      "cache.disk_dir",
      "admin.audit.spool.directory",
    ];
    let mut expected_combined = expected_minimal;
    expected_combined.extend(rotated_read_snapshot(
      "tls.ocsp.response_file",
      FilesystemAccessPurpose::TlsStatusData,
    ));
    expected_combined.extend(rotated_read_snapshot(
      "waf.loaded_rule_paths[0]",
      FilesystemAccessPurpose::WafRules,
    ));
    expected_combined.push(writable_directory_snapshot(
      "cache.disk_dir",
      FilesystemAccessPurpose::Cache,
      false,
    ));
    expected_combined.push(writable_directory_snapshot(
      "admin.audit.spool.directory",
      FilesystemAccessPurpose::AuditSpool,
      true,
    ));
    expected_combined.sort();
    assert_eq!(
      snapshot_sources(&combined_manifest, &combined_sources),
      expected_combined
    );
  }

  #[test]
  fn normalization_resolves_symlinks_and_missing_suffixes_without_writing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let actual = temp.path().join("actual");
    fs::create_dir(&actual).expect("create actual directory");
    symlink(&actual, temp.path().join("link")).expect("create symlink");
    let missing = temp.path().join("link/new/manifest.json");

    let normalized = normalize_path(&missing, temp.path()).expect("normalize path");

    assert_eq!(normalized, actual.join("new/manifest.json"));
    assert!(!actual.join("new").exists());
  }

  #[test]
  fn ordinary_symlinks_keep_canonical_enforcement_and_digest_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let actual = temp.path().join("actual.pem");
    let visible = temp.path().join("visible.pem");
    fs::write(&actual, b"fixture").expect("write target");
    symlink("actual.pem", &visible).expect("create ordinary symlink");
    let mut builder = ManifestBuilder {
      entries: Vec::new(),
      precise_read_paths: BTreeSet::new(),
      cwd: temp.path().to_path_buf(),
    };
    builder
      .add_read_file(
        &visible,
        FilesystemAccessPurpose::TlsCertificate,
        "tls.cert_chain",
        false,
      )
      .expect("add ordinary symlink");
    let manifest = builder.finish().expect("finish manifest");
    let entry = manifest.entries.first().expect("manifest entry");

    assert_eq!(entry.path, actual);
    assert_eq!(entry.digest_identity_path, actual);
  }

  #[test]
  fn manifest_view_reports_v3_atomic_writer_normalization() {
    let entries = vec![entry(
      Path::new("/etc/oxibelt/config/oxibelt.toml"),
      &[FilesystemAccessMode::ReadFile],
    )];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };

    assert_eq!(manifest.schema_version(), 3);
    assert_eq!(
      manifest.view(false).normalization,
      "canonical_enforcement_with_verified_kubernetes_atomic_writer_digest_identity_v3"
    );
  }

  #[test]
  fn relative_rotation_path_uses_the_normalized_parent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut builder = ManifestBuilder {
      entries: Vec::new(),
      precise_read_paths: BTreeSet::new(),
      cwd: temp.path().to_path_buf(),
    };
    builder
      .add_read_file(
        Path::new("cert.pem"),
        FilesystemAccessPurpose::TlsCertificate,
        "tls.cert_chain",
        true,
      )
      .expect("relative rotation path should normalize before deriving its parent");
    assert!(
      builder
        .entries
        .iter()
        .any(|entry| entry.path == temp.path() && entry.scope == FilesystemPathScope::Descendants)
    );
  }

  #[test]
  fn kubernetes_atomic_writer_rotations_keep_digest_identity_but_change_enforcement_targets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let secret = temp.path().join("secret");
    let first_name = "..2026_08_05_12_34_56.1234567890";
    let second_name = "..2026_08_05_12_35_56.1234567890";
    let first = secret.join(first_name);
    let second = secret.join(second_name);
    fs::create_dir_all(&first).expect("create first secret version");
    fs::create_dir_all(&second).expect("create second secret version");
    fs::write(first.join("tls.crt"), b"first").expect("write first certificate");
    fs::write(second.join("tls.crt"), b"second").expect("write second certificate");
    symlink(first_name, secret.join("..data")).expect("create data link");
    symlink("..data/tls.crt", secret.join("tls.crt")).expect("create visible link");
    let logical_certificate = secret.join("tls.crt");

    let build = || {
      let loaded_certificate = logical_certificate
        .canonicalize()
        .expect("resolve selected projected certificate");
      let mut builder = ManifestBuilder {
        entries: Vec::new(),
        precise_read_paths: BTreeSet::new(),
        cwd: temp.path().to_path_buf(),
      };
      builder
        .add_read_file(
          &loaded_certificate,
          FilesystemAccessPurpose::TlsCertificate,
          "tls.cert_chain",
          true,
        )
        .expect("build rotation manifest");
      builder.finish().expect("finish rotation manifest")
    };
    let installed = build();
    let installed_exact_path = installed
      .entries
      .iter()
      .find(|entry| entry.scope == FilesystemPathScope::Exact)
      .expect("installed exact file entry")
      .path
      .clone();
    assert_eq!(installed_exact_path, first.join("tls.crt"));
    assert!(
      installed
        .entries
        .iter()
        .any(|entry| entry.path == first && entry.scope == FilesystemPathScope::Descendants)
    );

    symlink(second_name, secret.join("..data.next")).expect("create replacement data link");
    fs::rename(secret.join("..data.next"), secret.join("..data"))
      .expect("rotate data link atomically");
    let rotated = build();
    let rotated_exact_path = rotated
      .entries
      .iter()
      .find(|entry| entry.scope == FilesystemPathScope::Exact)
      .expect("rotated exact file entry")
      .path
      .clone();
    assert_eq!(rotated_exact_path, second.join("tls.crt"));
    assert_ne!(installed_exact_path, rotated_exact_path);
    assert_eq!(installed.digest(), rotated.digest());
    assert_eq!(
      installed
        .entries
        .iter()
        .find(|entry| entry.scope == FilesystemPathScope::Exact)
        .expect("installed exact entry")
        .digest_identity_path,
      logical_certificate
    );
    assert_eq!(
      installed
        .entries
        .iter()
        .find(|entry| entry.scope == FilesystemPathScope::Descendants)
        .expect("installed rotation parent")
        .digest_identity_path,
      secret
    );
    assert!(
      !rotated.access_is_subset_of(&installed),
      "canonical enforcement must still detect the newly selected generation"
    );
    assert_ne!(
      installed.landlock_projection().read_paths,
      rotated.landlock_projection().read_paths,
      "Landlock must retain the canonical target selected for each generation"
    );
  }

  #[test]
  fn loaded_config_tls_and_quic_projection_digest_survives_atomic_writer_rotation() {
    let (temp, _) = resolved_config_fixture();
    let config_root = temp.path().join("config");
    let cert_root = temp.path().join("cert");
    let config_entry = config_root.join("oxibelt.toml");
    let mut config_contents = fs::read_to_string(&config_entry).expect("read fixture config");
    config_contents.push_str(
      r#"
[quic]
host_key_file = "quic-host-key.b64"
"#,
    );
    fs::remove_file(&config_entry).expect("remove unprojected config");
    fs::remove_file(cert_root.join("fullchain.pem")).expect("remove unprojected certificate");
    fs::remove_file(cert_root.join("privkey.pem")).expect("remove unprojected private key");

    let first_name = "..2026_08_05_12_34_56.1234567890";
    let second_name = "..2026_08_05_12_35_56.1234567890";
    for generation in [first_name, second_name] {
      let config_generation = config_root.join(generation);
      let cert_generation = cert_root.join(generation);
      fs::create_dir(&config_generation).expect("create config generation");
      fs::create_dir(&cert_generation).expect("create certificate generation");
      fs::write(config_generation.join("oxibelt.toml"), &config_contents)
        .expect("write projected config");
      fs::write(cert_generation.join("fullchain.pem"), b"test certificate")
        .expect("write projected certificate");
      fs::write(cert_generation.join("privkey.pem"), b"test private key")
        .expect("write projected private key");
      fs::write(
        cert_generation.join("quic-host-key.b64"),
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
      )
      .expect("write projected QUIC host key");
    }
    symlink(first_name, config_root.join("..data")).expect("create config data link");
    symlink("..data/oxibelt.toml", &config_entry).expect("create visible config link");
    symlink(first_name, cert_root.join("..data")).expect("create certificate data link");
    for file in ["fullchain.pem", "privkey.pem", "quic-host-key.b64"] {
      symlink(Path::new("..data").join(file), cert_root.join(file))
        .expect("create visible certificate link");
    }

    let build = || {
      let config = Config::load(&config_entry).expect("load projected config");
      assert!(
        config
          .source_paths
          .config_files
          .iter()
          .any(|path| path.starts_with(&config_root) && path != &config_entry),
        "the loader must expose a canonicalized config source path"
      );
      assert_ne!(config.tls.cert_chain, cert_root.join("fullchain.pem"));
      let logical_host_key = cert_root.join("quic-host-key.b64");
      assert_ne!(
        config.quic.host_key_file.as_deref(),
        Some(logical_host_key.as_path())
      );
      FilesystemAccessManifest::from_config(&config).expect("build projected manifest")
    };
    let installed = build();
    let exact_paths = |manifest: &FilesystemAccessManifest| {
      [
        "config.entrypoint",
        "tls.cert_chain",
        "tls.private_key",
        "quic.host_key_file",
      ]
      .into_iter()
      .map(|source| {
        manifest
          .entries
          .iter()
          .find(|entry| {
            entry.scope == FilesystemPathScope::Exact
              && entry.source_config_path.as_deref() == Some(source)
          })
          .unwrap_or_else(|| panic!("missing exact entry for {source}"))
          .path
          .clone()
      })
      .collect::<Vec<_>>()
    };
    let installed_paths = exact_paths(&installed);
    assert!(installed_paths[0].starts_with(config_root.join(first_name)));
    assert!(
      installed_paths[1..]
        .iter()
        .all(|path| path.starts_with(cert_root.join(first_name)))
    );

    symlink(second_name, config_root.join("..data.next"))
      .expect("create replacement config data link");
    fs::rename(config_root.join("..data.next"), config_root.join("..data"))
      .expect("rotate config data link");
    symlink(second_name, cert_root.join("..data.next"))
      .expect("create replacement certificate data link");
    fs::rename(cert_root.join("..data.next"), cert_root.join("..data"))
      .expect("rotate certificate data link");

    let rotated = build();
    let rotated_paths = exact_paths(&rotated);
    assert_eq!(installed.digest(), rotated.digest());
    assert_ne!(installed_paths, rotated_paths);
    assert!(rotated_paths[0].starts_with(config_root.join(second_name)));
    assert!(
      rotated_paths[1..]
        .iter()
        .all(|path| path.starts_with(cert_root.join(second_name)))
    );
  }

  #[test]
  fn rotation_paths_reject_parent_traversal() {
    let error = lexical_absolute_path(Path::new("certs/../tls.crt"), Path::new("/etc/oxibelt"))
      .expect_err("rotation anchors must not contain parent traversal");
    assert!(error.to_string().contains("parent traversal"));
  }

  #[test]
  fn empty_paths_are_rejected() {
    let error = normalize_path(Path::new(""), Path::new("/")).expect_err("empty path");
    assert!(error.to_string().contains("must not be empty"));
  }

  #[test]
  fn stable_digest_is_independent_of_insertion_order() {
    let mut left = vec![
      entry(Path::new("/tmp/b"), &[FilesystemAccessMode::ReadFile]),
      entry(Path::new("/tmp/a"), &[FilesystemAccessMode::ReadFile]),
    ];
    let mut right = left.iter().cloned().rev().collect::<Vec<_>>();
    left.sort_by(entry_order);
    right.sort_by(entry_order);
    assert_eq!(manifest_digest(&left), manifest_digest(&right));
  }

  #[test]
  fn redacted_view_hides_paths_but_keeps_stable_ids() {
    let entries = vec![entry(
      Path::new("/sensitive/private.pem"),
      &[FilesystemAccessMode::ReadFile],
    )];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };

    let redacted = serde_json::to_string(&manifest.view(false)).expect("serialize redacted");
    let full = serde_json::to_string(&manifest.view(true)).expect("serialize full");

    assert!(!redacted.contains("private.pem"));
    assert!(!redacted.contains(manifest.digest()));
    assert!(redacted.contains("\"manifest_digest_withheld\":true"));
    assert!(redacted.contains("path-0001"));
    assert!(full.contains("/sensitive/private.pem"));
    assert!(full.contains(manifest.digest()));
    assert_eq!(manifest.view(false), manifest.view(false));
  }

  #[test]
  fn mountinfo_parser_decodes_paths_and_selects_deepest_mount() {
    let mounts = parse_mountinfo(
      "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / /var/lib/oxi\\040belt ro - tmpfs tmpfs ro\n",
    )
    .expect("parse mountinfo");
    let selected =
      find_mount(Path::new("/var/lib/oxi belt/cache/item"), &mounts).expect("matching mount");
    assert_eq!(selected.mount_point, Path::new("/var/lib/oxi belt"));
    assert!(selected.read_only);
  }

  #[test]
  fn broader_descendant_access_covers_exact_candidate() {
    let installed = FilesystemAccessEntry {
      path: PathBuf::from("/var/lib/oxibelt"),
      digest_identity_path: PathBuf::from("/var/lib/oxibelt"),
      access: vec![FilesystemAccessMode::ReadFile],
      purpose: FilesystemAccessPurpose::RuntimeData,
      source_config_path: None,
      expected_type: FilesystemPathType::Directory,
      scope: FilesystemPathScope::Descendants,
      requires_parent_write: false,
      optional: false,
    };
    let required = entry(
      Path::new("/var/lib/oxibelt/cache/item"),
      &[FilesystemAccessMode::ReadFile],
    );
    assert!(installed.covers(&required));
  }

  #[test]
  fn parent_write_semantics_are_not_covered_by_path_rights_alone() {
    let installed = entry(
      Path::new("/var/lib/oxibelt/audit"),
      &[FilesystemAccessMode::WriteFile],
    );
    let mut required = installed.clone();
    required.requires_parent_write = true;
    let expansion = expansion_from_entries(&required, &[installed]).expect("parent expansion");
    assert_eq!(
      expansion.kind(),
      FilesystemAccessExpansionKind::ParentWriteExpanded
    );
  }

  #[test]
  fn reload_comparison_distinguishes_equal_subset_and_rights_expansion() {
    let read = entry(
      Path::new("/etc/oxibelt/config.toml"),
      &[FilesystemAccessMode::ReadFile],
    );
    let mut broader = read.clone();
    broader.access.push(FilesystemAccessMode::WriteFile);
    broader.access.sort();
    let installed = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: vec![broader.clone()],
      digest: "sha256:installed".to_string(),
    };
    let equal = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: vec![broader],
      digest: "sha256:equal".to_string(),
    };
    let subset = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: vec![read.clone()],
      digest: "sha256:subset".to_string(),
    };
    let expansion = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: vec![FilesystemAccessEntry {
        access: vec![
          FilesystemAccessMode::ReadFile,
          FilesystemAccessMode::WriteFile,
        ],
        ..read
      }],
      digest: "sha256:expansion".to_string(),
    };

    assert!(equal.access_is_subset_of(&installed));
    assert!(subset.access_is_subset_of(&installed));
    assert!(!expansion.access_is_subset_of(&subset));
  }

  #[test]
  fn manual_landlock_roots_keep_write_and_read_authority_distinct() {
    let read_candidate = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: vec![entry(
        Path::new("/etc/oxibelt/cert.pem"),
        &[FilesystemAccessMode::ReadFile],
      )],
      digest: "sha256:read".to_string(),
    };
    assert!(
      read_candidate
        .access_expansion_from_landlock(None, &[PathBuf::from("/etc/oxibelt")], &[])
        .is_empty()
    );

    let mut write = read_candidate.entries[0].clone();
    write.access.push(FilesystemAccessMode::WriteFile);
    let write_candidate = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      entries: vec![write],
      digest: "sha256:write".to_string(),
    };
    assert_eq!(
      write_candidate
        .access_expansion_from_landlock(None, &[PathBuf::from("/etc/oxibelt")], &[])
        .len(),
      1
    );
    assert!(
      write_candidate
        .access_expansion_from_landlock(None, &[], &[PathBuf::from("/etc/oxibelt")])
        .is_empty()
    );
  }

  #[test]
  fn manifest_landlock_rules_preserve_per_path_write_authority() {
    let cache_path = PathBuf::from("/var/cache/oxibelt");
    let socket_path = PathBuf::from("/run/oxibelt");
    let entries = vec![
      FilesystemAccessEntry {
        path: cache_path.clone(),
        digest_identity_path: cache_path.clone(),
        access: vec![
          FilesystemAccessMode::ReadFile,
          FilesystemAccessMode::ReadDirectory,
          FilesystemAccessMode::WriteFile,
          FilesystemAccessMode::CreateFile,
          FilesystemAccessMode::RemoveFile,
        ],
        purpose: FilesystemAccessPurpose::Cache,
        source_config_path: Some("cache.disk_dir".to_string()),
        expected_type: FilesystemPathType::Directory,
        scope: FilesystemPathScope::Descendants,
        requires_parent_write: false,
        optional: false,
      },
      FilesystemAccessEntry {
        path: socket_path.clone(),
        digest_identity_path: socket_path.clone(),
        access: vec![
          FilesystemAccessMode::ReadDirectory,
          FilesystemAccessMode::BindUnixSocket,
        ],
        purpose: FilesystemAccessPurpose::RuntimeSocket,
        source_config_path: Some("runtime.netport_switcher.socket_dir".to_string()),
        expected_type: FilesystemPathType::Directory,
        scope: FilesystemPathScope::Descendants,
        requires_parent_write: false,
        optional: false,
      },
    ];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };

    let projection = manifest.landlock_projection();
    let cache_rule = projection
      .rules
      .iter()
      .find(|rule| rule.path == cache_path)
      .expect("cache rule");
    assert!(
      cache_rule
        .access
        .contains(&LandlockFilesystemRight::MakeReg)
    );
    assert!(
      !cache_rule
        .access
        .contains(&LandlockFilesystemRight::MakeSock)
    );
    let socket_rule = projection
      .rules
      .iter()
      .find(|rule| rule.path == socket_path)
      .expect("socket rule");
    assert!(
      socket_rule
        .access
        .contains(&LandlockFilesystemRight::MakeSock)
    );
    assert!(
      !socket_rule
        .access
        .contains(&LandlockFilesystemRight::MakeReg)
    );
  }

  #[test]
  fn checks_do_not_create_missing_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing");
    let entries = vec![entry(&missing, &[FilesystemAccessMode::ReadFile])];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };

    let report = manifest.check(false, Some("1 0 0:1 / / rw - rootfs rootfs rw\n"));

    assert!(report.has_errors());
    assert!(!missing.exists());
    assert!(
      report
        .findings
        .iter()
        .any(|finding| finding.code == FilesystemAccessFindingCode::PathMissing)
    );
  }

  #[test]
  fn missing_parent_write_root_is_consistently_unrepresentable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("audit");
    let entries = vec![FilesystemAccessEntry {
      path: missing.clone(),
      digest_identity_path: missing,
      access: vec![FilesystemAccessMode::CreateFile],
      purpose: FilesystemAccessPurpose::AuditSpool,
      source_config_path: Some("admin.audit.spool.directory".to_string()),
      expected_type: FilesystemPathType::Directory,
      scope: FilesystemPathScope::Descendants,
      requires_parent_write: true,
      optional: false,
    }];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };

    let report = manifest.check(false, Some("1 0 0:1 / / rw - rootfs rootfs rw\n"));
    assert!(report.has_errors());
    assert!(
      report
        .findings
        .iter()
        .any(|finding| { finding.code == FilesystemAccessFindingCode::ParentScopeUnrepresentable })
    );
    assert!(!manifest.landlock_projection().parent_scope_representable);
  }

  #[test]
  fn read_only_root_compatibility_rejects_read_only_child_mounts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let entries = vec![FilesystemAccessEntry {
      path: temp.path().to_path_buf(),
      digest_identity_path: temp.path().to_path_buf(),
      access: vec![FilesystemAccessMode::WriteFile],
      purpose: FilesystemAccessPurpose::RuntimeState,
      source_config_path: Some("runtime.state".to_string()),
      expected_type: FilesystemPathType::Directory,
      scope: FilesystemPathScope::Descendants,
      requires_parent_write: false,
      optional: false,
    }];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };
    let mountinfo = format!(
      "1 0 0:1 / / rw - rootfs rootfs rw\n2 1 0:2 / {} ro - tmpfs tmpfs ro\n",
      temp.path().display()
    );
    let report = manifest.check(false, Some(&mountinfo));
    assert_eq!(report.read_only_rootfs_compatible, Some(false));
  }

  #[test]
  fn optional_missing_paths_are_not_projected_as_landlock_rules() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut optional = entry(
      &temp.path().join("missing-platform-file"),
      &[FilesystemAccessMode::ReadFile],
    );
    optional.optional = true;
    let entries = vec![optional];
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };
    assert!(manifest.landlock_projection().rules.is_empty());
  }

  #[test]
  fn findings_are_bounded_and_report_truncation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let entries = (0..(MAX_FILESYSTEM_ACCESS_FINDINGS + 32))
      .map(|index| {
        entry(
          &temp.path().join(format!("missing-{index}")),
          &[FilesystemAccessMode::ReadFile],
        )
      })
      .collect::<Vec<_>>();
    let manifest = FilesystemAccessManifest {
      schema_version: FILESYSTEM_ACCESS_MANIFEST_SCHEMA_VERSION,
      digest: manifest_digest(&entries),
      entries,
    };
    let report = manifest.check(false, Some("1 0 0:1 / / rw - rootfs rootfs rw\n"));
    assert_eq!(report.findings.len(), MAX_FILESYSTEM_ACCESS_FINDINGS);
    assert!(report.findings_truncated);
    assert!(report.total_findings as usize > report.findings.len());
  }

  #[test]
  fn proc_self_paths_remain_process_independent_in_the_manifest() {
    assert_eq!(
      normalize_path(Path::new("/proc/self/status"), Path::new("/")).expect("normalize proc path"),
      Path::new("/proc/self/status")
    );
  }
}
