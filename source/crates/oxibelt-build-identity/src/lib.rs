mod semver;

pub use semver::{compare_semver, is_release_version, parse_semver};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirtyState {
  Clean,
  Dirty,
  Unknown,
}

impl DirtyState {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Clean => "clean",
      Self::Dirty => "dirty",
      Self::Unknown => "unknown",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildKind {
  OfficialRelease,
  TaggedDevelopment,
  GitDevelopment,
  SourceArchive,
}

impl BuildKind {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::OfficialRelease => "official_release",
      Self::TaggedDevelopment => "tagged_development",
      Self::GitDevelopment => "git_development",
      Self::SourceArchive => "source_archive",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildIdentity {
  pub effective_version: &'static str,
  pub source_revision: Option<&'static str>,
  pub source_ref: Option<&'static str>,
  pub dirty: DirtyState,
  pub kind: BuildKind,
  compatibility_version: Option<&'static str>,
}

impl BuildIdentity {
  pub const fn compatibility_version(self) -> Option<&'static str> {
    self.compatibility_version
  }

  pub const fn source_revision_or_unknown(self) -> &'static str {
    match self.source_revision {
      Some(value) => value,
      None => "unknown",
    }
  }

  pub const fn source_ref_or_unknown(self) -> &'static str {
    match self.source_ref {
      Some(value) => value,
      None => "unknown",
    }
  }
}

include!(concat!(env!("OUT_DIR"), "/build_identity.rs"));

pub const fn current() -> &'static BuildIdentity {
  &BUILD_IDENTITY
}
