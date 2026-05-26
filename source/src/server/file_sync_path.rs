use std::path::{Component, Path};

use super::admin_control::AdminFileRoot;

const OXIRULE_FILE_SUFFIX: &str = ".oxirule.toml";
const OXIRULE_GROUP_FILE_SUFFIX: &str = ".oxirule-group.toml";
const OXIRULE_RULEPACK_FILE_SUFFIX: &str = ".oxirule-rulepack.toml";

pub(super) fn normalized_relative_path(path: &str) -> Result<String, String> {
  if path.trim().is_empty() {
    return Err("file sync path must not be empty".to_string());
  }
  let path = Path::new(path);
  if path.to_str().is_none() {
    return Err("file sync path must be valid UTF-8".to_string());
  }
  let mut parts = Vec::new();
  for component in path.components() {
    match component {
      Component::Normal(part) => parts.push(
        part
          .to_str()
          .ok_or_else(|| "file sync path must be valid UTF-8".to_string())?
          .to_string(),
      ),
      Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
        return Err(
          "file sync path must not contain absolute, current-directory, or parent-directory components"
            .to_string(),
        );
      }
    }
  }
  if parts.is_empty() {
    return Err("file sync path must not be empty".to_string());
  }
  Ok(parts.join("/"))
}

pub(super) fn validate_root_path(root: AdminFileRoot, normalized_path: &str) -> Result<(), String> {
  match root {
    AdminFileRoot::Config => Ok(()),
    AdminFileRoot::OxiRule if normalized_path.ends_with(OXIRULE_FILE_SUFFIX) => Ok(()),
    AdminFileRoot::OxiRule => Err("root oxirule can only manage .oxirule.toml files".to_string()),
    AdminFileRoot::OxiRuleGroup if normalized_path.ends_with(OXIRULE_GROUP_FILE_SUFFIX) => Ok(()),
    AdminFileRoot::OxiRuleGroup => {
      Err("root oxirule_group can only manage .oxirule-group.toml files".to_string())
    }
    AdminFileRoot::OxiRuleRulepack if normalized_path.ends_with(OXIRULE_RULEPACK_FILE_SUFFIX) => {
      Ok(())
    }
    AdminFileRoot::OxiRuleRulepack => {
      Err("root oxirule_rulepack can only manage .oxirule-rulepack.toml files".to_string())
    }
  }
}
