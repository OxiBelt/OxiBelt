use std::path::PathBuf;

use super::ConfigOriginIndex;

/// Source-file metadata retained for diagnostics and reload-aware admin responses.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigSourcePaths {
  pub config_entry: Option<PathBuf>,
  pub config_dir: Option<PathBuf>,
  pub cert_dir: Option<PathBuf>,
  pub oxirule_dir: Option<PathBuf>,
  pub config_files: Vec<PathBuf>,
  pub field_origins: ConfigOriginIndex,
  pub runtime_files: Vec<PathBuf>,
  pub discovery_files: Vec<PathBuf>,
  pub downstream_tls_files: Vec<PathBuf>,
  pub downstream_tls_cert_chain: Option<PathBuf>,
  pub downstream_tls_private_key: Option<PathBuf>,
  pub downstream_tls_certificates: Vec<DownstreamTlsCertificateSourcePaths>,
  pub downstream_tls_remote_signer_token_file: Option<PathBuf>,
  pub downstream_tls_ocsp_response_file: Option<PathBuf>,
  pub downstream_tls_crlite_filter_file: Option<PathBuf>,
  pub downstream_tls_ct_log_list_file: Option<PathBuf>,
  pub downstream_tls_ct_log_list_signature_file: Option<PathBuf>,
  pub quic_host_key_file: Option<PathBuf>,
  pub oxirule_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DownstreamTlsCertificateSourcePaths {
  pub cert_chain: PathBuf,
  pub private_key: Option<PathBuf>,
  pub ocsp_response_file: Option<PathBuf>,
}

impl ConfigSourcePaths {
  pub fn all_reload_files(&self) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(path) = &self.config_entry {
      files.push(path.clone());
    }
    files.extend(self.config_files.iter().cloned());
    files.extend(self.runtime_files.iter().cloned());
    files.extend(self.oxirule_files.iter().cloned());
    dedup_paths(files)
  }

  pub fn oxirule_reload_files(&self) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(path) = &self.config_entry {
      files.push(path.clone());
    }
    files.extend(self.config_files.iter().cloned());
    files.extend(self.oxirule_files.iter().cloned());
    dedup_paths(files)
  }

  pub fn downstream_tls_reload_files(&self) -> Vec<PathBuf> {
    dedup_paths(self.downstream_tls_files.clone())
  }

  pub(crate) fn remember_runtime_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.runtime_files, path);
  }

  pub(crate) fn remember_discovery_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.discovery_files, path);
  }

  pub(crate) fn remember_downstream_tls_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.downstream_tls_files, path);
  }

  pub(crate) fn remember_oxirule_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.oxirule_files, path);
  }
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
  if !paths.contains(&path) {
    paths.push(path);
  }
}

fn dedup_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
  paths.sort();
  paths.dedup();
  paths
}
