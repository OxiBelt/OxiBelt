use std::path::PathBuf;

use clap::Args;
use oxibelt::diagnostics::{DoctorFailOn, DoctorOutputFormat, ExternalProbeKind};

#[derive(Debug, Args)]
pub(crate) struct DoctorArgs {
  #[arg(long, value_name = "FILE", conflicts_with = "candidate")]
  pub(crate) config: Option<PathBuf>,
  #[arg(
    long,
    value_name = "FILE",
    conflicts_with_all = ["config", "helm_rendered", "helm_chart", "kubernetes"]
  )]
  pub(crate) candidate: Option<PathBuf>,
  #[arg(
    long = "helm-rendered",
    value_name = "DIR",
    conflicts_with_all = ["helm_chart", "kubernetes", "candidate"]
  )]
  pub(crate) helm_rendered: Option<PathBuf>,
  #[arg(
    long = "helm-chart",
    value_name = "CHART",
    conflicts_with_all = ["helm_rendered", "kubernetes", "candidate"]
  )]
  pub(crate) helm_chart: Option<PathBuf>,
  #[arg(long = "helm-values", value_name = "FILE", requires = "helm_chart")]
  pub(crate) helm_values: Vec<PathBuf>,
  #[arg(
    long = "helm-release",
    value_name = "NAME",
    default_value = "oxibelt-doctor"
  )]
  pub(crate) helm_release: String,
  #[arg(
    long = "helm-namespace",
    value_name = "NAMESPACE",
    default_value = "default"
  )]
  pub(crate) helm_namespace: String,
  #[arg(long, conflicts_with_all = ["helm_rendered", "helm_chart", "candidate"])]
  pub(crate) kubernetes: bool,
  #[arg(long = "kube-context", value_name = "CONTEXT", requires = "kubernetes")]
  pub(crate) kube_context: Option<String>,
  #[arg(
    long = "kube-namespace",
    value_name = "NAMESPACE",
    requires = "kubernetes"
  )]
  pub(crate) kube_namespace: Option<String>,
  #[arg(
    long = "all-namespaces",
    requires = "kubernetes",
    conflicts_with = "kube_namespace"
  )]
  pub(crate) all_namespaces: bool,
  #[arg(
    long = "kube-selector",
    value_name = "SELECTOR",
    requires = "kubernetes"
  )]
  pub(crate) kube_selector: Option<String>,
  #[arg(long, value_name = "FORMAT", value_parser = parse_output_format, default_value = "text")]
  pub(crate) format: DoctorOutputFormat,
  #[arg(long = "fail-on", value_name = "SEVERITY", value_parser = parse_fail_on, default_value = "error")]
  pub(crate) fail_on: DoctorFailOn,
  #[arg(long = "external-probe", value_name = "KIND", value_parser = parse_external_probe)]
  pub(crate) external_probes: Vec<ExternalProbeKind>,
}

impl DoctorArgs {
  pub(crate) fn deployment_source_count(&self) -> usize {
    usize::from(self.helm_rendered.is_some())
      + usize::from(self.helm_chart.is_some())
      + usize::from(self.kubernetes)
  }

  pub(crate) fn has_local_source(&self) -> bool {
    self.config.is_some() || self.deployment_source_count() > 0
  }
}

fn parse_output_format(value: &str) -> Result<DoctorOutputFormat, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}

fn parse_fail_on(value: &str) -> Result<DoctorFailOn, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}

fn parse_external_probe(value: &str) -> Result<ExternalProbeKind, String> {
  value
    .parse()
    .map_err(|error: anyhow::Error| error.to_string())
}
