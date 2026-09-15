use super::{docker_integration_matrix_script_text, repo_root};
use std::collections::BTreeSet;
use std::fs;

fn template_dns_names(script: &str, filename: &str) -> BTreeSet<String> {
  let marker = format!("cat >\"${{work_dir}}/{filename}\" <<'EOF'\n");
  assert_eq!(
    script.matches(&marker).count(),
    1,
    "unique {filename} template"
  );
  let template = script
    .split_once(&marker)
    .expect("certificate template should exist")
    .1
    .split_once("\nEOF")
    .expect("certificate template should terminate")
    .0;
  let mut names = BTreeSet::new();
  for line in template.lines().filter(|line| line.starts_with("DNS.")) {
    let (_, value) = line.split_once('=').expect("DNS entry should have a value");
    let value = value.trim();
    assert!(!value.is_empty(), "DNS entry should not be empty");
    assert!(names.insert(value.to_owned()), "duplicate DNS name {value}");
  }
  assert!(
    !names.is_empty(),
    "certificate template should contain DNS names"
  );
  names
}

fn fixture_config(category: &str, case: &str) -> toml::Value {
  let path = repo_root()
    .join("tests/fixtures/oxibelt-docker-integration-matrix/docker")
    .join(category)
    .join(case)
    .join("config/oxibelt.toml");
  let contents = fs::read_to_string(path).expect("Docker fixture should be readable");
  toml::from_str(&contents).expect("Docker fixture should contain valid TOML")
}

#[test]
fn certificate_metadata_dns_counts_match_generated_leaf() {
  let script = docker_integration_matrix_script_text();
  let names = template_dns_names(&script, "certificate-metadata-upstream-leaf.cnf");
  let config = fixture_config("protocol-proxying", "certificate-metadata-real-protocols");
  let response_rules = config["waf"]["rules"].as_array().expect("response rules");
  let stream_rules = config["routes"]
    .as_array()
    .expect("certificate routes")
    .iter()
    .filter_map(|route| route.get("waf").and_then(|waf| waf.get("rules")))
    .flat_map(|rules| rules.as_array().expect("route rules"));
  let mut phases = Vec::new();
  for rule in response_rules.iter().chain(stream_rules) {
    let expression = rule["when"].as_str().expect("certificate rule expression");
    let marker = ".Upstream.ServerCertificate.SanDnsNames.Count == ";
    assert_eq!(
      expression.matches(marker).count(),
      1,
      "one upstream DNS count per rule"
    );
    let expected = expression
      .split_once(marker)
      .expect("certificate rule should check the upstream DNS count")
      .1
      .split_whitespace()
      .next()
      .expect("expected DNS count")
      .parse::<usize>()
      .expect("DNS count should be an integer");
    assert_eq!(
      names.len(),
      expected,
      "generated upstream DNS names disagree with rule {}: {names:?}",
      rule["name"]
    );
    phases.push(rule["phase"].as_str().expect("rule phase"));
  }
  assert_eq!(phases, ["response", "stream", "stream"]);
}

#[test]
fn incremental_upstreams_have_certificate_dns_names() {
  let script = docker_integration_matrix_script_text();
  let names = template_dns_names(&script, "upstream-leaf.cnf");
  for case in [
    "incremental-rfc10036",
    "incremental-rfc10036-unpooled",
    "status-headers",
  ] {
    let config = fixture_config("http-semantics", case);
    let mut tls_hosts = BTreeSet::new();
    for upstream in config["upstreams"]
      .as_array()
      .expect("Incremental upstreams")
    {
      let origin = url::Url::parse(upstream["origin"].as_str().expect("upstream origin"))
        .expect("upstream origin URL");
      if origin.scheme() == "https" {
        let host = origin.host_str().expect("TLS upstream hostname");
        assert!(
          names.contains(host),
          "{case}: certificate does not cover {host}"
        );
        tls_hosts.insert(host.to_owned());
      }
    }
    assert_eq!(tls_hosts.len(), 2, "{case}: cover both TLS upstreams");
  }
}
