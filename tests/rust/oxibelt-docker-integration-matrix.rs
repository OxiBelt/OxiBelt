use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod oxibelt_docker_integration_matrix;

struct DockerCase {
  category: &'static str,
  name: &'static str,
  description: &'static str,
  expect_start: ExpectStart,
  needs: Needs,
  root_netport_switcher: bool,
  failure_contains: Option<&'static str>,
}

struct BrowserScenario {
  name: &'static str,
  description: &'static str,
}

struct DockerIntegrationGroup {
  name: &'static str,
  categories: &'static [&'static str],
}

const DOCKER_INTEGRATION_GROUPS: &[DockerIntegrationGroup] = &[
  DockerIntegrationGroup {
    name: "config-runtime",
    categories: &[
      "config-valid",
      "config-invalid",
      "listener-http",
      "limits",
      "timeouts",
      "buffering",
      "hot-reload",
      "lifecycle",
    ],
  },
  DockerIntegrationGroup {
    name: "proxy",
    categories: &[
      "http-semantics",
      "proxy-compression",
      "proxy-headers",
      "proxy-identity",
      "proxy-protocol",
      "proxy-routing",
      "proxy-upstream-tls",
      "upstream-discovery",
      "upstream-pools",
    ],
  },
  DockerIntegrationGroup {
    name: "protocol",
    categories: &[
      "protocol-startup",
      "protocol-proxying",
      "protocol-operations",
      "sni-forwarding",
    ],
  },
  DockerIntegrationGroup {
    name: "waf",
    categories: &[
      "waf-request",
      "waf-response",
      "waf",
      "waf-validation",
      "waf-helpers",
      "waf-crs",
      "waf-person-proof",
    ],
  },
  DockerIntegrationGroup {
    name: "cache",
    categories: &["cache"],
  },
  DockerIntegrationGroup {
    name: "state-data",
    categories: &[
      "database-access-log",
      "database-mitigation",
      "dynamic-policy",
      "shared-state",
    ],
  },
  DockerIntegrationGroup {
    name: "ops",
    categories: &["ops"],
  },
  DockerIntegrationGroup {
    name: "security",
    categories: &["security"],
  },
];

#[derive(Clone, Copy)]
enum ExpectStart {
  Success,
  Failure,
}

#[derive(Clone, Copy, Default)]
struct Needs {
  http_upstream: bool,
  https_upstream: bool,
  alt_upstream: bool,
  h2_upstream: bool,
  h2c_upstream: bool,
  h1_stall_upstream: bool,
  h3_upstream: bool,
  webtransport_upstream: bool,
  websocket_upstream: bool,
  turn_udp_upstream: bool,
  turn_tcp_upstream: bool,
  turn_tls_upstream: bool,
  dns_server: bool,
  kubernetes_server: bool,
  nomad_server: bool,
  protocol_probe: bool,
  pq_probe: bool,
  postgres: bool,
  postgres_mtls: bool,
  redis: bool,
  remote_signer: bool,
  second_proxy: bool,
}

fn main() -> Result<()> {
  let mut args = env::args().skip(1).collect::<Vec<_>>();
  if args.is_empty() {
    usage();
    return Err("missing command".into());
  }

  match args.remove(0).as_str() {
    "list" => list_command(&args),
    "materialize" => materialize_command(&args),
    _ => {
      usage();
      Err("unknown command".into())
    }
  }
}

fn list_command(args: &[String]) -> Result<()> {
  let suite = arg_value(args, "--suite")?;
  let format = arg_value(args, "--format")?;
  let group = optional_arg_value(args, "--group");
  if format != "github-matrix" {
    return Err(format!("unsupported list format: {format}").into());
  }

  match suite.as_str() {
    "docker" => print_docker_matrix(group.as_deref()),
    "browser" => {
      if group.is_some() {
        return Err("--group is only supported for the docker suite".into());
      }
      print_browser_matrix()
    }
    _ => Err(format!("unsupported suite: {suite}").into()),
  }
}

fn materialize_command(args: &[String]) -> Result<()> {
  let suite = arg_value(args, "--suite")?;
  let category = arg_value(args, "--category")?;
  let case_name = arg_value(args, "--case")?;
  let output = PathBuf::from(arg_value(args, "--output")?);

  match suite.as_str() {
    "docker" => {
      let case = docker_cases()
        .into_iter()
        .find(|case| case.category == category && case.name == case_name)
        .ok_or_else(|| format!("unknown docker case {category}/{case_name}"))?;
      materialize_docker_case(&case, &output)
    }
    "browser" => {
      let scenario = browser_scenarios()
        .into_iter()
        .find(|scenario| category == "webdriver" && scenario.name == case_name)
        .ok_or_else(|| format!("unknown browser scenario {category}/{case_name}"))?;
      materialize_browser_scenario(&scenario, &output)
    }
    _ => Err(format!("unsupported suite: {suite}").into()),
  }
}

fn usage() {
  eprintln!(
    "usage:\n  oxibelt-docker-integration-matrix list --suite <docker|browser> --format github-matrix [--group <docker-group>]\n  oxibelt-docker-integration-matrix materialize --suite <docker|browser> --category <name> --case <name> --output <dir>"
  );
}

fn arg_value(args: &[String], name: &str) -> Result<String> {
  args
    .windows(2)
    .find(|items| items[0] == name)
    .map(|items| items[1].clone())
    .ok_or_else(|| format!("missing argument {name}").into())
}

fn optional_arg_value(args: &[String], name: &str) -> Option<String> {
  args
    .windows(2)
    .find(|items| items[0] == name)
    .map(|items| items[1].clone())
}

fn docker_integration_group(name: &str) -> Result<&'static DockerIntegrationGroup> {
  if let Some(group) = DOCKER_INTEGRATION_GROUPS
    .iter()
    .find(|group| group.name == name)
  {
    return Ok(group);
  }

  let supported = DOCKER_INTEGRATION_GROUPS
    .iter()
    .map(|group| group.name)
    .collect::<Vec<_>>()
    .join(", ");
  Err(format!("unsupported docker matrix group: {name}; supported groups: {supported}").into())
}

fn print_docker_matrix(group: Option<&str>) -> Result<()> {
  let cases = docker_cases();
  let selected_cases = if let Some(group) = group {
    let group = docker_integration_group(group)?;
    cases
      .iter()
      .filter(|case| group.categories.contains(&case.category))
      .collect::<Vec<_>>()
  } else {
    cases.iter().collect::<Vec<_>>()
  };

  if selected_cases.is_empty() {
    return Err("selected docker matrix group has no cases".into());
  }

  print!("{{\"include\":[");
  for (index, case) in selected_cases.iter().enumerate() {
    if index > 0 {
      print!(",");
    }
    print!(
      "{{\"category\":\"{}\",\"case\":\"{}\",\"name\":\"{}\",\"description\":\"{}\"}}",
      json_escape(case.category),
      json_escape(case.name),
      json_escape(&format!("{}/{}", case.category, case.name)),
      json_escape(case.description)
    );
  }
  println!("]}}");
  Ok(())
}

fn print_browser_matrix() -> Result<()> {
  let scenarios = browser_scenarios();
  print!("{{\"include\":[");
  let mut first = true;
  for browser in ["chromium", "firefox"] {
    for scenario in &scenarios {
      if !first {
        print!(",");
      }
      first = false;
      print!(
        "{{\"browser\":\"{}\",\"category\":\"webdriver\",\"case\":\"{}\",\"name\":\"{}\",\"description\":\"{}\"}}",
        browser,
        json_escape(scenario.name),
        json_escape(&format!("{browser}/{}", scenario.name)),
        json_escape(scenario.description)
      );
    }
  }
  println!("]}}");
  Ok(())
}

fn materialize_docker_case(case: &DockerCase, output: &Path) -> Result<()> {
  fs::create_dir_all(output)?;
  let output = canonical_existing_dir(output, "docker case output directory")?;
  let mut manifest = String::new();
  manifest.push_str(&format!("CASE_CATEGORY={}\n", shell_quote(case.category)));
  manifest.push_str(&format!("CASE_NAME={}\n", shell_quote(case.name)));
  manifest.push_str(&format!(
    "CASE_DESCRIPTION={}\n",
    shell_quote(case.description)
  ));
  manifest.push_str(&format!(
    "CASE_EXPECT_START={}\n",
    shell_quote(match case.expect_start {
      ExpectStart::Success => "success",
      ExpectStart::Failure => "failure",
    })
  ));
  manifest.push_str(&format!(
    "CASE_NEED_HTTP_UPSTREAM={}\n",
    bool_env(case.needs.http_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_HTTPS_UPSTREAM={}\n",
    bool_env(case.needs.https_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_ALT_UPSTREAM={}\n",
    bool_env(case.needs.alt_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_H2_UPSTREAM={}\n",
    bool_env(case.needs.h2_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_H2C_UPSTREAM={}\n",
    bool_env(case.needs.h2c_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_H1_STALL_UPSTREAM={}\n",
    bool_env(case.needs.h1_stall_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_H3_UPSTREAM={}\n",
    bool_env(case.needs.h3_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_WEBTRANSPORT_UPSTREAM={}\n",
    bool_env(case.needs.webtransport_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_WEBSOCKET_UPSTREAM={}\n",
    bool_env(case.needs.websocket_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_TURN_UDP_UPSTREAM={}\n",
    bool_env(case.needs.turn_udp_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_TURN_TCP_UPSTREAM={}\n",
    bool_env(case.needs.turn_tcp_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_TURN_TLS_UPSTREAM={}\n",
    bool_env(case.needs.turn_tls_upstream)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_DNS_SERVER={}\n",
    bool_env(case.needs.dns_server)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_KUBERNETES_SERVER={}\n",
    bool_env(case.needs.kubernetes_server)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_NOMAD_SERVER={}\n",
    bool_env(case.needs.nomad_server)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_PROTOCOL_PROBE={}\n",
    bool_env(case.needs.protocol_probe)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_PQ_PROBE={}\n",
    bool_env(case.needs.pq_probe)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_POSTGRES={}\n",
    bool_env(case.needs.postgres)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_POSTGRES_MTLS={}\n",
    bool_env(case.needs.postgres_mtls)
  ));
  manifest.push_str(&format!("CASE_NEED_REDIS={}\n", bool_env(case.needs.redis)));
  manifest.push_str(&format!(
    "CASE_NEED_REMOTE_SIGNER={}\n",
    bool_env(case.needs.remote_signer)
  ));
  manifest.push_str(&format!(
    "CASE_NEED_SECOND_PROXY={}\n",
    bool_env(case.needs.second_proxy)
  ));
  manifest.push_str(&format!(
    "CASE_ROOT_NETPORT_SWITCHER={}\n",
    bool_env(case.root_netport_switcher)
  ));
  manifest.push_str(&format!(
    "CASE_EXPECT_FAILURE_CONTAINS={}\n",
    shell_quote(case.failure_contains.unwrap_or(""))
  ));
  copy_case_fixture_tree(case, &output)?;
  write_file(&output, "manifest.env", &manifest)?;
  Ok(())
}

fn materialize_browser_scenario(scenario: &BrowserScenario, output: &Path) -> Result<()> {
  fs::create_dir_all(output)?;
  let output = canonical_existing_dir(output, "browser scenario output directory")?;
  write_file(
    &output,
    "manifest.env",
    &format!(
      "CASE_CATEGORY='webdriver'\nCASE_NAME={}\nCASE_DESCRIPTION={}\n",
      shell_quote(scenario.name),
      shell_quote(scenario.description)
    ),
  )
}

fn write_file(root: &Path, relative: &str, content: &str) -> Result<()> {
  let path = root.join(relative);
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)?;
  }
  fs::write(path, content)?;
  Ok(())
}

fn copy_case_fixture_tree(case: &DockerCase, output: &Path) -> Result<()> {
  let source = docker_case_fixture_dir(case)?;
  let checks = source.join("checks.sh");
  if !checks.is_file() {
    return Err(format!("missing docker case checks file: {}", checks.display()).into());
  }
  copy_dir_contents(&source, output)
}

fn docker_case_fixture_dir(case: &DockerCase) -> Result<PathBuf> {
  let fixture_root = docker_fixture_root()
    .canonicalize()
    .map_err(|err| format!("failed to resolve docker fixture root: {err}"))?;
  let category = safe_path_component(OsStr::new(case.category), "docker case category")?;
  let name = safe_path_component(OsStr::new(case.name), "docker case name")?;
  let source = fixture_root.join(category).join(name);
  if !source.is_dir() {
    return Err(format!("missing docker fixture directory: {}", source.display()).into());
  }
  let source = source.canonicalize().map_err(|err| {
    format!(
      "failed to resolve docker fixture directory {}: {err}",
      source.display()
    )
  })?;
  ensure_path_under(&fixture_root, &source, "docker fixture directory")?;
  Ok(source)
}

fn docker_fixture_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("../tests/fixtures/oxibelt-docker-integration-matrix/docker")
}

fn copy_dir_contents(source: &Path, target: &Path) -> Result<()> {
  let source_root = canonical_existing_dir(source, "fixture source directory")?;
  let target_root = canonical_existing_dir(target, "fixture target directory")?;
  copy_dir_contents_inner(&source_root, &source_root, &target_root, &target_root)
}

fn copy_dir_contents_inner(
  source_root: &Path,
  source: &Path,
  target_root: &Path,
  target: &Path,
) -> Result<()> {
  for entry in fs::read_dir(source).map_err(|err| {
    format!(
      "failed to read fixture directory {}: {err}",
      source.display()
    )
  })? {
    let entry = entry?;
    let entry_name = safe_path_component(&entry.file_name(), "fixture entry name")?;
    let source_path = entry.path();
    let target_path = target.join(&entry_name);
    let file_type = entry.file_type()?;
    if file_type.is_dir() {
      fs::create_dir_all(&target_path)?;
      let source_path = source_path.canonicalize().map_err(|err| {
        format!(
          "failed to resolve fixture directory {}: {err}",
          source_path.display()
        )
      })?;
      let target_path = target_path.canonicalize().map_err(|err| {
        format!(
          "failed to resolve fixture output directory {}: {err}",
          target_path.display()
        )
      })?;
      ensure_path_under(source_root, &source_path, "fixture source directory")?;
      ensure_path_under(target_root, &target_path, "fixture output directory")?;
      copy_dir_contents_inner(source_root, &source_path, target_root, &target_path)?;
    } else if file_type.is_file() {
      let source_path = source_path.canonicalize().map_err(|err| {
        format!(
          "failed to resolve fixture file {}: {err}",
          source_path.display()
        )
      })?;
      ensure_path_under(source_root, &source_path, "fixture source file")?;
      let mut target_file = target_path.clone();
      if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)?;
        let parent = parent.canonicalize().map_err(|err| {
          format!(
            "failed to resolve fixture output parent {}: {err}",
            parent.display()
          )
        })?;
        ensure_path_under(target_root, &parent, "fixture output parent")?;
        target_file = parent.join(&entry_name);
      }
      fs::copy(&source_path, &target_file).map_err(|err| {
        format!(
          "failed to copy fixture {} to {}: {err}",
          source_path.display(),
          target_file.display()
        )
      })?;
    } else {
      return Err(format!("unsupported fixture entry: {}", source_path.display()).into());
    }
  }
  Ok(())
}

fn canonical_existing_dir(path: &Path, field_name: &str) -> Result<PathBuf> {
  let path = path
    .canonicalize()
    .map_err(|err| format!("failed to resolve {field_name} {}: {err}", path.display()))?;
  if !path.is_dir() {
    return Err(format!("{field_name} is not a directory: {}", path.display()).into());
  }
  Ok(path)
}

fn ensure_path_under(root: &Path, path: &Path, field_name: &str) -> Result<()> {
  if !path.starts_with(root) {
    return Err(
      format!(
        "{field_name} {} must stay under {}",
        path.display(),
        root.display()
      )
      .into(),
    );
  }
  Ok(())
}

fn safe_path_component(value: &OsStr, field_name: &str) -> Result<String> {
  let value = value
    .to_str()
    .ok_or_else(|| format!("{field_name} must be valid UTF-8"))?;
  if value.is_empty() || matches!(value, "." | "..") {
    return Err(format!("{field_name} must not be empty or a dot segment").into());
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
  {
    return Err(
      format!("{field_name} must contain only ASCII letters, digits, '.', '_' or '-'").into(),
    );
  }
  if value.contains("..") {
    return Err(format!("{field_name} must not contain parent-directory-like segments").into());
  }
  Ok(value.to_string())
}

fn bool_env(value: bool) -> &'static str {
  if value { "1" } else { "0" }
}

fn shell_quote(value: &str) -> String {
  format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn json_escape(value: &str) -> String {
  value
    .chars()
    .flat_map(|ch| match ch {
      '"' => "\\\"".chars().collect::<Vec<_>>(),
      '\\' => "\\\\".chars().collect::<Vec<_>>(),
      '\n' => "\\n".chars().collect::<Vec<_>>(),
      '\r' => "\\r".chars().collect::<Vec<_>>(),
      '\t' => "\\t".chars().collect::<Vec<_>>(),
      ch if ch.is_control() => format!("\\u{:04x}", ch as u32).chars().collect(),
      ch => vec![ch],
    })
    .collect()
}

fn docker_cases() -> Vec<DockerCase> {
  oxibelt_docker_integration_matrix::docker_cases()
}

fn browser_scenarios() -> Vec<BrowserScenario> {
  vec![
    BrowserScenario {
      name: "basic-navigation",
      description: "browser reaches OxiBelt and upstream receives forwarded metadata",
    },
    BrowserScenario {
      name: "waf-request",
      description: "browser-visible request WAF rejection",
    },
    BrowserScenario {
      name: "waf-response",
      description: "browser-visible response WAF mutation and replacement",
    },
    BrowserScenario {
      name: "person-proof",
      description: "browser solves person proof and reuses clearance",
    },
    BrowserScenario {
      name: "hot-reload",
      description: "browser observes full config and TLS hot reload",
    },
  ]
}

fn docker_case(
  category: &'static str,
  name: &'static str,
  description: &'static str,
  expect_start: ExpectStart,
  needs: Needs,
  failure_contains: Option<&'static str>,
) -> DockerCase {
  DockerCase {
    category,
    name,
    description,
    expect_start,
    needs,
    root_netport_switcher: false,
    failure_contains,
  }
}

fn root_netport_switcher_case(mut case: DockerCase) -> DockerCase {
  case.root_netport_switcher = true;
  case
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn safe_path_component_accepts_fixture_style_names() {
    assert_eq!(
      safe_path_component(OsStr::new("config-valid"), "test field").unwrap(),
      "config-valid"
    );
    assert_eq!(
      safe_path_component(OsStr::new("10-upstreams.toml"), "test field").unwrap(),
      "10-upstreams.toml"
    );
    assert_eq!(
      safe_path_component(OsStr::new("conf.d"), "test field").unwrap(),
      "conf.d"
    );
  }

  #[test]
  fn safe_path_component_rejects_traversal_and_separators() {
    for value in [
      "..",
      "../escape",
      "escape/child",
      "escape\\child",
      "bad..name",
    ] {
      assert!(
        safe_path_component(OsStr::new(value), "test field").is_err(),
        "{value} should be rejected"
      );
    }
  }

  #[test]
  fn every_docker_case_has_fixture_assets() {
    let fixture_root = docker_fixture_root();
    for case in docker_cases() {
      let path = fixture_root.join(case.category).join(case.name);
      assert!(
        path.is_dir(),
        "missing fixture directory for {}/{} at {}",
        case.category,
        case.name,
        path.display()
      );
      let checks = path.join("checks.sh");
      assert!(
        checks.is_file(),
        "missing checks file for {}/{} at {}",
        case.category,
        case.name,
        checks.display()
      );
    }
  }

  #[test]
  fn every_docker_case_belongs_to_exactly_one_group() {
    for case in docker_cases() {
      let groups = DOCKER_INTEGRATION_GROUPS
        .iter()
        .filter(|group| group.categories.contains(&case.category))
        .map(|group| group.name)
        .collect::<Vec<_>>();

      assert_eq!(
        groups.len(),
        1,
        "docker case {}/{} should belong to exactly one group; found {:?}",
        case.category,
        case.name,
        groups
      );
    }
  }

  #[test]
  fn every_docker_group_has_cases() {
    let cases = docker_cases();
    for group in DOCKER_INTEGRATION_GROUPS {
      let case_count = cases
        .iter()
        .filter(|case| group.categories.contains(&case.category))
        .count();

      assert!(
        case_count > 0,
        "docker matrix group {} should contain at least one case",
        group.name
      );
    }
  }
}
