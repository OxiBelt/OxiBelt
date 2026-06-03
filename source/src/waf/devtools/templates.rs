//! Template rendering for generated OxiRule artifacts.
//! Rendering is data-only and does not validate runtime policy semantics.

use super::types::{
  OxiRuleDevtoolsReport, OxiRuleFalsePositiveRequest, OxiRuleTemplateRenderRequest,
  OxiRuleTemplateSummary,
};

pub fn list_oxirule_templates() -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  report.templates = OXIRULE_TEMPLATES
    .iter()
    .map(|template| OxiRuleTemplateSummary {
      name: template.name,
      description: template.description,
      variables: template.variables,
    })
    .collect();
  report
}

pub fn render_oxirule_template(request: OxiRuleTemplateRenderRequest) -> OxiRuleDevtoolsReport {
  let Some(template) = OXIRULE_TEMPLATES
    .iter()
    .find(|template| template.name == request.name)
  else {
    return OxiRuleDevtoolsReport::error(
      "oxirule.template.unknown",
      format!("unknown OxiRule template {}", request.name),
    );
  };
  let mut rendered = template.content.to_string();
  for variable in template.variables {
    let Some(value) = request.variables.get(*variable) else {
      return OxiRuleDevtoolsReport::error(
        "oxirule.template.variable",
        format!("template {} requires variable {}", template.name, variable),
      );
    };
    rendered = rendered.replace(&format!("{{{{{variable}}}}}"), value);
  }
  let mut report = OxiRuleDevtoolsReport::ok();
  report.rendered = Some(rendered);
  report
}

pub fn plan_false_positive(request: OxiRuleFalsePositiveRequest) -> OxiRuleDevtoolsReport {
  let mut report = OxiRuleDevtoolsReport::ok();
  let rule_id = json_string(&request.finding, "rule_id")
    .or_else(|| json_string(&request.finding, "id"))
    .unwrap_or_else(|| "rule-id".to_string());
  let rule_name = json_string(&request.finding, "rule_name")
    .or_else(|| json_string(&request.finding, "name"))
    .unwrap_or_else(|| rule_id.clone());
  let path =
    json_string(&request.finding, "path").unwrap_or_else(|| "/confirmed-safe-path".to_string());
  let method = json_string(&request.finding, "method").unwrap_or_else(|| "GET".to_string());
  let route = json_string(&request.finding, "route").unwrap_or_else(|| "app-root".to_string());
  let is_crs = json_string(&request.finding, "kind")
    .or_else(|| json_string(&request.finding, "engine"))
    .is_some_and(|kind| kind.eq_ignore_ascii_case("crs"));

  if is_crs {
    report.suggestions.push(
      "Add the narrowest CRS allowlist that matches the confirmed false positive traffic."
        .to_string(),
    );
    report.suggestions.push(
      "Keep the CRS rule visible in telemetry while suppressing scoring for that scoped traffic."
        .to_string(),
    );
    report.toml_patch = Some(format!(
      r#"[[waf.crs.allowlists]]
name = "allow-{rule_id}"
rule_ids = ["{rule_id}"]
methods = ["{method}"]
routes = ["{route}"]
path_prefixes = ["{path}"]
reason = "confirmed false positive for {rule_name}"
"#
    ));
  } else {
    report
      .suggestions
      .push("Temporarily pin the rule to monitor mode while validating the exception.".to_string());
    report
      .suggestions
      .push("Prefer a narrow condition exception over disabling the rule globally.".to_string());
    report.toml_patch = Some(format!(
      r#"# Candidate native OxiRule tuning for {rule_name}
# Option A: set the matching rule to monitor during validation.
mode = "monitor"

# Option B: narrow the condition.
# when = "({{existing_condition}}) && !(Request.Http.Method == '{method}' && Request.Http.Path.startsWith('{path}'))"
"#
    ));
  }
  report
}

struct BuiltTemplate {
  name: &'static str,
  description: &'static str,
  variables: &'static [&'static str],
  content: &'static str,
}

const OXIRULE_TEMPLATES: &[BuiltTemplate] = &[
  BuiltTemplate {
    name: "vaultwarden",
    description: "Protect Vaultwarden admin and login surfaces.",
    variables: &["admin_cidr"],
    content: r#"name = "vaultwarden-admin-guard"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin') && !Request.Client.Ip.inCidr('{{admin_cidr}}')"

[[actions]]
type = "reject"
status = 403
body = "Forbidden"
"#,
  },
  BuiltTemplate {
    name: "gitea",
    description: "Block public access to Gitea admin paths.",
    variables: &["admin_cidr"],
    content: r#"name = "gitea-admin-guard"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/admin') && !Request.Client.Ip.inCidr('{{admin_cidr}}')"

[[actions]]
type = "reject"
status = 403
"#,
  },
  BuiltTemplate {
    name: "nextcloud",
    description: "Reduce common Nextcloud scanner noise.",
    variables: &[],
    content: r#"name = "nextcloud-scanner-noise"
phase = "request"
priority = 120
when = "Request.Http.Path.matches('(?i)(/wp-admin|/\\.env|/vendor/phpunit)')"

[[actions]]
type = "reject"
status = 404
body = "Not Found"
"#,
  },
  BuiltTemplate {
    name: "generic-login",
    description: "Rate-limit generic login attempts by client IP and path.",
    variables: &["rate"],
    content: r#"name = "generic-login-rate-limit"
phase = "request"
priority = 200
when = "Request.Http.Path.matches('(?i)(/login|/signin|/session)')"

[[actions]]
type = "rate_limit"
name = "login"
key = "client_ip_path"
rate = "{{rate}}"
burst = 5
status = 429
body = "Too Many Requests"
"#,
  },
  BuiltTemplate {
    name: "admin-path",
    description: "Allow admin paths only from a trusted CIDR.",
    variables: &["path_prefix", "admin_cidr"],
    content: r#"name = "admin-path-allowlist"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('{{path_prefix}}') && !Request.Client.Ip.inCidr('{{admin_cidr}}')"

[[actions]]
type = "reject"
status = 403
body = "Forbidden"
"#,
  },
];

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
  value
    .get(key)
    .and_then(serde_json::Value::as_str)
    .map(str::to_string)
}
