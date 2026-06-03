//! CRS compatibility reporting.
//! Reports are descriptive so unsupported syntax does not silently change enforcement.

use serde::Serialize;

pub(super) const SUPPORTED_CRS_CURRENT_VERSION: &str = "v4.25.0";
pub(super) const SUPPORTED_CRS_LTS_LINE: &str = "v4.25.x";
pub(super) const COMPATIBILITY_AS_OF: &str = "2026-05-10";

pub(super) const SUPPORTED_DIRECTIVES: &[&str] = &["SecAction", "SecMarker", "SecRule"];

pub(super) const ACCEPTED_IGNORED_DIRECTIVES: &[&str] = &[
  "SecComponentSignature",
  "SecDefaultAction",
  "SecRuleRemoveById",
  "SecRuleRemoveByMsg",
  "SecRuleRemoveByTag",
  "SecRuleUpdateActionById",
  "SecRuleUpdateTargetById",
  "SecRuleUpdateTargetByMsg",
  "SecRuleUpdateTargetByTag",
];

pub(super) const SUPPORTED_OPERATORS: &[&str] = &[
  "rx",
  "contains",
  "containsWord",
  "beginsWith",
  "endsWith",
  "streq",
  "pm",
  "eq",
  "ge",
  "gt",
  "le",
  "lt",
  "detectSQLi",
  "detectXSS",
  "unconditionalMatch",
  "validateUrlEncoding",
  "validateUtf8Encoding",
];

pub(super) const SUPPORTED_TRANSFORMS: &[&str] = &[
  "none",
  "lowercase",
  "urlDecode",
  "urlDecodeUni",
  "normalizePath",
  "normalizePathWin",
  "removeNulls",
  "replaceNulls",
  "compressWhitespace",
  "removeWhitespace",
  "trim",
  "trimLeft",
  "trimRight",
  "htmlEntityDecode",
  "jsDecode",
  "cssDecode",
  "cmdLine",
  "utf8toUnicode",
];

pub(super) const SUPPORTED_VARIABLES: &[&str] = &[
  "REQUEST_URI",
  "REQUEST_URI_RAW",
  "REQUEST_FILENAME",
  "REQUEST_BASENAME",
  "REQUEST_METHOD",
  "REQUEST_PROTOCOL",
  "REQUEST_HEADERS",
  "REQUEST_HEADERS_NAMES",
  "ARGS",
  "ARGS_GET",
  "QUERY_STRING",
  "REQUEST_COOKIES",
  "REQUEST_BODY",
  "RESPONSE_STATUS",
  "RESPONSE_PROTOCOL",
  "RESPONSE_HEADERS",
  "RESPONSE_HEADERS_NAMES",
  "RESPONSE_BODY",
  "MATCHED_VAR",
  "TX",
];

pub(super) const SUPPORTED_ACTION_KEYS: &[&str] =
  &["id", "phase", "msg", "tag", "skipAfter", "setvar", "t"];

pub(super) const ACCEPTED_IGNORED_ACTION_KEYS: &[&str] = &[
  "accuracy",
  "ctl",
  "expirevar",
  "initcol",
  "logdata",
  "maturity",
  "rev",
  "sanitiseArg",
  "setuid",
  "severity",
  "status",
  "ver",
];

pub(super) const ACCEPTED_IGNORED_BARE_ACTIONS: &[&str] = &[
  "append",
  "auditlog",
  "block",
  "capture",
  "deny",
  "log",
  "multiMatch",
  "noauditlog",
  "nolog",
  "pass",
  "prepend",
];

pub(super) fn is_accepted_ignored_directive(raw: &str) -> bool {
  ACCEPTED_IGNORED_DIRECTIVES
    .iter()
    .any(|directive| raw.starts_with(directive))
}

pub(super) fn is_supported_action_key(key: &str) -> bool {
  SUPPORTED_ACTION_KEYS.contains(&key)
}

pub(super) fn is_accepted_ignored_action_key(key: &str) -> bool {
  ACCEPTED_IGNORED_ACTION_KEYS.contains(&key)
}

pub(super) fn is_accepted_ignored_bare_action(action: &str) -> bool {
  ACCEPTED_IGNORED_BARE_ACTIONS.contains(&action)
}

#[derive(Debug, Clone, Serialize)]
pub struct CrsCompatibilityMatrix {
  pub compatibility_as_of: &'static str,
  pub release_lines: Vec<CrsReleaseLine>,
  pub unsupported_directive_policy: &'static str,
  pub supported: CrsSupportedSyntax,
  pub accepted_but_ignored: CrsAcceptedIgnoredSyntax,
  pub known_unsupported: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrsReleaseLine {
  pub name: &'static str,
  pub version: &'static str,
  pub status: &'static str,
  pub notes: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrsSupportedSyntax {
  pub directives: Vec<&'static str>,
  pub operators: Vec<&'static str>,
  pub transforms: Vec<&'static str>,
  pub variables: Vec<&'static str>,
  pub action_keys: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrsAcceptedIgnoredSyntax {
  pub directives: Vec<&'static str>,
  pub action_keys: Vec<&'static str>,
  pub bare_actions: Vec<&'static str>,
}

pub fn compatibility_matrix() -> CrsCompatibilityMatrix {
  CrsCompatibilityMatrix {
    compatibility_as_of: COMPATIBILITY_AS_OF,
    release_lines: vec![
      CrsReleaseLine {
        name: "current",
        version: SUPPORTED_CRS_CURRENT_VERSION,
        status: "targeted",
        notes: "Current CRS release target for the OxiBelt compatibility surface.",
      },
      CrsReleaseLine {
        name: "lts",
        version: SUPPORTED_CRS_LTS_LINE,
        status: "targeted",
        notes: "CRS 4 LTS line used as the stable production baseline.",
      },
    ],
    unsupported_directive_policy: "fail_closed",
    supported: CrsSupportedSyntax {
      directives: SUPPORTED_DIRECTIVES.to_vec(),
      operators: SUPPORTED_OPERATORS.to_vec(),
      transforms: SUPPORTED_TRANSFORMS.to_vec(),
      variables: SUPPORTED_VARIABLES.to_vec(),
      action_keys: SUPPORTED_ACTION_KEYS.to_vec(),
    },
    accepted_but_ignored: CrsAcceptedIgnoredSyntax {
      directives: ACCEPTED_IGNORED_DIRECTIVES.to_vec(),
      action_keys: ACCEPTED_IGNORED_ACTION_KEYS.to_vec(),
      bare_actions: ACCEPTED_IGNORED_BARE_ACTIONS.to_vec(),
    },
    known_unsupported: vec![
      "Full ModSecurity exclusion syntax is not implemented; use OxiBelt-native waf.crs rule_overrides and allowlists.",
      "Multipart body parsing is not CRS-compatible in this MVP; bounded body prefix inspection is used.",
      "WebTransport frame and datagram payload inspection is not supported.",
      "Unsupported CRS directives, operators, transforms, variables, or actions fail closed during compile.",
    ],
  }
}
