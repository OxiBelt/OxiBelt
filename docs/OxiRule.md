# OxiRule WAF Reference

Status: Draft
Target project: OxiBelt Rust-based reverse proxy

OxiRule is OxiBelt's CEL-like, declarative WAF rule model. For proxy behavior and runtime scope, see [Specification.md](Specification.md). For TOML placement and WAF limits, see [Configuration.md](Configuration.md). For a larger cookbook of practical rules, see [example/OxiRule.md](example/OxiRule.md).

## Rule Model

An OxiRule rule has:

- Metadata: `name`, optional `id`, optional `tags`, optional `mode`, `phase`, and `priority`.
- A side-effect-free boolean condition in `when`, reusable `groups`, or an external rule `path`.
- One or more declarative `actions`.

Basic inline rule:

```toml
[[waf.rules]]
name = "block-admin-from-public"
id = "block-admin-public"
tags = ["access-control", "admin"]
mode = "monitor"
phase = "request"
priority = 100
when = """
Request.Http.Path.startsWith('/admin') &&
!Request.Client.Ip.inCidr('10.0.0.0/8')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

The effective condition must evaluate to `Bool`. If it evaluates to `false`, the rule is skipped and no action from that rule executes.

Public rule `id` values are optional but must be unique when non-empty. `id` and entries in `tags` must match `[A-Za-z0-9-]{0,32}`. OxiBelt also assigns each compiled rule an internal runtime UUID for diagnostics; that UUID is not configured and is not stable across restarts.

Rule `mode` is optional and defaults to `[waf].mode`. A `monitor` rule counts and logs matches without applying actions. An `enforcing` rule applies actions normally, even when the global WAF mode is `monitor`.

Rule metadata tags are available through `Context.RuleTags`. Transaction tags created by actions such as `set_tag` and `require_person_proof.success_tag` are available through `Request.Tags`.

## Attachment and Files

Rules may be attached globally:

```toml
[[waf.rules]]
name = "global-request-policy"
phase = "request"
priority = 10
path = "rules/global-request.oxirule.toml"
```

Or on a route:

```toml
[[routes.waf.rules]]
name = "api-large-body-guard"
phase = "request"
priority = 100
when = "Request.Http.Method == 'POST' && Request.Http.Body.Size > 1048576"

[[routes.waf.rules.actions]]
type = "reject"
status = 413
body = "Payload Too Large"
```

A rule entry may specify `when`, `groups`, or both. External rule entries use `path`, and `path` cannot be combined with inline `when`, `merge_condition_as`, `groups`, or `actions` on the same rule entry.

External rule files resolve under the configured OxiRule directory. Absolute paths and paths containing `.` or `..` components are rejected. An external `.oxirule.toml` file contains only the rule body:

```toml
when = "Request.Headers.anyValueContains('sqlmap')"

[[actions]]
type = "reject"
status = 403
body = "Blocked by WAF"
```

External rule files may also define file-local rule groups. Because TOML keys after an array table belong to that table, place root-level `groups`, `when`, `merge_condition_as`, and `[[actions]]` before `[[rule_groups]]` definitions:

```toml
groups = ["scanner"]

[[actions]]
type = "reject"
status = 403

[[rule_groups]]
name = "scanner"
when = "Request.Headers.anyValueMatches('(?i)(sqlmap|nikto)')"
```

Pattern sets are configured globally and referenced by helper functions:

```toml
[[waf.pattern_sets]]
name = "xss-regexes"
kind = "regex"
patterns = ["(?i)<script", "(?i)javascript:"]
```

Supported pattern set kinds are `contains` and `regex`.

Bounded user-defined functions can be configured globally or per route:

```toml
[[waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.lowerAscii().contains('/wp-admin')"

[[routes.waf.functions]]
name = "is_bad_path"
params = ["path"]
expression = "path.startsWith('/admin')"
```

Functions are expression-valued helpers evaluated inside the same OxiRule sandbox and budgets as the calling rule. Function names and parameters must be valid OxiRule identifiers, cannot use reserved keywords or top-level objects such as `Request`, `Response`, `Stream`, `Context`, or `DynamicPolicy`, and cannot repeat parameter names. Function bodies may return any existing OxiRule value; rule `when` expressions still must evaluate to `Bool`.

Functions may call other functions when the call graph is acyclic. Global rules can call only global functions. Route rules can call global functions plus functions declared under that route; route functions override same-named global functions for that route. Global function bodies always resolve nested calls against global functions only, while route function bodies resolve against the route override set plus globals. Function bodies are phase-validated at call sites: a function that reads `Response` is valid only from response-phase expressions, and a function that reads `Stream` is valid only from stream-phase expressions. Rules that pass `Request.Body` or `Response.Body` into a function still trigger bounded body inspection when the callee, including nested callees, reads body content. Function definitions are allowed in TOML configuration only; external `.oxirule.toml` rule files remain rule-body-only.

## Rule Groups

Rule groups bundle reusable condition fragments and actions. Define global groups under `[[waf.rule_groups]]`, route-local groups under `[[routes.waf.rule_groups]]`, external file-local groups under `[[rule_groups]]` inside an external `.oxirule.toml` file, or shared group files referenced by `[waf] rule_group_files` and route-level `rule_group_files`. Shared group files use a top-level `[[rule_groups]]` array, resolve under the OxiRule directory, and use the same group fields as inline TOML groups. Exact paths must exist; glob entries may match zero files and are loaded in sorted order.

```toml
[[waf.rule_groups]]
name = "bot-defense"
phase = "request"
tags = ["automation", "malicious-intelligence"]
when = "Request.Headers.anyValueMatches('(?i)(sqlmap|nikto)')"
merge_condition_as = "and"

[[waf.rule_groups.conditions]]
label = "prompt-injection-query"
when = "Request.Http.Query.promptInjectionScore() >= 35"
merge_condition_as = "or"

[[waf.rule_groups.actions]]
priority = 10
type = "set_tag"
key = "BotDefense"
value = "matched"

[[waf.rules]]
name = "block-bot-defense"
phase = "request"
priority = 100
groups = ["bot-defense"]
when = "!Request.Client.Ip.inCidr('10.0.0.0/8')"
merge_condition_as = "and"

[[waf.rules.actions]]
priority = 20
type = "reject"
status = 403
```

Group lookup order is external file-local, then route-local, then global. External groups are visible only inside the external rule file that defines them. Rule execution order is still controlled by the referencing rule's `priority`.

Condition fragments are processed in `groups` array order, followed by the rule's own `when`. A group-level `when` is shorthand for one condition fragment; `[[conditions]]` adds labeled condition fragments in declaration order. `merge_condition_as` accepts `and`, `or`, or `override` and defaults to `and`; each fragment's value controls how that fragment joins the previous accumulated condition. If `override` appears, it may appear only once across the referenced groups plus rule, and the effective condition is exactly that fragment's `when`.

Group `phase` is optional. When set, only rules with the same phase may reference the group; mismatches fail closed at configuration load. Group `tags` are metadata for analysis, rulepack authorship, and documentation and must use the same label shape as rule tags.

Actions from referenced groups and the rule are collected, sorted by action `priority` with lower values first, and executed in stable declaration order for equal priorities. Action `priority` defaults to `0`. Terminal actions still stop later actions after sorting.

## Rulepacks

Rulepacks package OxiRule rules and shared group files into a manifest that can be loaded from `[waf] rulepack_files` or route-level `rulepack_files`. A rulepack manifest must end with `.oxirule-rulepack.toml`. OxiBelt supports rulepack schema version `2` only; older schema versions fail validation.

```toml
[rulepack]
schema_version = 2
name = "generic-login"
version = "0.1.0"
default_mode = "monitor"
targets = ["generic-login"]
requires = []

[[variables]]
name = "login_path"
type = "string"
default = "/login"

[[variables]]
name = "login_rate"
type = "rate"
default = "5r/m"

[[rules]]
name = "generic-login-rate-limit"
phase = "request"
priority = 100
content = '''
when = "Request.Http.Path == '{{login_path}}'"

[[actions]]
type = "rate_limit"
name = "login"
key = "client_ip_path"
rate = "{{login_rate}}"
burst = 5
status = 429
'''
```

Each `[[rules]]` entry declares the rule metadata and uses either inline `content` or `path = "rules/name.oxirule.toml"`. Each `[[group_files]]` entry uses either inline `content` or `path = "groups/name.oxirule-group.toml"`. Referenced paths resolve under the OxiRule directory and must stay normalized relative paths. `default_mode` defaults to `monitor`; rule-level `mode` overrides it.

Use `oxibeltctl rulepack inspect`, `render`, `check`, `fit`, `plan`, `diff`, and `apply` to work with local files, directories, HTTPS bundles, or `git+https://` repositories. URL installs verify transport and trust before UTF-8/TOML parsing, rendering, route fitting, planning, diffing, or apply. HTTPS rulepacks may be installed unsigned, but `apply`, `plan`, `diff`, and `apply --dry-run` still require `--sha256` unless `--allow-unpinned-rulepack` is set. A valid detached OpenPGP signature from a locally trusted public key also satisfies the apply pin. HTTP rulepacks additionally require `--allow-insecure-rulepack-url` and a valid detached OpenPGP signature; `--sha256` and `--allow-unpinned-rulepack` do not bypass that signature requirement. `git+https://` installs require `--git-ref` and record the resolved commit in the installed manifest.

```bash
oxibeltctl rulepack apply \
  --url https://packs.example.test/vaultwarden.oxirule-rulepack.toml \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

oxibeltctl rulepack apply \
  --url https://packs.example.test/vaultwarden.oxirule-rulepack.toml \
  --rulepack-openpgp-signature-url https://packs.example.test/vaultwarden.oxirule-rulepack.toml.sig \
  --rulepack-openpgp-keyring /etc/oxibelt/oxirule/trusted-rulepack-publishers

oxibeltctl rulepack apply \
  --url http://packs.internal/vaultwarden.oxirule-rulepack.toml \
  --allow-insecure-rulepack-url \
  --rulepack-openpgp-signature-url http://packs.internal/vaultwarden.oxirule-rulepack.toml.sig \
  --rulepack-openpgp-keyring /etc/oxibelt/oxirule/trusted-rulepack-publishers

oxibeltctl rulepack apply \
  --url https://packs.example.test/vaultwarden.oxirule-rulepack.toml \
  --rulepack-openpgp-signature-file vaultwarden.oxirule-rulepack.toml.sig \
  --rulepack-openpgp-key publisher.asc \
  --rulepack-openpgp-fingerprint 0123456789abcdef0123456789abcdef01234567
```

OpenPGP trust uses public keys only. `--rulepack-openpgp-key FILE` adds repeatable per-command trusted public keys. `--rulepack-openpgp-keyring DIR` adds repeatable trust-store directories. If no explicit trust material is supplied, `oxibeltctl` checks `OXIBELT_RULEPACK_OPENPGP_KEYRING_DIR`, then `/etc/oxibelt/oxirule/trusted-rulepack-publishers` when that directory exists. Fingerprint pins must be full 40- or 64-character hex OpenPGP fingerprints. Rulepack and signature URLs must not include usernames or passwords; use `--rulepack-token-env` for bearer auth. That token is sent to the signature URL only when it has the same scheme, host, and port as the rulepack URL.

When a URL rulepack is rendered for install, OxiBelt records optional `[rulepack]` provenance fields in the installed manifest: `source_url`, `source_sha256`, `source_openpgp_signature_url`, and `source_openpgp_signer_fingerprint`. URLs are sanitized before recording.

Remote catalogs are a discovery layer over the same URL install path. `oxibeltctl rulepack repo add NAME URL` records a catalog index URL in `${OXIBELT_RULEPACK_REPOS_FILE}` when set, otherwise `${XDG_CONFIG_HOME:-$HOME/.config}/oxibelt/rulepack-repos.toml`. The registry stores repo URLs, CA certificate paths, token environment variable names, insecure-URL opt-ins, and OpenPGP trust settings; it never stores bearer token values. Catalog repo tokens are forwarded to catalog-selected rulepack source URLs only when the source URL uses the same scheme, host, and port as the catalog repo URL.

Catalog indexes may be TOML or JSON. TOML indexes use this shape:

```toml
[index]
schema_version = 1
generated_at = "2026-06-14T00:00:00Z"

[[rulepacks]]
name = "vaultwarden-hardening"
version = "0.3.0"
targets = ["vaultwarden", "bitwarden-rs"]
source = "https://packs.example.test/vaultwarden/0.3.0/rulepack.oxirule-rulepack.toml"
sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
signature_type = "openpgp"
signature = "https://packs.example.test/vaultwarden/0.3.0/rulepack.sig"
min_oxibelt_version = "0.0.0"
license = "Apache-2.0"
maintainers = ["example-security"]
description = "Protect Vaultwarden admin and login surfaces."
```

`source` must be an HTTPS `.oxirule-rulepack.toml` URL unless the repo was added with `--allow-insecure-rulepack-url`; HTTP rulepack sources still require a valid detached OpenPGP signature during install. `sha256` is required for every catalog entry and is passed to the existing URL verifier. `signature_type` may only be `openpgp` in this release, and `signature` is passed to `--rulepack-openpgp-signature-url`. Sigstore and SLSA provenance are reserved for a later catalog schema.

`min_oxibelt_version`, when present, must be strict SemVer. Official releases
and clean exact-tag builds compare that minimum with their verified
compatibility version. Untagged Git, dirty, and source-archive builds have no
verified compatibility version and reject every catalog entry that declares a
minimum, including `0.0.0`, with a diagnostic recommending an official or
clean exact-tag build. Catalog entries without `min_oxibelt_version` remain
eligible. This fail-closed rule prevents Cargo's `0.0.0` sentinel or an
arbitrary development commit from impersonating a compatible release.

```bash
oxibeltctl rulepack repo add official https://packs.example.test/index.toml \
  --rulepack-openpgp-keyring /etc/oxibelt/oxirule/trusted-rulepack-publishers
oxibeltctl rulepack search vaultwarden
oxibeltctl rulepack info vaultwarden-hardening
oxibeltctl rulepack install vaultwarden-hardening --interactive --dry-run
oxibeltctl rulepack install vaultwarden-hardening --interactive
oxibeltctl rulepack update --plan
```

`rulepack install` resolves the selected catalog entry into the same inputs as `rulepack apply --url`, so `--values`, `--bind`, `--var`, `--profile`, `--mode`, `--force-mode`, `--interactive`, `--dry-run`, `--fixture`, and `--replay` keep their normal behavior. Catalog-installed manifests must still be schema version `2`; schema version `1`, `type = "route"` under `[[variables]]`, and legacy `[variables.discovery]` are rejected.

Route bindings separate local OxiBelt objects from general render variables. Use an explicit `[[bindings]]` entry to declare the object to discover and the placeholder it renders into. Scalar values stay in `[[variables]]`; route names and other environment objects are supplied with `--bind`.

```toml
[rulepack]
schema_version = 2
name = "vaultwarden-hardening"
version = "0.1.0"
targets = ["vaultwarden"]
default_mode = "monitor"

[[variables]]
name = "admin_cidr"
type = "cidr"
required = true
prompt = "Trusted CIDR allowed to access /admin."

[[variables]]
name = "login_rate"
type = "rate"
default = "5r/m"

[[bindings]]
name = "app_route"
kind = "route"
bind_as = "route_name"
required = true
prompt = "Select the route that points to Vaultwarden."

[bindings.discovery]
name_any = ["vaultwarden", "bitwarden", "vault", "secret"]
host_contains_any = ["vaultwarden", "bitwarden", "vault"]
upstream_contains_any = ["vaultwarden", "bitwarden"]
path_prefix_any = ["/"]

[[profiles]]
name = "public-production"
mode = "enforcing"

[profiles.values]
login_rate = "10r/m"
```

The `bind_as` value names the render placeholder, so `--bind app_route=mmsecretvault` renders `{{route_name}}`. It must not collide with a scalar variable name or another binding target. OxiBelt rulepacks are schema version `2` only. Schema version `1`, `type = "route"` under `[[variables]]`, and legacy `[variables.discovery]` are rejected by render, check, fit, plan, diff, apply, and apply dry-run; use `[[bindings]]` instead.

Values files let operators keep local route bindings, scalar values, and rollout profile choices outside the remote rulepack:

```toml
[bindings]
app_route = "mmsecretvault"

[values]
admin_cidr = "10.10.0.0/16"
login_rate = "10r/m"

[overrides]
profile = "public-production"
mode = "enforcing"
force_mode = true

[[exceptions]]
name = "allow-healthcheck-login-preflight"
rule_ids = ["vaultwarden-login"]
routes = ["mmsecretvault"]
methods = ["GET"]
path_prefixes = ["/identity/accounts/prelogin"]
source_cidrs = ["10.20.0.0/16"]
reason = "internal synthetic healthcheck"
expires_at = "2999-07-01T00:00:00Z"
```

Only `[bindings]`, `[values]`, `[overrides]`, `[[rule_overrides]]`, and `[[exceptions]]` are accepted. Binding and value entries must be strings. `[overrides] profile` selects a declared `[[profiles]]` entry, `mode` may be `monitor` or `enforcing`, and `force_mode = true` pins every rule to the effective mode. Precedence is `[[variables]] default` < selected profile values/mode < values file < CLI `--bind`, `--var`, `--profile`, `--mode`, and `--force-mode`. Without an explicit profile or mode override, `rulepack apply` still installs in `monitor` mode.

Rulepack schema version `2` also supports typed rule overrides. Manifest `[[overrides]]` entries are rulepack-authored defaults; values-file `[[rule_overrides]]` entries are local operator overlays kept outside the remote rulepack. Override selectors must set exactly one selector kind: `rulepack`, `tags`, `rule_id`, or `rule_name`. Tag selectors match any listed tag. Precedence is manifest rulepack < manifest tag < manifest rule < local rulepack < local tag < local rule, and later entries in the same tier win.

```toml
[[overrides]]
selector = { rulepack = "vaultwarden-hardening" }
mode = "monitor"

[[overrides]]
selector = { tags = ["surface:login"] }
mode = "enforcing"

[[overrides]]
selector = { rule_id = "oxibelt.vaultwarden.admin_guard" }
mode = "enforcing"
priority = 90
```

Values files use `[[rule_overrides]]` so they do not collide with the existing `[overrides]` table for profile and install mode:

```toml
[[rule_overrides]]
selector = { rule_name = "vaultwarden-login-rate-limit" }
action = { type = "rate_limit", name = "vaultwarden-login" }
rate = "10r/m"
burst = 10
status = 429
body = "Too Many Requests"
```

Supported rule fields are `mode`, `priority`, and `enabled`. Setting `enabled = false` removes the matched rule from the rendered install manifest. Supported action fields are `rate`, `burst`, `status`, and `body`; action overrides require an `action` selector and must match exactly one action in each matched rule. `rate_limit` action overrides require `action.name`; terminal actions such as `reject`, `replace_response`, and `reject_response` may use a type-only selector when that action type is unique in the rule. Overrides do not support raw content replacement, regex patching, arbitrary scripts, callbacks, or exception predicates.

Rulepack `[[exceptions]]` provide narrow false-positive tuning without disabling a whole rule. They may live in the source manifest or in a values file. Select rules with `rule_ids`, `rule_names`, or `tags`; at least one rule selector is required. Scope traffic with `routes`, `methods`, `path_prefixes`, or `source_cidrs`; at least one traffic selector is required. Categories are ANDed together, while values within one category are ORed. Matching active exceptions add a negative predicate to the rendered rule condition. `reason` is required, and `expires_at` must use strict UTC `YYYY-MM-DDTHH:MM:SSZ`; expired exceptions are ignored and logged, while future-dated exceptions stop matching requests once `expires_at` is reached without requiring a reload. Header, body, raw regex, and stream-phase exception selectors are not supported.

`oxibeltctl rulepack fit` reads the redacted effective config from Admin `/admin/v1/config/effective`, scores route candidates from route names, hosts, upstream names, redacted upstream origins, and path prefixes, then prints missing bindings and scalar variables as JSON. `oxibeltctl rulepack plan`, `rulepack diff`, and `rulepack apply --dry-run` reuse that fitting data, render the intended install artifact, and print a non-mutating `RulepackPreinstallReport`. `oxibeltctl rulepack apply --interactive` uses the same data to prompt for unresolved route bindings and required variables before applying a rendered manifest through `/admin/v1/files/sync`; `apply --interactive --dry-run` may prompt for missing inputs, but it does not ask for final install approval. Noninteractive `render`, `check`, `plan`, `diff`, and `apply` can pass bindings and values explicitly or through `--values`:

```sh
oxibeltctl rulepack fit --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml
oxibeltctl rulepack plan --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml
oxibeltctl rulepack diff --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml
oxibeltctl rulepack check --file vaultwarden.oxirule-rulepack.toml --bind app_route=mmsecretvault --var admin_cidr=10.0.0.0/8
oxibeltctl rulepack render --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml --profile public-production
oxibeltctl rulepack apply --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml --dry-run
oxibeltctl rulepack apply --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml --dry-run --fixture fixture.json --replay captured.ndjson
oxibeltctl rulepack apply --file vaultwarden.oxirule-rulepack.toml --bind app_route=mmsecretvault --var admin_cidr=10.0.0.0/8
oxibeltctl rulepack apply --file vaultwarden.oxirule-rulepack.toml --values vaultwarden.values.toml
oxibeltctl rulepack apply --file vaultwarden.oxirule-rulepack.toml --interactive
```

The preinstall report contains `install_plan`, `diff`, `risk`, `warnings`, `route_candidates`, `missing_bindings`, `missing_variables`, and `suggested_command`. In complete reports, `install_plan.will_put` lists the exact OxiRule-relative files that would be written, `will_reload` is `oxirule`, and the report includes the effective mode, selected profile, bindings, values count, and source/provenance summary. Incomplete reports leave `diff` empty and include route candidates plus a suggested command for the missing bindings or scalar values.

`rulepack diff` prefers `/admin/v1/waf/rulepacks/plan` for config-aware reports. When it falls back to active `/admin/v1/waf/rulepacks` summaries, a new install reports exact `added_rules`, `changed_rules = 0`, `deleted_rules = 0`, and `basis = "new_install"`. A same-name active rulepack reports count deltas from the active summary, sets `changed_rules = null`, and uses `basis = "active_summary"`.

`risk` reports terminal action types derived from rendered rule TOML, static request/response body inspection needs, cost warnings from the Admin OxiRule devtool when available, optional fixture results, optional replay results, and an estimated cost of `low` or `medium`. `--fixture FILE` and `--replay FILE` are valid only with `apply --dry-run`. Dry-run prints the report and exits before fetching an apply ETag, sending `/admin/v1/files/sync`, or verifying active installation.

Installed manifests contain concrete rendered rule content and do not require source `[[bindings]]` or `[[profiles]]` metadata at runtime. Direct runtime loading rejects source manifests that still declare unresolved required bindings; render, plan, diff, dry-run, or apply them with `--bind` first. `rulepack apply` also writes `rulepacks/{name}.install.toml` under the OxiRule directory with the selected profile, effective mode, source/provenance fields, bindings, values, local rule overrides, and local exceptions. The install lockfile is metadata only and is not loaded as an executable rulepack.

`oxibeltctl rulepack adapt` is a local import helper for foreign WAF ecosystem inputs. It does not install policy, contact Admin APIs, fetch remote rulepacks, or execute external adapter binaries. The first adapter, `modsecurity-crs-exclusion`, converts a narrow subset of ModSecurity CRS exclusion directives into OxiBelt-native CRS tuning TOML:

```sh
oxibeltctl rulepack adapt \
  --adapter modsecurity-crs-exclusion \
  --input exclusions.conf \
  --route app-root \
  --method POST \
  --output crs-tuning.toml
```

Supported input is limited to `SecRuleRemoveById`, `SecRuleRemoveByTag`, `SecRuleRemoveByMsg`, and literal `<Location "/prefix">` blocks. Scoped exclusions emit `[[waf.crs.allowlists]]`; unscoped exclusions fail closed unless `--allow-global-disable` is set, in which case they emit `[[waf.crs.rule_overrides]] mode = "disabled"`. Unsupported ModSecurity updates, `ctl:ruleRemove*`, regex `LocationMatch`, rule ID ranges, scripts, callbacks, and ambiguous path scopes are rejected. Adapters do not change the native rulepack format: OxiBelt rulepack manifests remain schema version `2` only, and schema version `1`, `[variables.discovery]`, and `[[variables]] type = "route"` stay rejected.

## Development Tools

OxiBelt includes local and Admin API OxiRule development tools for validating and exercising rules before writing or applying them.

Local CLI:

```sh
oxibelt --config source/config/oxibelt.toml oxirule check --rule rules/block.oxirule.toml
oxibelt --config source/config/oxibelt.toml oxirule test --rule rules/block.oxirule.toml --fixture '{"request":{"uri":"/admin"}}'
oxibelt --config source/config/oxibelt.toml oxirule explain --rule rules/block.oxirule.toml --fixture fixture.json
oxibelt --config source/config/oxibelt.toml oxirule cost --rule rules/block.oxirule.toml
oxibelt --config source/config/oxibelt.toml oxirule replay --rule rules/block.oxirule.toml --input captured.ndjson
oxibelt oxirule template list
oxibelt oxirule template render --name admin-path --var path_prefix=/admin --var admin_cidr=10.0.0.0/8
oxibelt oxirule false-positive --finding finding.json
```

The matching Admin API endpoints live under `/admin/v1/waf/oxirule/*` and are synchronous and stateless. They accept inline candidate OxiRule content plus optional inline OxiRule group content, compile it against the active configuration context, and return JSON fields such as `ok`, `diagnostics`, `matched_rules`, `actions`, `terminal`, `mutations`, `tags`, `stream_close`, `body_need`, `cost_warnings`, and `explain_steps`. Candidate-only requests with `include_active_rules = false` do not include active WAF rules or rule groups in the evaluation context. The API does not write files or install rules; use `POST /admin/v1/files/sync` for deployment.

`POST /admin/v1/waf/oxirule/analyze` accepts a fixture and returns local risk summaries for URI, path, query, header, body, response body, or stream payload surfaces. `POST /admin/v1/waf/oxirule/hardening-plan` renders non-mutating TOML suggestions for malicious-intelligence, prompt-injection, malformed payload, and suspicious automation defenses. These endpoints do not call external LLMs or classifiers and do not deploy policy; write the returned TOML through file sync when it is ready to apply.

Fixtures can target request, response, or stream phase. Stream fixtures evaluate the rule engine's `WafStreamInput` shape for WebSocket/WebTransport metadata and payloads; they do not create live upgraded sessions. Replay accepts uploaded NDJSON fixture lines and does not read server-side log files.

Built-in templates are `vaultwarden`, `gitea`, `nextcloud`, `generic-login`, and `admin-path`. The false-positive planner returns suggested TOML for CRS allowlists/rule overrides or native OxiRule monitor/condition tuning without mutating configuration.

## CRS Compatibility

OxiBelt can run a CRS-compatible WAF layer alongside OxiRule rules:

```toml
[waf.crs]
enabled = true
mode = "monitor" # monitor | enforcing
setup_file = "crs/crs-setup.conf"
rule_files = ["crs/rules/*.conf"]
paranoia_level = 1
inbound_anomaly_score_threshold = 5
outbound_anomaly_score_threshold = 4
unsupported_directive_policy = "fail_closed"
```

CRS files resolve under the OxiRule directory and must use normalized relative paths or globs. The CRS layer supports request/response phases 1, 2, 3, and 4, CRS-style `tx` variables, macro expansion, `setvar`, chained rules, paranoia-level tags, transforms used by the supported CRS v4.x surface, and anomaly scoring. CRS validation operators such as `@validateUrlEncoding` and `@validateUtf8Encoding` follow CRS detection semantics by matching malformed encodings. Unsupported CRS syntax fails closed during configuration load/compile and includes file/line context.

CRS `monitor` mode records rule hits and latest inbound/outbound anomaly summaries through `/admin/v1/waf/rule-hits` without blocking. CRS `enforcing` mode blocks requests with `403` when the inbound blocking threshold is met and suppresses blocked upstream response bodies with a `502` response when the outbound blocking threshold is met. Prometheus metrics intentionally do not expose CRS rule IDs, names, or tags as labels.

The CRS compatibility matrix is available at `GET /admin/v1/waf/crs/compatibility` for principals allowed to use `waf:GetCrsCompatibility`. It returns the targeted CRS release lines, currently including CRS `v4.25.0` and the `v4.25.x` LTS line as of 2026-05-10, plus supported directives, operators, transforms, variables, action syntax, accepted-but-ignored syntax, and known unsupported surfaces.

OxiBelt-native CRS tuning is configured under `[waf.crs]`:

```toml
[[waf.crs.rule_overrides]]
name = "monitor-sqli-rule"
rule_ids = ["942100"]
tags = ["attack-sqli"]
mode = "monitor" # enforcing | monitor | disabled
reason = "known application false positive"

[[waf.crs.allowlists]]
name = "allow-editor-html"
rule_ids = ["941320"]
methods = ["POST"]
routes = ["app-root"]
path_prefixes = ["/editor/"]
reason = "editor intentionally submits HTML"
```

Rule selectors match by `rule_ids`, `tags`, or `msg_contains`; at least one selector is required. Allowlists also require a traffic selector. Traffic selector categories are ANDed together, and values within one category are ORed. Scope allowlists with `methods`, `routes`, or `path_prefixes`; `header_equals` is rejected because inbound request headers are client-controlled before proxy forwarding. A matching allowlist suppresses CRS scoring/actions for that transaction, increments `tuned_hits`, and leaves the original hit visible for review. `rule_overrides` are for broader per-rule policy changes: `monitor` observes without contributing to blocking score, `enforcing` can enforce under global monitor mode, and `disabled` records hits without scoring/actions.

Use `oxibeltctl rulepack adapt --adapter modsecurity-crs-exclusion` when importing existing ModSecurity CRS exclusion snippets. Review the generated TOML before adding it to `[waf.crs]`; the adapter supports only narrow remove-by-ID/tag/message exclusions and intentionally rejects broad or executable ModSecurity constructs.

Recommended rollout is monitor first, review `/admin/v1/waf/rule-hits`, add scoped allowlists or per-rule overrides for confirmed false positives, then switch CRS mode to `enforcing`. This mirrors the CRS tuning model while keeping OxiBelt's supported tuning surface in TOML rather than implementing the full ModSecurity exclusion language. See the official CRS [v4.25.0 LTS announcement](https://coreruleset.org/20260321/announcing-crs-v4-25-lts/), [false positives and tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/), and [installation](https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/) references.

Response body and native stream payload inspection are bounded by `waf.limits.max_body_inspection_bytes`, record whether the inspected prefix was truncated, and should be enabled only where the deployment needs response leak detection or upgraded-session payload policy. For WebSocket stream WAF, an individual frame payload larger than this limit is closed fail-closed instead of being buffered and forwarded. CRS compatibility mode does not inspect WebSocket frames/messages or WebTransport stream/datagram payloads.

## Execution Phases

Request rules run after OxiBelt parses the request and matches a route, but before upstream forwarding. They can reject the request, silently close the downstream connection, mutate request headers, set transaction tags, require Person proof, or override the upstream/pool selection.

Response rules run after OxiBelt receives an upstream response or creates a synthetic upstream-error response, but before returning data to the downstream client. They can continue, replace, reject, or silently close instead of forwarding the response, mutate response headers, and emit access logs.

Stream rules run after a WebSocket upgrade or WebTransport CONNECT session is established. They inspect both directions, including WebSocket raw frames, reassembled WebSocket messages, WebTransport stream chunks, and WebTransport datagrams. They can close the active stream/session with `close_stream` or abort it with `silent_close`; request/response mutation and routing actions are not valid in stream phase. Generic HTTP Upgrade and CONNECT tunnels remain byte tunnels in v1.

Rules that read request, response, or stream payload content trigger bounded prefix inspection before forwarding that side of the transaction. OxiBelt scans up to `waf.limits.max_body_inspection_bytes`, replays the captured prefix, and forwards data beyond the inspection window unchanged with `Body.IsTruncated = true` or `Stream.Payload.IsTruncated = true`, except that oversized WebSocket frames on stream-WAF routes are rejected before forwarding to keep proxy-owned frame buffers bounded. On routes with WAF HTTP body compression transform enabled, `Request.Body` and `Response.Body` use the decoded `Content-Encoding` view for OxiRule, OxiRule Group, external OxiRule file, rulepack, and CRS body inspection; DynamicPolicy still runs earlier from header/metadata subjects and does not expose a decoded body subject.

Rules that read only `Request.Body.Size` or `Response.Body.Size` use a single valid positive `Content-Length` when it is available. When body size is unknown, including chunked HTTP/1.1 bodies and bodies without `Content-Length`, OxiBelt captures a bounded prefix up to `waf.limits.max_body_inspection_bytes` before evaluating the size. If that prefix is truncated, `Body.Size` evaluates to the captured byte count plus one as a conservative lower bound. On transform-enabled routes with non-identity `Content-Encoding`, compressed `Content-Length` is not used for `Body.Size`; OxiBelt reports the decoded full size when the body fits the transform and inspection caps, otherwise it reports the decoded captured byte count plus one as a lower bound. Rules that read `Body.Text`, `Body.Bytes`, `Body.IsTruncated`, or body helper methods such as `contains`, `matches`, `scan`, and `isFormat` still trigger bounded prefix inspection. When prefix inspection is required but the HTTP metadata proves the body is empty, OxiBelt evaluates body text and bytes against an empty captured body without polling the stream.

Rules run by ascending `priority`, with rule name as a tie-breaker. Tags created by request rules are visible to later request rules and to response rules for the same transaction.

`Response` is not available in request-phase or stream-phase expressions. `Request.Body` is also unavailable in stream-phase expressions; use `Stream.Payload` for upgraded-session payload inspection.

When upstream forwarding fails, response rules receive a synthetic response with a status such as `502`, `503`, or `504` and `Response.Upstream.Error` populated:

```toml
[[waf.rules]]
name = "replace-upstream-failure"
phase = "response"
priority = 100
when = "Response.Upstream.Error != null"

[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Upstream unavailable"
```

## Expression Language

Object properties use `PascalCase`, such as `Request.Http.Path`. Built-in methods use `lowerCamelCase`, such as `startsWith` and `inCidr`. User-defined functions are called directly, such as `is_bad_path(Request.Http.Path)`.

Supported literals:

```cel
true
false
null
123
'bounded string'
```

Supported operators:

```cel
== !=
< <= > >=
&& || !
+
```

Examples:

```cel
Request.Http.Path.startsWith('/login')
```

```cel
Request.Headers.has('User-Agent') &&
Request.Headers.get('User-Agent').contains('sqlmap')
```

```cel
Request.Protocol == 'webtransport' &&
Request.Transport.Network == 'udp'
```

```cel
Response.Http.Status >= 500 || Response.Upstream.Error != null
```

String functions:

```cel
Value.contains('needle')
Value.startsWith('/prefix')
Value.endsWith('.php')
Value.matches('(?i)sqlmap')
Value.lowerAscii()
Value.upperAscii()
Value.size()
Value.anomalyScore('uri')
Value.malformedScore('payload')
Value.promptInjectionScore()
```

IP/CIDR helper:

```cel
Request.Client.Ip.inCidr('10.0.0.0/8')
```

Forbidden constructs:

- `if`, `else`, `for`, `while`, `switch`, `try`, `catch`, `throw`.
- `let`, `const`, assignment, mutation, classes, or `new`.
- Closures, callbacks, arrow functions, imperative function bodies, and imports. Declarative bounded user-defined functions are configured with `[[waf.functions]]` or `[[routes.waf.functions]]`.
- `await`, promises, external I/O, file access, environment access, network access, clock access, random access, or process execution.
- Unbounded loops, comprehensions, and map construction in v1.

Dynamic policy integration does not change this sandbox: OxiRule can only read `DynamicPolicy.*` values already computed from the current in-memory snapshot. Dynamic policies may match IP/CIDR, route/path, client IP prefix, hashed TLS fingerprint, hashed token-binding, verified Person proof clearance hash, ASN, ASN-route, or hashed composite-client subjects before OxiRule evaluation, but OxiRule expressions still see only the resulting read-only context.

Nullable values must be checked before nested access:

```cel
Request.Transport.Tcp != null &&
Request.Transport.Tcp.Sni == 'blocked.example.com'
```

## Actions

Actions run only when the effective rule condition evaluates to `true`. Ungrouped actions run in declaration order because their default `priority` is `0`; grouped and rule-local actions are sorted together by action `priority`.

Request-phase terminal actions:

```toml
[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

```toml
[[waf.rules.actions]]
type = "rate_limit"
name = "login-token-limit"
key = "access_token_route"
access_token_source = "trusted_header"
token_header = "X-Api-Token"
rate = "10r/m"
burst = 10
max_buckets = 16384
status = 429
body = "rate limit exceeded"
```

```toml
[[waf.rules.actions]]
type = "weigh_person_proof"
weight = 25
```

```toml
[[waf.rules.actions]]
type = "allow_person_proof"
```

```toml
[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "built_in"
difficulty = 18
token_validity_seconds = 300
clearance.cookie.key = "__oxibelt_person_proof"
token_bindings = ["user_agent", "route", "direct_peer_ip_network_prefix"]
direct_peer_ipv4_prefix_bits = 24
direct_peer_ipv6_prefix_bits = 56
single_use = true
success_tag = "PersonProof"
status = 403
```

```toml
[waf.person_proof]
session_path = "/.oxibelt/person-proof/session"
verify_path = "/.oxibelt/person-proof/verify"
openapi_path = "/.oxibelt/person-proof/openapi.json"

[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "third_party_provider"
third_party_provider = "turnstile" # turnstile | hcaptcha | friendly_captcha_v2
custom_frontend_url = "/person-proof/index.html"
challenge_redirect_status = 303
site_key = "0x4AAAA..."
secret_env = "OXIBELT_TURNSTILE_SECRET"
provider_timeout_ms = 3000
provider_fail_policy = "closed" # closed | open
send_remote_ip = true
```

Silent-close terminal action:

```toml
[[waf.rules.actions]]
type = "silent_close"
```

`silent_close` is valid in request, response, and stream phases. It supports only `priority`; `status`, `body`, WebSocket/WebTransport close codes, and `reason` are rejected because no HTTP response or protocol close payload is sent. In request phase OxiBelt closes or resets the downstream connection before upstream forwarding. In response phase OxiBelt discards the upstream response and closes or resets before sending downstream response headers. In stream phase OxiBelt aborts the active WebSocket or WebTransport session without a WebSocket close frame or WebTransport close reason.

`rate_limit` is request-phase only. Supported keys are `global`, `route`, `client_ip`, `client_ip_route`, `client_ip_path`, `access_token`, `access_token_route`, `access_token_path`, `client_ip_prefix`, `client_ip_prefix_route`, `client_ip_prefix_path`, `tls_fingerprint`, `tls_fingerprint_route`, `token_binding_hash`, `token_binding_hash_route`, `person_proof_clearance`, `person_proof_clearance_route`, `composite_client`, `composite_client_route`, `asn`, and `asn_route`; `client-ip` style aliases are accepted for the client-IP keys. `global` uses one bucket shared by all matching requests, and `route` uses one bucket per resolved route. Access-token limits must set `access_token_source`: `trusted_authorization_bearer` reads only `Authorization: Bearer <token>` and rejects `token_header`, while `trusted_header` reads only `token_header` and ignores `Authorization`. `token_header` is valid only for `trusted_header` access-token keys. This is a breaking hardening change for existing `access_token*` rules. Use access-token keys only after a trusted authentication layer has validated or injected the token; public pre-auth routes should pair route/IP/prefix/composite/TLS/Person proof budgets before trusting app/API tokens. Token values, TLS fingerprints, token-binding payloads, and composite-client payloads are hashed before storage. Missing identities fall back to `fallback_ip:<ip>` where possible, not a shared `unknown` bucket. `ipv4_prefix_bits` and `ipv6_prefix_bits` default to `/24` and `/56`. `identity_parts` is required for `composite_client*` keys and may include `client_ip_prefix`, `user_agent`, `tls_fingerprint`, and `asn`. `token_bindings` is required for `token_binding_hash*` keys and reuses Person proof token binding names except `tcp_max_hop`, which is rejected for rate-limit token binding hashes. `person_proof_clearance*` buckets use the stable hash of a verified clearance credential and never store raw clearance tokens. `asn*` uses `[client_identity.asn]` lookup; `Request.Client.Asn` remains `null` when ASN lookup is disabled or degraded. `max_buckets` defaults to `16384` and caps buckets for a single WAF rate-limit action; in enforcing mode, new identities are rejected after the cap until an existing bucket expires or can be reclaimed. When shared state maps rate limits to a backend, WAF `rate_limit` actions use the same Redis-compatible or PostgreSQL token-bucket storage as route rate limits and enforce `max_buckets` before creating a new distributed bucket. Monitor-mode rules count matches without consuming rate-limit tokens.

Response-phase terminal actions:

```toml
[[waf.rules.actions]]
type = "continue_response"
```

```toml
[[waf.rules.actions]]
type = "replace_response"
status = 502
body = "Temporary upstream error"
```

```toml
[[waf.rules.actions]]
type = "reject_response"
status = 403
body = "Blocked response"
```

Stream-phase terminal actions:

```toml
[[waf.rules.actions]]
type = "close_stream"
websocket_code = 1008
webtransport_code = 1
reason = "policy violation"
```

`close_stream` is valid only in stream-phase rules. If fields are omitted, WebSocket uses close code `1008`, WebTransport uses close/reset code `1`, and the reason is `policy violation`. WebSocket close reasons are limited to the protocol payload limit for a close frame.

Request routing actions:

```toml
[[waf.rules.actions]]
type = "route_to_pool"
pool = "api-pool"
```

```toml
[[waf.rules.actions]]
type = "route_to_upstream"
upstream = "api-primary"
```

```toml
[[waf.rules.actions]]
type = "set_load_balancing_policy"
policy = "weighted_least_conn"
```

Supported load-balancing policies are `power_of_two_choices`, `weighted_least_conn`, `rendezvous_hash`, `rendezvous_ip_hash`, `ewma`, and `least_time`. `sticky_cookie` is configured on the upstream pool itself, not through WAF policy overrides. Legacy policy names such as `round_robin`, `least_conn`, `least_connections`, `random`, `hash`, and `ip_hash` are rejected.

Header mutation actions:

```toml
[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-Checked"
value = "true"

[[waf.rules.actions]]
type = "remove_request_header"
name = "X-Debug-Mode"
```

```toml
[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"

[[waf.rules.actions]]
type = "remove_response_header"
name = "Server"
```

Tag action:

```toml
[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"
```

Tag keys and Person proof `success_tag` values must match `[A-Za-z0-9-]{1,32}`. `waf.limits.max_mutations` counts request/response header mutations, `set_tag`, routing overrides, `set_load_balancing_policy`, `rate_limit`, `weigh_person_proof`, `allow_person_proof`, and `emit_mitigation`. Terminal actions such as `reject`, `silent_close`, `replace_response`, `reject_response`, `require_person_proof`, `continue_response`, and `close_stream` are validated separately and do not consume this mutation budget.

Mitigation emission action:

```toml
[[waf.rules.actions]]
type = "emit_mitigation"
intent = "rtbh" # dots | flowspec | rtbh | blackhole | vendor | observe
provider = "example-isp"
reason = "login flood"
target = "Request.Transport.RemoteIp"
ttl_seconds = 300
dedupe_window_ms = 60000
min_count = 3
failure_policy = "open" # open | closed

[[waf.rules.actions.fields]]
name = "path"
value = "Request.Http.Path"
```

`emit_mitigation` is valid in request, response, and stream phases. It writes an aggregate PostgreSQL row through `[database.mitigation]` for an external mitigation controller to translate into DOTS, BGP FlowSpec, RTBH/blackhole, or provider-specific REST/OpenAPI calls. OxiBelt does not call those external APIs directly.

The default target is `Request.Transport.RemoteIp`. `target` and `target_prefix` are OxiRule expressions and must evaluate to an IP address or CIDR string. Custom `fields` use the same expression shape as `emit_access_log`, but may not read `Request.Body`, `Response.Body`, or `Stream.Payload`, including through user-defined functions. Default records include safe request, transport, TLS, response, and stream metadata, including User-Agent, Host, path without query, route, rule identity, TCP/UDP metadata, TLS fingerprint, and stream direction/unit.

When `min_count` is greater than `1`, rows are written as `observing` until the deduplicated aggregate count reaches the threshold, then promoted to `pending`. Existing controller-owned statuses are preserved on later updates. `failure_policy = "open"` drops queue/write failures after logging and metrics; `closed` returns the configured fail-closed HTTP response or stream close.

## Person Proof

`require_person_proof` is a request-phase anti-automation challenge. It is not authentication, identity proof, proof of biological or legal status, bot reputation, or proof of benign intent.

Public Person proof behavior is selected with `person_proof_mode`:

- `built_in`: OxiBelt built-in proof-of-work plus the built-in challenge frontend. This is the default and does not use `custom_frontend_url`.
- `openapi`: OxiBelt built-in proof-of-work session/verify/OpenAPI endpoints plus a custom challenge frontend. This requires `custom_frontend_url`.
- `third_party_provider`: OxiBelt built-in adapters for `third_party_provider = "turnstile" | "hcaptcha" | "friendly_captcha_v2"`. This requires `custom_frontend_url`, `third_party_provider`, `site_key`, and `secret_env`.
- `custom_provider`: custom JSON HTTP provider verification for external Proof of Something flows. This preserves the former custom provider capability under the new mode name, requires `custom_frontend_url` and `provider_endpoint`, and keeps `provider` as the custom provider identifier.

The PoW modes compute a nonce such that `SHA-256(session || "." || nonce)` has the configured number of leading zero bits. Successful verification issues the same signed `clearance.v2` token through the configured clearance target. Later requests validate the configured clearance sources and, when `single_use = true`, rotate the signed clearance credential instead of recomputing proof.

For `custom_provider`, operators may describe the external proof with `proof_kind`, `proof_challenge_kind`, `proof_label`, and arbitrary `provider_metadata`. OxiBelt does not implement those proof semantics. It signs the session, protects replay, calls the configured provider, and issues clearance when the provider returns `{ "success": true }`.

`custom_frontend_url` is not a filesystem path. It is an origin-relative URL routed by the same OxiBelt instance as the protected request. It can point at a static route asset, such as a route whose `static_root` contains `/person-proof/index.html`, or at a separate challenge frontend backend proxied by OxiBelt. When set, OxiBelt redirects the protected request to that URL and exposes only the general Person proof API paths in the redirect query. Browser-visible challenge code should call OxiBelt's `session`, `verify`, and optional `openapi` endpoints, not provider-native server APIs.

Global API path defaults are configured under `[waf.person_proof]`:

```toml
[waf.person_proof]
session_path = "/.oxibelt/person-proof/session"
verify_path = "/.oxibelt/person-proof/verify"
openapi_path = "/.oxibelt/person-proof/openapi.json"
```

Each `require_person_proof` action may override `session_path`, `verify_path`, and `openapi_path`. API paths must be origin-relative paths without query strings or fragments. `custom_frontend_url` may include a query string but not a fragment. If the same runtime path is used for different API roles, configuration fails closed; explicitly duplicated per-policy API paths are also rejected.

`GET openapi_path` returns a static OpenAPI 3.1 JSON document with the configured paths reflected in `paths` and `Cache-Control: no-store`.

When a protected request needs a custom challenge, OxiBelt responds with `challenge_redirect_status` and a `Location` that includes signed `session`, `session_path`, `verify_path`, `openapi_path`, `return_path`, and `expires_unix_ms` query parameters. Provider details such as CAPTCHA site keys are intentionally returned by `GET session_path?session=...` instead of being placed on the redirect URL.

Clearance storage and lookup are configured under each `require_person_proof` action. `clearance.sources` is the ordered list OxiBelt checks on protected requests. Source `type = "cookie"` reads the named cookie key from the `Cookie` header, `type = "authorization_bearer"` reads `Authorization: Bearer <token>`, and `type = "header"` reads the configured header key as the raw token. `clearance.issue_to = "cookie"` sends `Set-Cookie` after verification, `issue_to = "local_storage"` returns the token and localStorage metadata in the verify JSON so the browser can store it, and `issue_to = "response_json"` only returns the token in JSON for custom clients. OxiBelt cannot read browser localStorage directly, so localStorage mode uses `clearance.local_storage.request_header` as the follow-up request bridge; clients should also update the stored token from that response header when `single_use = true` rotates the clearance.

```toml
[[waf.rules.actions]]
type = "require_person_proof"
clearance.issue_to = "cookie" # cookie | local_storage | response_json

[[waf.rules.actions.clearance.sources]]
type = "cookie"
key = "__oxibelt_person_proof"

[[waf.rules.actions.clearance.sources]]
type = "authorization_bearer"

[[waf.rules.actions.clearance.sources]]
type = "header"
key = "X-OxiBelt-Person-Proof"

[waf.rules.actions.clearance.cookie]
key = "__oxibelt_person_proof"
path = "/"
same_site = "lax"
secure = true
http_only = true

[waf.rules.actions.clearance.local_storage]
key = "oxibelt.personProof"
request_header = "X-OxiBelt-Person-Proof"
```

`GET session_path?session=<signed-session>` returns JSON describing the challenge:

```json
{
  "session": "session.v1...",
  "person_proof_mode": "third_party_provider",
  "provider": "cloudflare-turnstile",
  "expires_unix_ms": 1700000000000,
  "return_path": "/protected",
  "verify_path": "/.oxibelt/person-proof/verify",
  "clearance": {
    "issue_to": "cookie",
    "cookie": {
      "key": "__oxibelt_person_proof",
      "path": "/",
      "same_site": "Lax",
      "secure": true,
      "http_only": true
    },
    "local_storage": {
      "key": "oxibelt.personProof",
      "request_header": "X-OxiBelt-Person-Proof"
    },
    "sources": [
      { "type": "cookie", "key": "__oxibelt_person_proof" }
    ]
  },
  "challenge": {
    "kind": "third_party_provider",
    "third_party_provider": "turnstile",
    "site_key": "0x4AAAA...",
    "metadata": {}
  }
}
```

PoW sessions for `built_in` and `openapi` use `challenge.kind = "pow_sha256_v1"` and include `difficulty` and `token`. The `token` is the signed session string that the client hashes with the nonce and submits to `verify_path`. Clearance delivery metadata is top-level `clearance`, not a token-internal field. `third_party_provider` sessions use `challenge.kind = "third_party_provider"` and include `third_party_provider`, `site_key`, and configured `provider_metadata`. `custom_provider` sessions return the custom provider identifier and configured `provider_metadata`.

For `custom_provider`, `challenge.kind` is `proof_challenge_kind` when set, otherwise the legacy compatibility value `custom_provider`. The custom challenge also includes `proof_kind`, `provider`, `label`, and `metadata`. If `proof_kind` is omitted, OxiBelt returns `custom`.

`POST verify_path` accepts `application/json`:

```json
{
  "session": "session.v1...",
  "response": {
    "token": "browser-or-provider-token",
    "fields": {}
  }
}
```

Successful verification returns `200 application/json` with `{ "ok": true, "return_path": "...", "clearance": { ... } }`. Cookie mode also sends a `Set-Cookie` header with the configured cookie key and attributes. LocalStorage and response-JSON modes include the `clearance.token`; localStorage mode also includes `clearance.local_storage.key` and `clearance.local_storage.request_header`. The frontend should store the token when required, then navigate to the signed `return_path`. Invalid or missing sessions return `403`, expired sessions return `410`, invalid responses return `403`, provider transport/API failure returns `503` unless `provider_fail_policy = "open"`, non-POST verify requests return `405`, non-JSON verify requests return `415`, and oversized verify bodies return `413`.

Default provider endpoints are:

- `turnstile`: `https://challenges.cloudflare.com/turnstile/v0/siteverify`
- `hcaptcha`: `https://api.hcaptcha.com/siteverify`
- `friendly_captcha_v2`: `https://global.frcapi.com/api/v2/captcha/siteverify`

Use `provider_endpoint` to override the default endpoint for EU, private, or test deployments. OxiBelt sends the secret from `secret_env`, the browser token as `response`, the configured `site_key` where the provider supports it, and the direct remote IP when `send_remote_ip = true`. Provider transport errors, timeouts, invalid JSON, or non-success HTTP status codes fail closed with `503` by default; set `provider_fail_policy = "open"` only when availability is more important than this anti-automation control.

`custom_provider` sends a JSON verification request to `provider_endpoint` and expects a JSON response with boolean `success`, such as `{ "success": true }` or `{ "success": false }`; providers may include an optional `error_codes` array for their own diagnostics. The request includes the OxiBelt session, `person_proof_mode`, `proof_kind`, `proof_challenge_kind`, `proof_label`, provider name, response token/fields, optional remote IP, optional site key, and configured metadata. Built-in Turnstile, hCaptcha, and Friendly Captcha HTTP shapes are adapter-internal and are not exposed to the browser-facing API.

Proof of Knowledge via an external provider:

```toml
[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "custom_provider"
custom_frontend_url = "/proof/pok.html"
provider = "passkey-knowledge"
proof_kind = "knowledge"
proof_challenge_kind = "proof_of_knowledge_v1"
proof_label = "passkey"
provider_endpoint = "https://proofs.internal.example/verify"
provider_metadata = { prompt = "login-passkey" }
```

Proof of Work via an external provider, distinct from OxiBelt built-in `pow_sha256_v1`:

```toml
[[waf.rules.actions]]
type = "require_person_proof"
person_proof_mode = "custom_provider"
custom_frontend_url = "/proof/external-work.html"
provider = "external-work-service"
proof_kind = "work"
proof_challenge_kind = "external_proof_of_work_v1"
proof_label = "managed-work"
provider_endpoint = "https://proofs.internal.example/work/verify"
provider_metadata = { difficulty_profile = "interactive" }
```

Tokens are signed with a startup-local secret by default, or a shared cluster secret when `[shared_state].person_proof_backend` is configured. Session and clearance tokens bind the original host, mode, selected third-party or custom provider identity, request method, route, policy key, return path, API paths, clearance signing id, and token-binding hash.

Supported token bindings:

- `user_agent`: the `User-Agent` request header.
- `tls_fingerprint`: OxiBelt's downstream TLS fingerprint.
- `route`: the matched OxiBelt route name.
- `direct_peer_ip_network_prefix`: the direct peer IP prefix, not a forwarded-header value.
- `tcp_max_hop`: the configured TCP max-hop policy.

Defaults are `["user_agent", "route", "direct_peer_ip_network_prefix"]`, `/24` for IPv4, and `/56` for IPv6. Use `/32` and `/128` to bind to exact direct peer IPs.

When any policy sets `tcp_max_hop`, OxiBelt applies the strictest configured value listener-wide at accept time using Linux `IP_MINTTL` for IPv4 and `IPV6_MINHOPCOUNT` for IPv6. This is not route-local because the route is not known until after TLS and request parsing.

`single_use` defaults to `true`. When enabled, OxiBelt tracks verification-attempt and clearance reuse in memory by default, or in the configured Person proof shared backend when shared state is enabled. Challenge issuance itself does not reserve replay state. For Person proof API verification, the signed session is consumed before provider verification so a failed CAPTCHA/provider response cannot replay the same session into another provider call. It rotates the configured clearance credential after each valid request. LocalStorage clients should persist the rotated token from the configured request-header name in the protected response. Local in-memory state is bounded by `waf.limits.max_person_proof_reuse_tokens`; exhaustion fails closed with `429 Too Many Requests`.

With a configured Person proof shared backend, replay markers, clearance-revocation checks, and the narrow Person proof Admin revocation mutation remain fail closed if the backend is unavailable. `shared_state.failure_policies.person_proof` must therefore be `fail_closed`; configuration validation rejects a weaker value and never falls back to process-local state for a shared revocation operation.

`weigh_person_proof` and `allow_person_proof` are request-phase policy helpers for Anubis-style explicit rule sets. `weigh_person_proof` adds its integer `weight` to `Request.Client.PersonProof.Weight` for later request rules in the same transaction. `allow_person_proof` sets `Request.Client.PersonProof.Allowed = true`; later `require_person_proof` actions no-op while other actions, including `reject`, still run normally. OxiBelt does not challenge generic browser traffic by default: define the weights and terminal challenge rules you want explicitly.

```toml
[[waf.rules]]
name = "weigh-suspicious-automation"
phase = "request"
priority = 100
when = "Request.Client.UserAgent.contains('Headless')"

[[waf.rules.actions]]
type = "weigh_person_proof"
weight = 50

[[waf.rules]]
name = "allow-static-health"
phase = "request"
priority = 110
when = "Request.Http.Path == '/healthz'"

[[waf.rules.actions]]
type = "allow_person_proof"

[[waf.rules]]
name = "challenge-high-person-proof-weight"
phase = "request"
priority = 120
when = "Request.Client.PersonProof.Weight >= 50 && Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 18
token_validity_seconds = 300
clearance.cookie.key = "__oxibelt_person_proof"
```

Validation constraints:

- `person_proof_mode` must be `built_in`, `openapi`, `third_party_provider`, or `custom_provider`.
- `method`, `algorithm`, and `challenge_url` are no longer supported; use `person_proof_mode` and `custom_frontend_url`.
- `difficulty` must be between `1` and `30` for `built_in` and `openapi`.
- `token_validity_seconds` must be between `1` and `86400`.
- `ttl_seconds` and `token_ttl_seconds` are compatibility aliases.
- Flat `cookie` is no longer supported; use `clearance.cookie.key` and `clearance.sources`.
- `clearance.cookie.key` and cookie sources may contain only ASCII letters, digits, `_`, `-`, or `.`.
- `clearance.cookie.path` must be an origin path without control characters or `;`.
- Header sources and `clearance.local_storage.request_header` must be valid HTTP header names.
- `clearance.local_storage.key` must not be empty or contain control characters.
- `clearance.sources` must not be empty when `clearance.issue_to = "response_json"`.
- `token_bindings` must not be empty and may not contain duplicates.
- IPv4 prefix bits must be `0..32`; IPv6 prefix bits must be `0..128`.
- `tcp_max_hop`, when set, must be `0..255`.
- `token_bindings` containing `tcp_max_hop` must also set `tcp_max_hop`.
- `status` must be a valid HTTP status code.
- `custom_frontend_url`, when set, must be origin-relative and may include a query string but not a fragment.
- `challenge_redirect_status` must be `301`, `302`, `303`, `307`, or `308`; the default is `303`.
- `built_in` forbids `custom_frontend_url` and `third_party_provider`.
- `openapi` requires `custom_frontend_url` and forbids `third_party_provider`.
- `third_party_provider` requires `custom_frontend_url`, `third_party_provider`, `site_key`, and `secret_env`, and forbids `provider`.
- `custom_provider` requires `custom_frontend_url` and `provider_endpoint`.
- `proof_kind`, `proof_challenge_kind`, and `proof_label` are valid only with `custom_provider` and must match `[A-Za-z0-9_.:-]{1,64}`.
- `session_path`, `verify_path`, and `openapi_path` must be origin-relative paths without query strings or fragments.
- `provider_endpoint`, when set, must use `http://` or `https://`.
- `provider_timeout_ms` and `provider_max_response_body_bytes` must be greater than zero.
- `weigh_person_proof.weight` must be between `-1000000` and `1000000`.

`Request.TokenBindings` exposes the normalized binding values to expressions.

## Access Log Action

`emit_access_log` is valid only in response-phase rules:

```toml
[[waf.rules]]
name = "stdout-access-log"
phase = "response"
priority = 1000
when = "true"

[[waf.rules.actions]]
type = "emit_access_log"

[[waf.rules.actions.fields]]
name = "method"
value = "Request.Http.Method"

[[waf.rules.actions.fields]]
name = "path"
value = "Request.Http.Path"

[[waf.rules.actions.fields]]
name = "status"
value = "Response.Http.Status"
```

The emitted access-log record always includes `event = "oxibelt.access"`, `timestamp_unix_ms`, and `scope = "waf"` unless a field named `scope` is explicitly configured. OxiBelt projects the record through the shared `[access_log]` runtime: stdout and OTLP sinks emit Open Cybersecurity Schema Framework JSON with `schema = "ocsf"` or Elastic Common Schema JSON with `schema = "ecs"`. PostgreSQL access-log sinks are removed.

Field `value` may also be written as `expression`. Field expressions may read response-phase `Request`, `Response`, and `Context` values and may call the same scoped user-defined functions available to the matching WAF rule. They may evaluate to scalar JSON values (`Bool`, `Int`, `String`, or `Null`) or bounded JSON collections/objects exposed by the OxiRule object model, such as `Request.Headers`, `Request.QueryParams`, `Request.Cookies`, `Request.Tags`, `Context.RuleTags`, or `Request.Headers.getAll(...)`. Field names must match `[A-Za-z0-9_.-]{1,64}` and may not be `event` or `timestamp_unix_ms`. Fields that read request body bytes are rejected. Request-wide system access-log fields under `[logging.access_log]` use the OxiRule expression language but do not receive WAF user-defined functions in v1.

If `fields` is omitted, OxiBelt emits the default access-log field set. In that default set, `user_agent` is a bounded collection from `Request.Headers.getAll('User-Agent')`, so duplicate `User-Agent` headers are preserved instead of failing the whole log record.

## Object Model

Top-level objects:

```text
Context.Phase: 'request' | 'response' | 'stream'
Context.RuleName: String
Context.RuleId: String | Null
Context.RuleTags: RuleTagSet
Context.RouteName: String | Null
Context.TransactionId: String
Context.Mode: 'enforcing' | 'monitor' # effective mode for the current rule, or global mode outside a rule
```

```text
DynamicPolicy.Matched: Bool
DynamicPolicy.Action: 'allow' | 'reject' | 'silent_close' | 'rate_limit' | 'challenge' | Null
DynamicPolicy.Name: String | Null
DynamicPolicy.Reason: String | Null
DynamicPolicy.Code: String | Null
DynamicPolicy.Mode: 'enforce' | 'dry_run' | Null
DynamicPolicy.Source: String | Null
```

`DynamicPolicy.*` is read-only request context from OxiBelt's in-memory dynamic policy snapshot. It does not perform SQL or any other external I/O while evaluating an OxiRule expression. Subject identities that contain sensitive material, such as TLS fingerprints, token-binding payloads, composite-client parts, and Person proof clearances, are compared as prefixed SHA-256 hashes before this context is populated. Terminal dynamic policy rejects, silent closes, and Person proof challenges happen before request-phase OxiRule evaluation, so these fields are mainly useful for requests that matched an allowed dynamic `allow`, non-terminal `rate_limit`, valid-clearance `challenge`, or `dry_run` policy and for response/access-log expressions.

```text
Request.Id: String
Request.Protocol: 'http' | 'websocket' | 'webrtc' | 'webtransport'
Request.ReceivedAtUnixMs: Int
Request.Client: ClientMetadata
Request.Transport: TransportMetadata
Request.Http: HttpRequestMetadata
Request.Headers: HeaderMap
Request.QueryParams: QueryParamMap
Request.Cookies: CookieMap
Request.Normalized: NormalizedRequestView
Request.Body: BodyView
Request.Tls: TlsMetadata | Null
Request.Tags: TagMap
Request.TokenBindings: PersonProofTokenBindingView
```

```text
Response.Id: String
Response.Protocol: 'http' | 'websocket' | 'webrtc' | 'webtransport'
Response.ReceivedAtUnixMs: Int
Response.Upstream: UpstreamMetadata
Response.Transport: TransportMetadata
Response.Http: HttpResponseMetadata
Response.Headers: HeaderMap
Response.Cookies: CookieMap
Response.Body: BodyView
Response.Tls: TlsMetadata | Null
Response.Tags: TagMap
```

```text
Stream.Protocol: 'websocket' | 'webtransport'
Stream.Direction: 'downstream_to_upstream' | 'upstream_to_downstream'
Stream.Unit: 'websocket_frame' | 'websocket_message' | 'webtransport_stream_chunk' | 'webtransport_datagram'
Stream.Payload: BodyView
Stream.WebSocket: WebSocketStreamMetadata
Stream.WebTransport: WebTransportStreamMetadata
```

Important nested fields:

```text
ClientMetadata.Kind: 'person' | 'unknown'
ClientMetadata.Ip: IpAddress
ClientMetadata.Port: Int
ClientMetadata.SourceAddress: String
ClientMetadata.UserAgent: String | Null
ClientMetadata.PersonProof: PersonProofMetadata
ClientMetadata.Agent: AgentMetadata
ClientMetadata.Bot: BotMetadata
ClientMetadata.GeoCountry: String | Null
ClientMetadata.Asn: Int | Null

PersonProofMetadata.State: 'absent' | 'valid' | 'failed' | 'expired'
PersonProofMetadata.Mode: String | Null
PersonProofMetadata.Difficulty: Int | Null
PersonProofMetadata.IssuedAtUnixMs: Int | Null
PersonProofMetadata.ExpiresAtUnixMs: Int | Null
PersonProofMetadata.Weight: Int
PersonProofMetadata.Allowed: Bool

AgentMetadata.Verified: Bool
AgentMetadata.Kind: String | Null
AgentMetadata.Provider: String | Null
AgentMetadata.Model: String | Null
AgentMetadata.AuthMethod: String | Null

BotMetadata.Disposition: 'unknown' | 'normal' | 'malicious'
BotMetadata.Malicious: Bool | Null
BotMetadata.Score: Int
BotMetadata.Reason: String | Null

PersonProofTokenBindingView.UserAgent: String
PersonProofTokenBindingView.TlsFingerprint: String
PersonProofTokenBindingView.Route: String
PersonProofTokenBindingView.DirectPeerIpNetworkPrefix: String
PersonProofTokenBindingView.TcpMaxHop: String
PersonProofTokenBindingView.directPeerIpNetworkPrefix(Ipv4PrefixBits, Ipv6PrefixBits): String
PersonProofTokenBindingView.tcpMaxHop(ConfiguredMaxHop): String
```

`Request.Client.Bot` is derived from local request signals such as URI shape, query/path anomalies, suspicious headers, automation User-Agent strings, and any request body prefix already captured for WAF evaluation. `Score` is `0..100`; `Disposition` becomes `malicious` for high-confidence local automation or attack signals and otherwise remains `unknown` unless a future trusted bot identity source marks traffic as normal. `Request.Client.Agent.Verified` remains `false` unless an explicitly trusted agent authentication mechanism is configured; client-supplied AI/LLM or crawler claims are not trusted. `Request.Client.Asn` is populated only by `[client_identity.asn]` prefix-to-ASN lookup. The IANA AS Numbers registry is optional ASN metadata, not an IP prefix-to-origin-ASN source. `Request.Client.GeoCountry` is currently always `null`.

```text
TransportMetadata.Network: 'tcp' | 'udp'
TransportMetadata.RemoteIp: IpAddress
TransportMetadata.RemotePort: Int
TransportMetadata.IsEncrypted: Bool
TransportMetadata.Tcp: TcpMetadata | Null
TransportMetadata.Udp: UdpMetadata | Null
```

```text
TcpMetadata.Sni: String | Null
TcpMetadata.Alpn: String | Null
TcpMetadata.MaxHop: Int | Null
TcpMetadata.Mss: Int | Null
TcpMetadata.RttMs: Int | Null
```

```text
UdpMetadata.DatagramSize: Int | Null
UdpMetadata.QuicDetected: Bool
UdpMetadata.ConnectionId: String | Null
```

`TcpMetadata.Mss` is populated from the accepted TCP socket's maximum segment size where the platform exposes it. `TcpMetadata.RttMs` is populated from Linux `TCP_INFO` RTT in milliseconds; unsupported platforms or socket option failures evaluate to `null`. `UdpMetadata.ConnectionId` is an OxiBelt-local QUIC connection identifier in the form `quinn-stable:<id>` when available. It is not the wire QUIC connection ID. Request-level `UdpMetadata.DatagramSize` is reserved because a single HTTP/3 request does not map cleanly to one UDP datagram; WebTransport datagram payload size is exposed separately as `Stream.WebTransport.DatagramSize`.

```text
HttpRequestMetadata.Version: '1.0' | '1.1' | '2' | '3'
HttpRequestMetadata.Method: String
HttpRequestMetadata.Scheme: 'http' | 'https'
HttpRequestMetadata.Host: String
HttpRequestMetadata.Path: String
HttpRequestMetadata.Query: String
HttpRequestMetadata.Uri: String
HttpRequestMetadata.Body: BodyMetadata
```

```text
NormalizedRequestView.Http: NormalizedHttpRequestMetadata
NormalizedRequestView.Headers: HeaderMap
NormalizedRequestView.QueryParams: QueryParamMap
NormalizedRequestView.Cookies: CookieMap

NormalizedHttpRequestMetadata.Path: String
NormalizedHttpRequestMetadata.Query: String
NormalizedHttpRequestMetadata.Uri: String
```

`Request.Normalized` is a WAF-only view. It does not replace raw `Request.Http.*`, `Request.Headers`, `Request.QueryParams`, or `Request.Cookies`. The view applies URL/Unicode decoding, Unicode NFC normalization, null removal, whitespace compression, lower-case text transforms, path segment normalization, and duplicate metadata policy handling through the same bounded map helpers.

```text
HttpResponseMetadata.Version: '1.0' | '1.1' | '2' | '3'
HttpResponseMetadata.Status: Int
HttpResponseMetadata.Reason: String | Null
HttpResponseMetadata.Body: BodyMetadata
```

```text
UpstreamMetadata.Name: String | Null
UpstreamMetadata.Pool: String | Null
UpstreamMetadata.Scheme: String | Null
UpstreamMetadata.ConnectTimeMs: Int | Null
UpstreamMetadata.FirstByteTimeMs: Int | Null
UpstreamMetadata.Error: UpstreamError | Null

UpstreamError.Code: 'dns_error' | 'connect_timeout' | 'connect_error' | 'tls_error' | 'read_timeout' | 'protocol_error'
UpstreamError.Message: String

WebSocketStreamMetadata.Opcode: 'continuation' | 'text' | 'binary' | 'close' | 'ping' | 'pong' | 'message'
WebSocketStreamMetadata.Fin: Bool
WebSocketStreamMetadata.IsControl: Bool
WebSocketStreamMetadata.MessageOpcode: 'text' | 'binary' | Null
WebSocketStreamMetadata.FramePayloadSize: Int

WebTransportStreamMetadata.StreamKind: 'bidi' | 'uni' | Null
WebTransportStreamMetadata.StreamId: Int | Null
WebTransportStreamMetadata.DatagramSize: Int | Null
```

`UpstreamMetadata.Name` is `Null` when no upstream was selected or the upstream is unknown. `UpstreamMetadata.Pool` is `Null` when no upstream pool was used. `UpstreamMetadata.Scheme` is `Null` when the upstream scheme is unknown.

```text
TlsMetadata.Enabled: Bool
TlsMetadata.Version: String | Null
TlsMetadata.CipherSuite: String | Null
TlsMetadata.Sni: String | Null
TlsMetadata.Alpn: String | Null
TlsMetadata.Fingerprint: String | Null
TlsMetadata.FingerprintScheme: String | Null
TlsMetadata.ClientCertificatePresent: Bool
```

Current implementation notes:

- TCP request rules expose TCP transport metadata; HTTP/3 and WebTransport request rules expose UDP/QUIC metadata.
- HTTP/3 TLS fingerprints use the `quinn-rustls-quic-v2` scheme.
- `TlsMetadata.ClientCertificatePresent` reflects downstream TCP TLS client certificate presence. HTTP/3 client certificate identity is not currently exposed by the stable QUIC metadata path, so it remains unavailable there.
- `Request.Id`, `Response.Id`, `Context.TransactionId`, request/response receive timestamps, and upstream first-byte timing are populated for HTTP request-wide and OxiRule access-log contexts.
- Upstream connect timing is populated only where the proxy can measure it directly; otherwise it evaluates to `null`.
- Some local endpoint fields, byte counters, request-level UDP datagram sizes, TCP socket metadata, and unavailable connection identifiers are reserved and may evaluate to `null`.

## Bounded Helpers

OxiRule forbids user-controlled iteration. Repeated data is inspected through bounded helpers that charge runtime, step, memory, regex, helper-item, and result-size budgets.

Header helpers:

```text
Request.Headers.count(): Int
Request.Headers.has(Name): Bool
Request.Headers.get(Name): String | Null
Request.Headers.getAll(Name): BoundedStringList
Request.Headers.anyNameMatches(Pattern): Bool
Request.Headers.anyValueContains(Value): Bool
Request.Headers.anyValueMatches(Pattern): Bool
Request.Headers.anyEntryMatches(NamePattern, ValuePattern): Bool
Request.Headers.allEntriesMatch(NamePattern, ValuePattern): Bool
```

The same single-value duplicate behavior applies to query parameters and cookies according to `waf.duplicate_metadata_policy`. Use `getAll(...)` when duplicates are expected.

Query parameter helpers:

```text
Request.QueryParams.count(): Int
Request.QueryParams.has(Name): Bool
Request.QueryParams.get(Name): String | Null
Request.QueryParams.getAll(Name): BoundedStringList
Request.QueryParams.anyNameMatches(Pattern): Bool
Request.QueryParams.anyValueContains(Value): Bool
Request.QueryParams.anyValueMatches(Pattern): Bool
Request.QueryParams.anyEntryMatches(NamePattern, ValuePattern): Bool
```

Cookie helpers:

```text
Request.Cookies.count(): Int
Request.Cookies.has(Name): Bool
Request.Cookies.get(Name): String | Null
Request.Cookies.getAll(Name): BoundedStringList
Request.Cookies.anyNameMatches(Pattern): Bool
Request.Cookies.anyValueContains(Value): Bool
Request.Cookies.anyValueMatches(Pattern): Bool
Request.Cookies.anyEntryMatches(NamePattern, ValuePattern): Bool
```

Tag helpers:

```text
Request.Tags.count(): Int
Request.Tags.has(Key): Bool
Request.Tags.get(Key): String | Null
Request.Tags.anyKeyMatches(Pattern): Bool
Request.Tags.anyValueContains(Value): Bool
Request.Tags.anyEntryMatches(KeyPattern, ValuePattern): Bool

Context.RuleTags.count(): Int
Context.RuleTags.has(Tag): Bool
Context.RuleTags.anyMatches(Pattern): Bool
```

Bounded string lists:

```text
BoundedStringList.Count: Int
BoundedStringList.IsTruncated: Bool
BoundedStringList.First: String | Null
BoundedStringList.contains(Value): Bool
BoundedStringList.containsAny(PatternSetName): Bool
BoundedStringList.matchesAny(PatternSetName): Bool
```

Body view:

```text
Request.Body.Size: Int
Request.Body.IsTruncated: Bool
Request.Body.Text: String | Null
Request.Body.Bytes: Bytes | Null
Request.Body.isFormat(Format): Bool
Request.Body.contains(Value): Bool
Request.Body.matches(Pattern): Bool
Request.Body.containsAny(PatternSetName): Bool
Request.Body.matchesAny(PatternSetName): Bool
Request.Body.scan(PatternSetName): BodyScanResult
Request.Body.anomalyScore(Profile): Int
Request.Body.malformedScore(Profile): Int
Request.Body.promptInjectionScore(): Int
```

The same shape is supported for `Response.Body` in response-phase rules and `Stream.Payload` in stream-phase rules. Body content helpers are bounded by `waf.limits.max_body_inspection_bytes`; bytes beyond that prefix are replayed or forwarded but not inspected.

Malicious-intelligence and malformed-payload score helpers return an integer from `0` to `100`. They are deterministic local heuristics, not external LLM classifications, identity proof, Person proof, or proof of benign or malicious intent. Supported profiles are `uri`, `path`, `query`, `header`, `payload`, `json`, `form`, `prompt`, and `generic`. `anomalyScore` combines malformed encoding, suspicious delimiter density, encoded layering, high-entropy segments, known attack strings, prompt-injection phrases, and truncation signals. `malformedScore` focuses on invalid percent/unicode encoding, control/null characters, path traversal shape, malformed JSON-like input, and truncation. `promptInjectionScore` focuses on instruction override, system/developer prompt disclosure, tool/function-call abuse, and secret exfiltration language. Body score helpers require bounded prefix inspection.

`Body.scan(PatternSetName)` returns:

```text
BodyScanResult.Matched: Bool
BodyScanResult.Pattern: String | Null
BodyScanResult.Offset: Int | Null
BodyScanResult.Match: String | Null
BodyScanResult.IsTruncated: Bool
```

Bytes helpers:

```text
Bytes.size(): Int
Bytes.isFormat(Format): Bool
Bytes.isBinaryFormat(Format): Bool
Bytes.matchesFormat(Format): Bool
```

Supported binary format checks include common image, audio, video, document, archive, data-container, font, and executable signatures such as `png`, `jpeg`, `webp`, `mp3`, `webm`, `pdf`, `zip`, `gzip`, `tar`, `woff`, `woff2`, `elf`, `exe`, and `pe`, plus unambiguous MIME aliases. Text formats such as `svg`, `html`, `json`, `yaml`, `css`, `csv`, and `markdown` are intentionally not matched by the binary signature helper.

## Protocol Notes

- HTTP rules may inspect and mutate headers, URI metadata, methods, status, and bounded body metadata.
- WebSocket request rules apply to the HTTP upgrade request. Stream-phase rules inspect raw frames before forwarding, reject individual frame payloads larger than `waf.limits.max_body_inspection_bytes`, and reassemble text/binary messages up to that limit before releasing queued fragments.
- WebRTC signaling HTTP requests can be inspected when they pass through OxiBelt; TURN media payloads are forwarded by WebRTC TURN listeners outside OxiRule/WAF inspection.
- WebTransport over HTTP/3 exposes the CONNECT request as `Request.Protocol == 'webtransport'` with UDP/QUIC transport metadata. Stream-phase rules inspect WebTransport stream chunks and datagrams before forwarding. Stream IDs are exposed as `null` where the underlying crate API does not provide them.

## Validation Summary

OxiRule validation rejects:

- External `path` entries combined with inline `when`, `groups`, or `actions`, or rules without an effective condition.
- Duplicate rule names in the same scope.
- Duplicate non-empty public rule IDs.
- Duplicate rule group names in one scope, duplicate group references from one rule, or references to unknown rule groups.
- Invalid rule IDs, rule tags, transaction tag keys, or Person proof `success_tag` values.
- Multiple `merge_condition_as = "override"` condition fragments in one rule expansion.
- Invalid function names or parameters, duplicate function names in one scope, duplicate parameters, unknown function calls, arity mismatches, or recursive function call graphs.
- Unsupported phases, negative rule or action priorities, unsupported operators, unknown properties, or unknown built-in functions.
- Forbidden imperative constructs, callbacks, imports, or external I/O.
- Request-phase access to `Response`.
- Stream-phase access to `Response` or `Request.Body`.
- Response mutation actions in request-phase rules.
- Request routing actions in response-phase rules.
- Request, response, routing, rate-limit, tag, Person proof, and access-log actions in stream-phase rules.
- `close_stream` outside stream phase.
- `silent_close` fields other than `priority`.
- `emit_access_log` outside response phase.
- Header mutations or other mutations that exceed `max_mutations`.
- Pattern sets that exceed configured count, length, regex, or budget limits.
- `route_to_upstream` or `route_to_pool` references to unknown targets.
- Invalid Person proof settings.

## Examples

Block public access to `/admin`:

```toml
[[waf.rules]]
name = "block-public-admin"
phase = "request"
priority = 100
when = """
Request.Http.Path.startsWith('/admin') &&
!Request.Client.Ip.inCidr('10.0.0.0/8')
"""

[[waf.rules.actions]]
type = "reject"
status = 403
body = "Forbidden"
```

Add response security headers:

```toml
[[waf.rules]]
name = "security-response-headers"
phase = "response"
priority = 200
when = "true"

[[waf.rules.actions]]
type = "set_response_header"
name = "X-Content-Type-Options"
value = "nosniff"

[[waf.rules.actions]]
type = "set_response_header"
name = "Referrer-Policy"
value = "no-referrer"
```

Pass request-side context to a response rule:

```toml
[[waf.rules]]
name = "tag-login-request"
phase = "request"
priority = 100
when = "Request.Http.Path.startsWith('/login')"

[[waf.rules.actions]]
type = "set_tag"
key = "LoginRequest"
value = "true"

[[waf.rules]]
name = "no-store-login-errors"
phase = "response"
priority = 100
when = "Request.Tags.get('LoginRequest') == 'true' && Response.Http.Status >= 500"

[[waf.rules.actions]]
type = "set_response_header"
name = "Cache-Control"
value = "no-store"
```

Chain Person proof success into a later request rule:

```toml
[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 100
when = "Request.Client.PersonProof.State != 'valid'"

[[waf.rules.actions]]
type = "require_person_proof"
success_tag = "PersonProof"

[[waf.rules]]
name = "mark-verified-person"
phase = "request"
priority = 110
when = "Request.Tags.get('PersonProof') == 'valid'"

[[waf.rules.actions]]
type = "set_request_header"
name = "X-OxiBelt-Person-Proof"
value = "valid"
```
