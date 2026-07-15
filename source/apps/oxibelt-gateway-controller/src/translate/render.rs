use super::super::cli::SharedArgs;
use super::{GENERATED_HEADER, GeneratedKubernetesDiscoveryPort, TranslationState};

pub(super) fn render_toml(state: &TranslationState, args: &SharedArgs) -> String {
  let mut out = String::from(GENERATED_HEADER);
  out.push_str("# controller_name = ");
  out.push_str(&toml_string(&args.controller_name));
  out.push('\n');
  out.push_str("# managed_config_path = ");
  out.push_str(&toml_string(&args.managed_config_path));
  out.push_str("\n\n");

  for auth in state.external_auth.values() {
    out.push_str("# Source: ");
    out.push_str(&auth.source);
    out.push('\n');
    out.push_str("[[external_auth]]\n");
    out.push_str("name = ");
    out.push_str(&toml_string(&auth.name));
    out.push('\n');
    out.push_str("provider = \"gateway_ext_auth_http\"\n");
    out.push_str("endpoint = ");
    out.push_str(&toml_string(&auth.endpoint));
    out.push('\n');
    out.push_str("forward_headers = ");
    out.push_str(&toml_string_array(&auth.forward_headers));
    out.push('\n');
    out.push_str("identity_headers = ");
    out.push_str(&toml_string_array(&auth.identity_headers));
    out.push('\n');
    out.push_str("terminal_response_headers = ");
    out.push_str(&toml_string_array(&auth.terminal_response_headers));
    out.push('\n');
    out.push('\n');
  }

  for pool in state.pools.values() {
    out.push_str("# Source: ");
    out.push_str(&pool.source);
    out.push('\n');
    out.push_str("[[upstream_pools]]\n");
    out.push_str("name = ");
    out.push_str(&toml_string(&pool.name));
    out.push('\n');
    for server in &pool.servers {
      out.push_str("\n[[upstream_pools.servers]]\n");
      out.push_str("id = ");
      out.push_str(&toml_string(&server.id));
      out.push('\n');
      out.push_str("origin = ");
      out.push_str(&toml_string(&server.origin));
      out.push('\n');
      out.push_str("weight = ");
      out.push_str(&server.weight.to_string());
      out.push('\n');
    }
    for discovery in &pool.discoveries {
      out.push_str("\n[[upstream_pools.discovery]]\n");
      out.push_str("provider = \"kubernetes\"\n");
      out.push_str("endpoint = ");
      out.push_str(&toml_string(&discovery.endpoint));
      out.push('\n');
      out.push_str("namespace = ");
      out.push_str(&toml_string(&discovery.namespace));
      out.push('\n');
      out.push_str("service = ");
      out.push_str(&toml_string(&discovery.service));
      out.push('\n');
      out.push_str("scheme = ");
      out.push_str(&toml_string(&discovery.scheme));
      out.push('\n');
      match &discovery.port {
        GeneratedKubernetesDiscoveryPort::Number(port) => {
          out.push_str("port = ");
          out.push_str(&port.to_string());
          out.push('\n');
        }
        GeneratedKubernetesDiscoveryPort::Name(name) => {
          out.push_str("port_name = ");
          out.push_str(&toml_string(name));
          out.push('\n');
        }
      }
      out.push_str("kubernetes_resource = \"endpoint_slice\"\n");
      out.push_str("watch = true\n");
      out.push_str("token_file = \"/var/run/secrets/kubernetes.io/serviceaccount/token\"\n");
    }
    out.push('\n');
  }

  for route in &state.routes {
    out.push_str("# Source: ");
    out.push_str(&route.source);
    out.push('\n');
    out.push_str("[[routes]]\n");
    out.push_str("name = ");
    out.push_str(&toml_string(&route.name));
    out.push('\n');
    out.push_str("hosts = ");
    out.push_str(&toml_string_array(&route.hosts));
    out.push('\n');
    out.push_str("path_prefix = ");
    out.push_str(&toml_string(&route.path_prefix));
    out.push('\n');
    if let Some(upstream_pool) = &route.upstream_pool {
      out.push_str("upstream_pool = ");
      out.push_str(&toml_string(upstream_pool));
      out.push('\n');
    }
    if let Some(external_auth) = &route.external_auth {
      out.push_str("external_auth = ");
      out.push_str(&toml_string(external_auth));
      out.push('\n');
    }
    out.push_str("[routes.match]\n");
    out.push_str("priority = ");
    out.push_str(&route.priority.to_string());
    out.push('\n');
    if !route.methods.is_empty() {
      out.push_str("methods = ");
      out.push_str(&toml_string_array(&route.methods));
      out.push('\n');
    }
    if let Some(exact) = &route.path_exact {
      out.push_str("[routes.match.path]\n");
      out.push_str("exact = ");
      out.push_str(&toml_string(exact));
      out.push('\n');
    }
    for header in &route.headers {
      out.push_str("\n[[routes.match.headers]]\n");
      out.push_str("name = ");
      out.push_str(&toml_string(&header.name));
      out.push('\n');
      out.push_str("exact = ");
      out.push_str(&toml_string(&header.value));
      out.push('\n');
    }
    for query in &route.queries {
      out.push_str("\n[[routes.match.queries]]\n");
      out.push_str("name = ");
      out.push_str(&toml_string(&query.name));
      out.push('\n');
      out.push_str("exact = ");
      out.push_str(&toml_string(&query.value));
      out.push('\n');
    }
    if let Some(rewrite) = &route.rewrite {
      out.push_str("\n[routes.actions.rewrite]\n");
      if let Some(path) = &rewrite.path {
        out.push_str("path = ");
        out.push_str(&toml_string(path));
        out.push('\n');
      }
      if let Some(query) = &rewrite.query {
        out.push_str("query = ");
        out.push_str(&toml_string(query));
        out.push('\n');
      }
    }
    if let Some(redirect) = &route.redirect {
      out.push_str("\n[routes.actions.redirect]\n");
      out.push_str("status = ");
      out.push_str(&redirect.status.to_string());
      out.push('\n');
      out.push_str("location_template = ");
      out.push_str(&toml_string(&redirect.location_template));
      out.push('\n');
    }
    render_header_modifier(&mut out, "request_headers", &route.request_headers);
    render_header_modifier(&mut out, "response_headers", &route.response_headers);
    if let Some(cors) = &route.cors {
      out.push_str("\n[routes.actions.cors]\n");
      out.push_str("allow_origins = ");
      out.push_str(&toml_string_array(&cors.allow_origins));
      out.push('\n');
      out.push_str("allow_methods = ");
      out.push_str(&toml_string_array(&cors.allow_methods));
      out.push('\n');
      if !cors.allow_headers.is_empty() {
        out.push_str("allow_headers = ");
        out.push_str(&toml_string_array(&cors.allow_headers));
        out.push('\n');
      }
      if !cors.expose_headers.is_empty() {
        out.push_str("expose_headers = ");
        out.push_str(&toml_string_array(&cors.expose_headers));
        out.push('\n');
      }
      if cors.allow_credentials {
        out.push_str("allow_credentials = true\n");
      }
      if let Some(max_age) = cors.max_age_seconds {
        out.push_str("max_age_seconds = ");
        out.push_str(&max_age.to_string());
        out.push('\n');
      }
    }
    for mirror in &route.request_mirrors {
      out.push_str("\n[[routes.actions.request_mirrors]]\n");
      out.push_str("upstream_pool = ");
      out.push_str(&toml_string(&mirror.upstream_pool));
      out.push('\n');
      if let Some(sample_percent) = mirror.sample_percent {
        out.push_str("sample_percent = ");
        out.push_str(&sample_percent.to_string());
        out.push('\n');
      }
      out.push_str("max_body_bytes = ");
      out.push_str(&mirror.max_body_bytes.to_string());
      out.push('\n');
    }
    out.push('\n');
  }

  for rule in &state.sni_rules {
    out.push_str("# Source: ");
    out.push_str(&rule.source);
    out.push('\n');
    out.push_str("[[sni_forward.rules]]\n");
    out.push_str("name = ");
    out.push_str(&toml_string(&rule.name));
    out.push('\n');
    out.push_str("server_names = ");
    out.push_str(&toml_string_array(&rule.server_names));
    out.push('\n');
    out.push_str("target = ");
    out.push_str(&toml_string(&rule.target));
    out.push('\n');
    out.push_str("protocols = [\"tcp_tls\"]\n\n");
  }

  out
}

fn toml_string(value: &str) -> String {
  toml::Value::String(value.to_string()).to_string()
}

fn toml_string_array(values: &[String]) -> String {
  let mut text = String::from("[");
  for (index, value) in values.iter().enumerate() {
    if index > 0 {
      text.push_str(", ");
    }
    text.push_str(&toml_string(value));
  }
  text.push(']');
  text
}

fn render_header_modifier(out: &mut String, name: &str, modifier: &super::HeaderModifierAction) {
  if modifier.is_empty() {
    return;
  }
  if !modifier.remove.is_empty() {
    out.push_str("\n[routes.actions.");
    out.push_str(name);
    out.push_str("]\n");
    out.push_str("remove = ");
    out.push_str(&toml_string_array(&modifier.remove));
    out.push('\n');
  }
  for entry in &modifier.set {
    out.push_str("\n[[routes.actions.");
    out.push_str(name);
    out.push_str(".set]]\n");
    out.push_str("name = ");
    out.push_str(&toml_string(&entry.name));
    out.push('\n');
    out.push_str("value = ");
    out.push_str(&toml_string(&entry.value));
    out.push('\n');
  }
  for entry in &modifier.add {
    out.push_str("\n[[routes.actions.");
    out.push_str(name);
    out.push_str(".add]]\n");
    out.push_str("name = ");
    out.push_str(&toml_string(&entry.name));
    out.push('\n');
    out.push_str("value = ");
    out.push_str(&toml_string(&entry.value));
    out.push('\n');
  }
}
