use super::*;

fn config(raw: &str) -> RealIpConfig {
  toml::from_str(raw).expect("test real-IP config")
}

fn headers() -> HeaderMap {
  let mut headers = HeaderMap::new();
  headers.insert(
    "x-forwarded-for",
    "203.0.113.10, 192.0.2.2".parse().unwrap(),
  );
  headers.insert("x-real-ip", "203.0.113.11".parse().unwrap());
  headers.insert("cf-connecting-ip", "203.0.113.12".parse().unwrap());
  headers.insert(
    "forwarded",
    "for=203.0.113.13, for=192.0.2.2".parse().unwrap(),
  );
  headers
}

fn resolve(config: &RealIpConfig, host: &str, sni: Option<&str>) -> SocketAddr {
  RealIpPolicySelector::new(config)
    .expect("compile policies")
    .resolve_client_addr(
      &headers(),
      "192.0.2.1:1234".parse().unwrap(),
      host,
      sni,
      config,
    )
    .unwrap()
}

#[test]
fn real_ip_rules_select_independent_headers_and_preserve_recursive_resolution() {
  let config = config(
    r#"
enabled = false
header = "forwarded"
trusted_proxies = ["198.51.100.0/24"]
[[rules]]
name = "xff"
hosts = ["xff.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
[[rules]]
name = "real"
hosts = ["real.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
header = "x-real-ip"
[[rules]]
name = "cdn"
hosts = ["cdn.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
header = "cf-connecting-ip"
[[rules]]
name = "forwarded"
hosts = ["forwarded.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
header = "forwarded"
"#,
  );
  for (host, expected) in [
    ("xff.test", "203.0.113.10:1234"),
    ("real.test", "203.0.113.11:1234"),
    ("cdn.test", "203.0.113.12:1234"),
    ("forwarded.test", "203.0.113.13:1234"),
    ("other.test", "192.0.2.1:1234"),
  ] {
    assert_eq!(
      resolve(&config, host, None),
      expected.parse().unwrap(),
      "{host}"
    );
  }
}

#[test]
fn real_ip_rules_are_ordered_and_disabled_match_stops_fallback() {
  let config = config(
    r#"
enabled = true
trusted_proxies = ["192.0.2.0/24"]
[[rules]]
name = "off"
hosts = ["*.tenant.test"]
[[rules]]
name = "exact"
hosts = ["api.tenant.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
header = "x-real-ip"
"#,
  );
  assert_eq!(
    resolve(&config, "api.tenant.test", None).ip(),
    "192.0.2.1".parse::<IpAddr>().unwrap()
  );
  assert_eq!(
    resolve(&config, "a.b.tenant.test", None).ip(),
    "192.0.2.1".parse::<IpAddr>().unwrap()
  );
  assert_eq!(
    resolve(&config, "tenant.test", None).ip(),
    "203.0.113.10".parse::<IpAddr>().unwrap()
  );
  assert_eq!(
    resolve(&config, "badtenant.test", None).ip(),
    "203.0.113.10".parse::<IpAddr>().unwrap()
  );
}

#[test]
fn real_ip_rules_require_both_received_names_but_any_name_in_each_list() {
  let config = config(
    r#"
[[rules]]
name = "pair"
hosts = ["api.test", "other.test"]
server_names = ["edge.test", "*.edge.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
header = "x-real-ip"
"#,
  );
  for (host, sni, expected) in [
    ("API.TEST:443", Some("EDGE.TEST."), "203.0.113.11:1234"),
    ("other.test.", Some("a.b.edge.test"), "203.0.113.11:1234"),
    ("api.test", None, "192.0.2.1:1234"),
    ("api.test", Some("other.test"), "192.0.2.1:1234"),
    ("absent.test", Some("edge.test"), "192.0.2.1:1234"),
    ("", Some("edge.test"), "192.0.2.1:1234"),
    ("api.test", Some("edge.test:443"), "192.0.2.1:1234"),
  ] {
    assert_eq!(
      resolve(&config, host, sni),
      expected.parse().unwrap(),
      "{host} {sni:?}"
    );
  }
}

#[test]
fn real_ip_rules_use_sni_only_and_exact_ip_hosts() {
  let config = config(
    r#"
[[rules]]
name = "ipv6"
hosts = ["[2001:db8::1]"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
header = "cf-connecting-ip"
[[rules]]
name = "sni"
server_names = ["edge.test"]
enabled = true
trusted_proxies = ["192.0.2.0/24"]
"#,
  );
  assert_eq!(
    resolve(&config, "[2001:0db8::1]:8443", None),
    "203.0.113.12:1234".parse().unwrap()
  );
  assert_eq!(
    resolve(&config, "any.test", Some("edge.test")),
    "203.0.113.10:1234".parse().unwrap()
  );
  assert_eq!(
    resolve(&config, "any.test", None),
    "192.0.2.1:1234".parse().unwrap()
  );
}

#[test]
fn real_ip_rules_do_not_fall_through_on_untrusted_metadata() {
  let config = config(
    r#"
enabled = true
trusted_proxies = ["192.0.2.0/24"]
[[rules]]
name = "restricted"
hosts = ["api.test"]
enabled = true
trusted_proxies = ["198.51.100.0/24"]
fail_on_untrusted_forwarded_headers = true
"#,
  );
  let result = RealIpPolicySelector::new(&config)
    .expect("compile policies")
    .resolve_client_addr(
      &headers(),
      "192.0.2.1:1234".parse().unwrap(),
      "api.test",
      None,
      &config,
    );
  assert!(result.is_err());
  assert_eq!(
    resolve(&config, "other.test", None),
    "203.0.113.10:1234".parse().unwrap()
  );
}

#[test]
fn real_ip_rules_without_rules_preserve_all_global_header_modes() {
  for header in [
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "forwarded",
  ] {
    for recursive in [true, false] {
      let config = config(&format!(
        "enabled = true\ntrusted_proxies = [\"192.0.2.0/24\"]\nheader = \"{header}\"\nrecursive = {recursive}"
      ));
      let peer = "192.0.2.1:1234".parse().unwrap();
      assert_eq!(
        resolve(&config, "api.test", Some("edge.test")),
        crate::identity::resolve_client_addr(&headers(), peer, &config).unwrap()
      );
    }
  }
}
