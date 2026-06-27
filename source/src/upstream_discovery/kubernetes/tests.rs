use super::*;
use crate::config::UpstreamDiscoveryProvider;

fn endpoint_slice_discovery() -> UpstreamPoolDiscoveryConfig {
  UpstreamPoolDiscoveryConfig {
    provider: UpstreamDiscoveryProvider::Kubernetes,
    name: None,
    endpoint: Some("https://kubernetes.default.svc".parse().expect("valid URL")),
    namespace: Some("default".to_string()),
    service: Some("app".to_string()),
    port_name: Some("http".to_string()),
    key_prefix: None,
    token_env: None,
    token_file: None,
    filter: None,
    datacenter: None,
    file: None,
    record_type: Default::default(),
    scheme: DiscoveryUpstreamScheme::Http,
    port: None,
    kubernetes_resource: KubernetesDiscoveryResource::EndpointSlice,
    watch: true,
    watch_timeout_seconds: 300,
    update_debounce_ms: 250,
    refresh_interval_ms: 30_000,
    min_ttl_ms: 1_000,
  }
}

#[test]
fn endpoint_slice_servers_require_ready_non_terminating_ip_endpoints() {
  let discovery = endpoint_slice_discovery();
  let slice: KubernetesEndpointSlice = serde_json::from_str(
    r#"{
      "metadata": {
        "name": "app-abc",
        "labels": {"kubernetes.io/service-name": "app"}
      },
      "addressType": "IPv4",
      "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
      "endpoints": [
        {"addresses": ["10.0.0.1"], "conditions": {"ready": true}},
        {"addresses": ["10.0.0.2"], "conditions": {"ready": false}},
        {"addresses": ["10.0.0.3"], "conditions": {"ready": true, "terminating": true}},
        {"addresses": ["10.0.0.4"]},
        {"addresses": ["pod.example"], "conditions": {"ready": true}}
      ]
    }"#,
  )
  .expect("slice should parse");

  let error = endpoint_slice_servers("default", "app", &discovery, &slice)
    .expect_err("FQDN address should be rejected");
  assert!(
    error.to_string().contains("discovered IP is invalid"),
    "unexpected error: {error}"
  );

  let mut slice = slice;
  slice.endpoints.truncate(4);
  let servers = endpoint_slice_servers("default", "app", &discovery, &slice)
    .expect("valid ready endpoints should convert");
  assert_eq!(servers.len(), 2);
  assert_eq!(servers[0].origin.as_str(), "http://10.0.0.1:8080/");
  assert_eq!(servers[1].origin.as_str(), "http://10.0.0.4:8080/");
}

#[test]
fn endpoint_slice_servers_support_ipv6_and_deduplication() {
  let mut discovery = endpoint_slice_discovery();
  discovery.port_name = None;
  discovery.port = Some(8443);
  discovery.scheme = DiscoveryUpstreamScheme::Https;
  let list: KubernetesEndpointSliceList = serde_json::from_str(
    r#"{
      "metadata": {"resourceVersion": "10"},
      "items": [
        {
          "metadata": {
            "name": "slice-a",
            "labels": {"kubernetes.io/service-name": "app"}
          },
          "addressType": "IPv6",
          "ports": [{"port": 8443}],
          "endpoints": [
            {"addresses": ["2001:db8::1", "2001:db8::1"], "conditions": {"ready": true}}
          ]
        }
      ]
    }"#,
  )
  .expect("slice list should parse");
  let cache = EndpointSliceCache::from_list(&discovery, list).expect("cache should build");
  let servers = cache.servers(&discovery).expect("servers should convert");

  assert_eq!(servers.len(), 1);
  assert_eq!(servers[0].origin.as_str(), "https://[2001:db8::1]:8443/");
}
