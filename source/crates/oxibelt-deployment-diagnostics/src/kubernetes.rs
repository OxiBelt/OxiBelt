//! Fail-closed construction for the doctor's direct Kubernetes client.

use anyhow::{Context, bail};
use kube::{Client, Config};

use super::{KUBERNETES_CONNECT_TIMEOUT, KUBERNETES_READ_TIMEOUT};

/// A Kubernetes configuration that has passed the doctor's direct-transport
/// policy. Keeping the inner `Config` private ensures validation happens before
/// the first-party client can be constructed.
pub(super) struct DirectKubernetesConfig {
  config: Config,
}

impl TryFrom<Config> for DirectKubernetesConfig {
  type Error = anyhow::Error;

  fn try_from(mut config: Config) -> Result<Self, Self::Error> {
    if config.cluster_url.scheme_str() != Some("https") {
      bail!(
        "Kubernetes doctor requires an HTTPS API-server URL; cleartext and non-HTTPS schemes are not permitted"
      );
    }
    if config.proxy_url.is_some() {
      bail!(
        "Kubernetes doctor requires a direct API-server connection; proxy-url, HTTPS_PROXY, and https_proxy are not permitted"
      );
    }
    if config.accept_invalid_certs {
      bail!(
        "Kubernetes doctor requires verified API-server TLS; insecure-skip-tls-verify is not permitted"
      );
    }

    config.connect_timeout = Some(KUBERNETES_CONNECT_TIMEOUT);
    config.read_timeout = Some(KUBERNETES_READ_TIMEOUT);
    Ok(Self { config })
  }
}

impl DirectKubernetesConfig {
  pub(super) fn default_namespace(&self) -> &str {
    &self.config.default_namespace
  }

  pub(super) fn into_client(self) -> anyhow::Result<Client> {
    Client::try_from(self.config).context("failed to create direct read-only Kubernetes client")
  }
}

#[cfg(test)]
mod tests {
  use std::process::Command;

  use kube::config::{KubeConfigOptions, Kubeconfig};

  use super::*;

  fn direct_config() -> Config {
    Config::new(
      "https://kubernetes.example.test:6443"
        .parse()
        .expect("Kubernetes API URI"),
    )
  }

  #[test]
  fn rejects_cleartext_api_server_before_client_construction() {
    let config = Config::new(
      "http://kubernetes.example.test:8080"
        .parse()
        .expect("Kubernetes API URI"),
    );

    let error = DirectKubernetesConfig::try_from(config)
      .err()
      .expect("cleartext Kubernetes API transport must be rejected");
    assert!(
      error.to_string().contains("requires an HTTPS"),
      "unexpected error: {error:#}"
    );
  }

  #[test]
  fn rejects_any_loaded_proxy_before_client_construction() {
    for proxy in [
      "http://proxy.example.test:8080",
      "https://proxy.example.test:8443",
      "socks5://proxy.example.test:1080",
    ] {
      let mut config = direct_config();
      config.proxy_url = Some(proxy.parse().expect("proxy URI"));

      let error = DirectKubernetesConfig::try_from(config)
        .err()
        .expect("proxied Kubernetes configuration must be rejected");
      assert!(
        error.to_string().contains("requires a direct"),
        "unexpected error for {proxy}: {error:#}"
      );
    }
  }

  #[test]
  fn rejects_disabled_certificate_verification_before_client_construction() {
    let mut config = direct_config();
    config.accept_invalid_certs = true;

    let error = DirectKubernetesConfig::try_from(config)
      .err()
      .expect("insecure Kubernetes TLS must be rejected");
    assert!(
      error.to_string().contains("requires verified"),
      "unexpected error: {error:#}"
    );
  }

  #[tokio::test]
  async fn rejects_explicit_kubeconfig_proxy_and_insecure_tls_fields() {
    let proxied = serde_json::from_value::<Kubeconfig>(serde_json::json!({
      "clusters": [{
        "name": "cluster",
        "cluster": {
          "server": "https://kubernetes.example.test:6443",
          "proxy-url": "https://proxy.example.test:8443"
        }
      }],
      "contexts": [{
        "name": "context",
        "context": {"cluster": "cluster"}
      }],
      "current-context": "context"
    }))
    .expect("proxied Kubeconfig fixture");
    let proxied = Config::from_custom_kubeconfig(proxied, &KubeConfigOptions::default())
      .await
      .expect("proxied Kubernetes configuration");
    assert!(proxied.proxy_url.is_some());
    assert!(DirectKubernetesConfig::try_from(proxied).is_err());

    let insecure = serde_json::from_value::<Kubeconfig>(serde_json::json!({
      "clusters": [{
        "name": "cluster",
        "cluster": {
          "server": "https://kubernetes.example.test:6443",
          "insecure-skip-tls-verify": true
        }
      }],
      "contexts": [{
        "name": "context",
        "context": {"cluster": "cluster"}
      }],
      "current-context": "context"
    }))
    .expect("insecure Kubeconfig fixture");
    let mut insecure = Config::from_custom_kubeconfig(insecure, &KubeConfigOptions::default())
      .await
      .expect("insecure Kubernetes configuration");
    assert!(insecure.accept_invalid_certs);
    insecure.proxy_url = None;
    let error = DirectKubernetesConfig::try_from(insecure)
      .err()
      .expect("insecure kubeconfig TLS must be rejected");
    assert!(error.to_string().contains("requires verified"));
  }

  #[tokio::test]
  async fn rejects_cleartext_kubeconfig_api_server() {
    let cleartext = serde_json::from_value::<Kubeconfig>(serde_json::json!({
      "clusters": [{
        "name": "cluster",
        "cluster": {"server": "http://kubernetes.example.test:8080"}
      }],
      "contexts": [{
        "name": "context",
        "context": {"cluster": "cluster"}
      }],
      "current-context": "context"
    }))
    .expect("cleartext Kubeconfig fixture");
    let cleartext = Config::from_custom_kubeconfig(cleartext, &KubeConfigOptions::default())
      .await
      .expect("cleartext Kubernetes configuration");

    let error = DirectKubernetesConfig::try_from(cleartext)
      .err()
      .expect("cleartext kubeconfig API transport must be rejected");
    assert!(error.to_string().contains("requires an HTTPS"));
  }

  #[test]
  fn rejects_environment_derived_proxies() {
    let executable = std::env::current_exe().expect("current test executable");
    for variable in ["HTTPS_PROXY", "https_proxy"] {
      let status = Command::new(&executable)
        .arg("--exact")
        .arg("kubernetes::tests::environment_proxy_child")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env(variable, "https://proxy.example.test:8443")
        .env("OXIBELT_KUBERNETES_PROXY_ENV_CHILD", "1")
        .status()
        .expect("proxy environment child test");
      assert!(
        status.success(),
        "environment-derived proxy rejection failed for {variable}"
      );
    }
  }

  #[test]
  fn environment_proxy_child() {
    if std::env::var_os("OXIBELT_KUBERNETES_PROXY_ENV_CHILD").is_none() {
      return;
    }

    let kubeconfig = serde_json::from_value::<Kubeconfig>(serde_json::json!({
      "clusters": [{
        "name": "cluster",
        "cluster": {"server": "https://kubernetes.example.test:6443"}
      }],
      "contexts": [{
        "name": "context",
        "context": {"cluster": "cluster"}
      }],
      "current-context": "context"
    }))
    .expect("Kubeconfig fixture");
    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime");
    let config = runtime
      .block_on(Config::from_custom_kubeconfig(
        kubeconfig,
        &KubeConfigOptions::default(),
      ))
      .expect("environment-derived Kubernetes configuration");

    assert!(config.proxy_url.is_some());
    let error = DirectKubernetesConfig::try_from(config)
      .err()
      .expect("environment-derived proxy must be rejected");
    assert!(
      error.to_string().contains("requires a direct"),
      "unexpected error: {error:#}"
    );
  }

  #[test]
  fn preserves_direct_cluster_tls_identity_and_server_name() {
    let mut config = direct_config();
    config.default_namespace = "edge".to_owned();
    config.root_cert = Some(vec![vec![1, 2, 3]]);
    config.tls_server_name = Some("api.internal.example.test".to_owned());
    config.auth_info.token = Some("test-token".into());

    let direct = DirectKubernetesConfig::try_from(config)
      .expect("verified direct Kubernetes configuration must pass");

    assert_eq!(direct.default_namespace(), "edge");
    assert_eq!(direct.config.root_cert, Some(vec![vec![1, 2, 3]]));
    assert_eq!(
      direct.config.tls_server_name.as_deref(),
      Some("api.internal.example.test")
    );
    assert!(direct.config.auth_info.token.is_some());
    assert_eq!(
      direct.config.connect_timeout,
      Some(KUBERNETES_CONNECT_TIMEOUT)
    );
    assert_eq!(direct.config.read_timeout, Some(KUBERNETES_READ_TIMEOUT));
  }
}
