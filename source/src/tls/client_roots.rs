use anyhow::bail;
use rustls::RootCertStore;

use crate::config::UpstreamTlsTrust;

use super::certificate_io::load_certs;

pub(super) fn load_webpki_root_store() -> RootCertStore {
  let mut roots = RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  roots
}

pub(crate) fn load_upstream_root_store_with_trust(
  extra_root_certificates: &[std::path::PathBuf],
  trust: UpstreamTlsTrust,
) -> anyhow::Result<RootCertStore> {
  if trust == UpstreamTlsTrust::System && !extra_root_certificates.is_empty() {
    bail!("system upstream TLS trust must not include custom root certificates");
  }
  let mut roots = match trust {
    UpstreamTlsTrust::Inherit | UpstreamTlsTrust::System => load_webpki_root_store(),
    UpstreamTlsTrust::Exclusive => RootCertStore::empty(),
  };

  for path in extra_root_certificates {
    let certs = load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable upstream root certificates found in {}",
        path.display()
      );
    }
  }

  if roots.is_empty() {
    bail!("upstream TLS trust store must contain at least one certificate");
  }

  Ok(roots)
}
