use anyhow::bail;
use rustls::RootCertStore;

pub(super) fn load_webpki_root_store() -> RootCertStore {
  let mut roots = RootCertStore::empty();
  roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
  roots
}

pub(crate) fn load_upstream_root_store(
  extra_root_certificates: &[std::path::PathBuf],
) -> anyhow::Result<RootCertStore> {
  let mut roots = load_webpki_root_store();

  for path in extra_root_certificates {
    let certs = super::load_certs(path)?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
      bail!(
        "no parsable upstream root certificates found in {}",
        path.display()
      );
    }
  }

  Ok(roots)
}
