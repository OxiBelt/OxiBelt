use std::{collections::HashMap, sync::Arc};

use anyhow::{Context, ensure};
use tokio::sync::Semaphore;
use url::Url;

use crate::{
  cache::external_handler::ExternalCacheHttpClient,
  compression_dictionary::{
    codec::maximum_working_set_bytes,
    fields::{DictionaryType, UseAsDictionary},
    storage::DictionaryStorage,
  },
  config::{
    CompressionDictionaryConfig, CompressionDictionaryProfileConfig,
    CompressionDictionaryStoreConfig, CompressionDictionaryStoreKind, Config,
  },
  shared_state::SharedState,
};

use super::{
  Dictionary, DictionaryRuntime, ProfileRuntime, StoreRuntime, hash_bytes, ledger::LedgerEntry,
  validate_dictionary_metadata, validate_dictionary_parts,
};

pub(super) fn reuse_profile(
  previous: Option<&DictionaryRuntime>,
  config: &CompressionDictionaryProfileConfig,
  store: &Arc<StoreRuntime>,
) -> anyhow::Result<Option<Arc<ProfileRuntime>>> {
  let Some(profile) = previous.and_then(|runtime| runtime.profile(&config.name)) else {
    return Ok(None);
  };
  if Arc::ptr_eq(&profile.store, store) && profile.config == *config {
    return Ok(Some(profile));
  }
  let usage = profile
    .usage
    .lock()
    .map_err(|_| anyhow::anyhow!("dictionary profile usage poisoned"))?;
  let codec_capacity = profile.config.max_codec_concurrency.min(
    usize::try_from(profile.config.max_codec_memory_bytes / maximum_working_set_bytes())
      .unwrap_or(usize::MAX),
  );
  ensure!(
    profile.codec_permits.available_permits() == codec_capacity,
    "cannot replace dictionary profile while codec jobs are active"
  );
  ensure!(
    usage.jobs == 0,
    "cannot reload compression dictionary profile {} while learning jobs are active",
    config.name
  );
  Ok(None)
}

pub(super) fn build_storage(
  config: &Config,
  store: &CompressionDictionaryStoreConfig,
  shared: Option<Arc<SharedState>>,
) -> anyhow::Result<DictionaryStorage> {
  match store.kind {
    CompressionDictionaryStoreKind::Memory => Ok(DictionaryStorage::memory()),
    CompressionDictionaryStoreKind::Disk => DictionaryStorage::disk(
      &store
        .disk
        .as_ref()
        .context("dictionary disk configuration is absent")?
        .root,
    ),
    CompressionDictionaryStoreKind::Shared => Ok(DictionaryStorage::Shared {
      state: shared.context("shared dictionary storage requires SharedState")?,
      backend: store
        .shared
        .as_ref()
        .context("dictionary shared configuration is absent")?
        .backend
        .clone(),
    }),
    CompressionDictionaryStoreKind::External => {
      let name = &store
        .external
        .as_ref()
        .context("dictionary external configuration is absent")?
        .handler;
      let handler = config
        .cache
        .external_handlers
        .iter()
        .find(|value| value.name == *name)
        .context("dictionary external handler is absent")?;
      let client = ExternalCacheHttpClient::new(
        handler,
        &config.proxy.trusted_ca_certs,
        config.crypto.auxiliary_tls.enable_secp256r1mlkem768,
        config.proxy.buffering.max_memory_body_bytes,
        usize::try_from(store.quota_bytes)
          .context("dictionary external quota exceeds platform limit")?,
      )?;
      Ok(DictionaryStorage::External {
        client: Box::new(client),
        permits: Arc::new(Semaphore::new(handler.max_inflight_requests)),
      })
    }
  }
}

pub(super) fn load_configured_dictionaries(
  config: &CompressionDictionaryConfig,
) -> anyhow::Result<HashMap<String, Arc<Dictionary>>> {
  let mut values = HashMap::new();
  for dictionary in &config.dictionaries {
    let bytes = std::fs::read(&dictionary.path)
      .with_context(|| format!("read configured dictionary {}", dictionary.name))?;
    let hash = hash_bytes(&bytes)?;
    ensure!(
      hex_encode(hash.as_bytes()) == dictionary.sha256,
      "configured dictionary {} changed after configuration validation",
      dictionary.name
    );
    let declaration = UseAsDictionary {
      match_pattern: dictionary.url.path().to_owned(),
      match_destinations: Vec::new(),
      id: String::new(),
      dictionary_type: DictionaryType::Raw,
    };
    validate_dictionary_parts(&dictionary.url, &declaration, &bytes)?;
    values.insert(
      dictionary.name.clone(),
      Arc::new(Dictionary {
        name: Some(dictionary.name.clone()),
        public: dictionary.public,
        bytes: Arc::from(bytes),
        hash,
        url: dictionary.url.clone(),
        declaration,
      }),
    );
  }
  Ok(values)
}

pub(super) fn ledger_entry_dictionary(entry: &LedgerEntry) -> anyhow::Result<Dictionary> {
  let url = Url::parse(&entry.url).context("dictionary ledger URL is invalid")?;
  validate_dictionary_metadata(&url, &entry.declaration)?;
  Ok(Dictionary {
    name: None,
    public: false,
    bytes: Arc::from([]),
    hash: entry.hash,
    url,
    declaration: entry.declaration.clone(),
  })
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len().saturating_mul(2));
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}
