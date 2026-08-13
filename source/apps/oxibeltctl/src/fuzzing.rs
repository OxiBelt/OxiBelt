use crate::config_migrate_transform::transform_document;
use crate::fingerprint::normalize_fingerprint_pins;
use crate::supply_chain_workload_policy::{
  AdmissionWorkloadPolicy, ContainerApproval, ContainerClass, MAX_AUXILIARY_CONTAINERS,
  canonicalize_workload_policy, validate_container_name, validate_image_reference,
  validate_workload_policy,
};

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_TOML_BYTES: usize = 16 * 1024;
const MAX_FINGERPRINTS: usize = 8;
const MAX_FINGERPRINT_BYTES: usize = 256;

/// Exercises bounded operator-tool canonicalizers without reading files, environment variables,
/// keyrings, or network resources.
pub fn exercise_config_policy_normalization(data: &[u8]) {
  let data = &data[..data.len().min(MAX_INPUT_BYTES)];
  let mut input = FuzzInput::new(data);

  exercise_config_migration(&mut input);
  exercise_workload_policy(&mut input);
  exercise_fingerprint_normalization(&mut input);
}

fn exercise_config_migration(input: &mut FuzzInput<'_>) {
  let raw = input.text(MAX_TOML_BYTES);
  let first = transform_document(&raw, "fuzz.toml");
  let second = transform_document(&raw, "fuzz.toml");
  if let (Ok((first_document, first_changes)), Ok((second_document, second_changes))) =
    (first, second)
  {
    assert_eq!(
      first_document, second_document,
      "config migration must be deterministic for identical input"
    );
    assert_eq!(
      first_changes, second_changes,
      "config migration diagnostics must be deterministic for identical input"
    );

    // The migration contract is explicitly one-way: a successful canonical document is a
    // fixed point. Invalid/conflicting documents are intentionally not asserted here.
    if let Ok((repeated_document, repeated_changes)) =
      transform_document(&first_document, "fuzz.toml")
    {
      assert_eq!(repeated_document, first_document);
      assert!(repeated_changes.is_empty());
    }
  }
}

fn exercise_workload_policy(input: &mut FuzzInput<'_>) {
  let count = input.usize(MAX_AUXILIARY_CONTAINERS.saturating_add(2));
  let mut entries = Vec::with_capacity(count);
  for index in 0..count {
    let name = if input.bool() {
      format!("fuzz-{}-{}", index, input.byte())
    } else {
      input.text(96)
    };
    let digest = input.byte();
    let image_reference = if input.bool() {
      format!(
        "ghcr.io/fuzz/example-{}@sha256:{}",
        index,
        format!("{digest:02x}").repeat(32)
      )
    } else {
      input.text(320)
    };
    let class = match input.byte() % 4 {
      0 => ContainerClass::Regular,
      1 => ContainerClass::Init,
      2 => ContainerClass::NativeSidecar,
      _ => ContainerClass::Ephemeral,
    };
    let approval = ContainerApproval {
      class,
      name,
      image_reference,
    };
    let _ = validate_container_name(&approval.name);
    let _ = validate_image_reference(&approval.image_reference);
    entries.push(approval);
  }

  let policy = AdmissionWorkloadPolicy {
    schema_version: if input.bool() { 1 } else { input.u16().into() },
    auxiliary_containers: entries,
  };
  let _ = validate_workload_policy(&policy);
  let Ok(canonical) = canonicalize_workload_policy(policy) else {
    return;
  };
  assert!(validate_workload_policy(&canonical).is_ok());
  let repeated = canonicalize_workload_policy(canonical.clone());
  assert_eq!(repeated.ok(), Some(canonical));
}

fn exercise_fingerprint_normalization(input: &mut FuzzInput<'_>) {
  let count = input.usize(MAX_FINGERPRINTS.saturating_add(1));
  let mut values = Vec::with_capacity(count);
  for _ in 0..count {
    values.push(input.text(MAX_FINGERPRINT_BYTES));
  }
  let _ = normalize_fingerprint_pins(&values);
}

struct FuzzInput<'a> {
  data: &'a [u8],
  offset: usize,
}

impl<'a> FuzzInput<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self { data, offset: 0 }
  }

  fn byte(&mut self) -> u8 {
    if self.data.is_empty() {
      return 0;
    }
    let byte = self.data[self.offset % self.data.len()];
    self.offset = self.offset.wrapping_add(1);
    byte
  }

  fn bool(&mut self) -> bool {
    self.byte() & 1 == 1
  }

  fn u16(&mut self) -> u16 {
    u16::from_be_bytes([self.byte(), self.byte()])
  }

  fn usize(&mut self, modulo: usize) -> usize {
    if modulo == 0 {
      0
    } else {
      (usize::from(self.u16()) ^ usize::from(self.byte())) % modulo
    }
  }

  fn text(&mut self, max: usize) -> String {
    const ALPHABET: &[u8] =
      b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .:/_-[]%?&=\n\r\t@";
    let length = self.usize(max.saturating_add(1));
    (0..length)
      .map(|_| char::from(ALPHABET[self.usize(ALPHABET.len())]))
      .collect()
  }
}
