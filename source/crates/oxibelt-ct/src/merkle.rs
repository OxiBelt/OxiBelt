//! RFC 6962 / RFC 9162 SHA-256 history-tree primitives.

use sha2::{Digest, Sha256};

use super::{CtError, Result};

pub const HASH_BYTES: usize = 32;
pub type Hash = [u8; HASH_BYTES];

pub fn empty_hash() -> Hash {
  Sha256::digest([]).into()
}

pub fn leaf_hash(leaf_input: &[u8]) -> Hash {
  let mut hash = Sha256::new();
  hash.update([0x00]);
  hash.update(leaf_input);
  hash.finalize().into()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
  let mut hash = Sha256::new();
  hash.update([0x01]);
  hash.update(left);
  hash.update(right);
  hash.finalize().into()
}

pub fn tree_hash(entries: &[impl AsRef<[u8]>]) -> Hash {
  let leaves: Vec<Hash> = entries
    .iter()
    .map(|entry| leaf_hash(entry.as_ref()))
    .collect();
  root_from_leaf_hashes(&leaves)
}

pub fn root_from_leaf_hashes(leaves: &[Hash]) -> Hash {
  match leaves.len() {
    0 => empty_hash(),
    1 => leaves[0],
    length => {
      let split = largest_power_of_two_less_than(length);
      node_hash(
        &root_from_leaf_hashes(&leaves[..split]),
        &root_from_leaf_hashes(&leaves[split..]),
      )
    }
  }
}

pub fn inclusion_proof(leaves: &[Hash], leaf_index: usize) -> Result<Vec<Hash>> {
  if leaves.is_empty() || leaf_index >= leaves.len() {
    return Err(CtError::new(
      "CT inclusion proof leaf index is outside the tree",
    ));
  }
  let mut proof = Vec::new();
  build_inclusion_proof(leaves, leaf_index, &mut proof);
  Ok(proof)
}

fn build_inclusion_proof(leaves: &[Hash], leaf_index: usize, proof: &mut Vec<Hash>) {
  if leaves.len() == 1 {
    return;
  }
  let split = largest_power_of_two_less_than(leaves.len());
  if leaf_index < split {
    build_inclusion_proof(&leaves[..split], leaf_index, proof);
    proof.push(root_from_leaf_hashes(&leaves[split..]));
  } else {
    build_inclusion_proof(&leaves[split..], leaf_index - split, proof);
    proof.push(root_from_leaf_hashes(&leaves[..split]));
  }
}

pub fn verify_inclusion(
  leaf: &Hash,
  leaf_index: usize,
  tree_size: usize,
  proof: &[Hash],
  expected_root: &Hash,
) -> bool {
  if tree_size == 0 || leaf_index >= tree_size {
    return false;
  }
  let mut proof_index = 0;
  let Some(root) = inclusion_root(leaf, leaf_index, tree_size, proof, &mut proof_index) else {
    return false;
  };
  proof_index == proof.len() && root == *expected_root
}

fn inclusion_root(
  leaf: &Hash,
  leaf_index: usize,
  tree_size: usize,
  proof: &[Hash],
  proof_index: &mut usize,
) -> Option<Hash> {
  if tree_size == 1 {
    return (leaf_index == 0).then_some(*leaf);
  }
  let split = largest_power_of_two_less_than(tree_size);
  if leaf_index < split {
    let left = inclusion_root(leaf, leaf_index, split, proof, proof_index)?;
    let right = *proof.get(*proof_index)?;
    *proof_index += 1;
    Some(node_hash(&left, &right))
  } else {
    let right = inclusion_root(
      leaf,
      leaf_index - split,
      tree_size - split,
      proof,
      proof_index,
    )?;
    let left = *proof.get(*proof_index)?;
    *proof_index += 1;
    Some(node_hash(&left, &right))
  }
}

pub fn consistency_proof(leaves: &[Hash], old_size: usize) -> Result<Vec<Hash>> {
  if old_size > leaves.len() {
    return Err(CtError::new(
      "CT consistency proof old tree is larger than new tree",
    ));
  }
  if old_size == 0 || old_size == leaves.len() {
    return Ok(Vec::new());
  }
  let mut proof = Vec::new();
  build_consistency_subproof(old_size, leaves, true, &mut proof);
  Ok(proof)
}

fn build_consistency_subproof(
  old_size: usize,
  leaves: &[Hash],
  complete: bool,
  proof: &mut Vec<Hash>,
) {
  if old_size == leaves.len() {
    if !complete {
      proof.push(root_from_leaf_hashes(leaves));
    }
    return;
  }
  let split = largest_power_of_two_less_than(leaves.len());
  if old_size <= split {
    build_consistency_subproof(old_size, &leaves[..split], complete, proof);
    proof.push(root_from_leaf_hashes(&leaves[split..]));
  } else {
    build_consistency_subproof(old_size - split, &leaves[split..], false, proof);
    proof.push(root_from_leaf_hashes(&leaves[..split]));
  }
}

/// Verifies an RFC 6962 consistency path using the algorithm from RFC 9162
/// Section 2.1.4.2.
pub fn verify_consistency(
  old_size: usize,
  new_size: usize,
  old_root: &Hash,
  new_root: &Hash,
  proof: &[Hash],
) -> bool {
  if old_size > new_size {
    return false;
  }
  if old_size == 0 {
    return proof.is_empty()
      && *old_root == empty_hash()
      && (new_size != 0 || *new_root == empty_hash());
  }
  if old_size == new_size {
    return proof.is_empty() && old_root == new_root;
  }

  let mut first = old_size - 1;
  let mut second = new_size - 1;
  while first & 1 == 1 {
    first >>= 1;
    second >>= 1;
  }

  let (mut first_hash, mut second_hash, mut proof_index) = if first == 0 {
    (*old_root, *old_root, 0)
  } else {
    let Some(seed) = proof.first().copied() else {
      return false;
    };
    (seed, seed, 1)
  };

  while let Some(node) = proof.get(proof_index) {
    if second == 0 {
      return false;
    }
    if first & 1 == 1 || first == second {
      first_hash = node_hash(node, &first_hash);
      second_hash = node_hash(node, &second_hash);
      while first != 0 && first & 1 == 0 {
        first >>= 1;
        second >>= 1;
      }
    } else {
      second_hash = node_hash(&second_hash, node);
    }
    first >>= 1;
    second >>= 1;
    proof_index += 1;
  }

  second == 0 && first_hash == *old_root && second_hash == *new_root
}

fn largest_power_of_two_less_than(value: usize) -> usize {
  debug_assert!(value > 1);
  1_usize << ((usize::BITS - 1 - (value - 1).leading_zeros()) as usize)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn leaves(count: usize) -> Vec<Hash> {
    (0..count)
      .map(|index| leaf_hash(&(index as u64).to_be_bytes()))
      .collect()
  }

  #[test]
  fn rfc6962_empty_and_domain_separated_hashes_are_stable() {
    assert_eq!(
      hex(&empty_hash()),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
      hex(&leaf_hash(&[])),
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
    let unprefixed: Hash = Sha256::digest(b"x").into();
    assert_ne!(leaf_hash(b"x"), unprefixed);
    assert_ne!(node_hash(&[0; 32], &[0; 32]), leaf_hash(&[0; 64]));
  }

  #[test]
  fn inclusion_proofs_cover_arbitrary_tree_shapes() {
    for tree_size in 1..=257 {
      let tree = leaves(tree_size);
      let root = root_from_leaf_hashes(&tree);
      for leaf_index in 0..tree_size {
        let proof = inclusion_proof(&tree, leaf_index).unwrap();
        assert!(verify_inclusion(
          &tree[leaf_index],
          leaf_index,
          tree_size,
          &proof,
          &root
        ));
        let mut malformed = proof.clone();
        malformed.push([0; 32]);
        assert!(!verify_inclusion(
          &tree[leaf_index],
          leaf_index,
          tree_size,
          &malformed,
          &root
        ));
        if let Some(first) = proof.first() {
          let mut corrupted = proof.clone();
          corrupted[0] = *first;
          corrupted[0][0] ^= 1;
          assert!(!verify_inclusion(
            &tree[leaf_index],
            leaf_index,
            tree_size,
            &corrupted,
            &root
          ));
        }
      }
    }
  }

  #[test]
  fn consistency_proofs_cover_every_prefix() {
    for new_size in 1..=257 {
      let tree = leaves(new_size);
      let new_root = root_from_leaf_hashes(&tree);
      for old_size in 0..=new_size {
        let old_root = root_from_leaf_hashes(&tree[..old_size]);
        let proof = consistency_proof(&tree, old_size).unwrap();
        assert!(
          verify_consistency(old_size, new_size, &old_root, &new_root, &proof),
          "old={old_size} new={new_size} proof={}",
          proof.len()
        );
        if old_size > 0 && old_size < new_size {
          let mut corrupted = proof.clone();
          corrupted[0][0] ^= 1;
          assert!(!verify_consistency(
            old_size, new_size, &old_root, &new_root, &corrupted,
          ));
        }
      }
    }
    assert!(!verify_consistency(
      0,
      0,
      &empty_hash(),
      &[0; HASH_BYTES],
      &[],
    ));
  }

  fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
      output.push(char::from(DIGITS[usize::from(byte >> 4)]));
      output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
  }
}
