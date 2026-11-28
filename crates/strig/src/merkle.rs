//! Merkle tree over audit records (feature `audit`), after RFC 6962 / RFC 9162 §2.1.
//!
//! The tree lets you hand an auditor one record, or a stretch of the trail, together with a proof
//! that it belongs to a tree whose root you published, without exposing the rest of the log. Every
//! function here is pure: no IO, no clock, no randomness. The byte-level rules are in
//! `docs/audit-format.md`.
//!
//! - A leaf hash is `SHA-256(0x00 || data)` and a node hash is `SHA-256(0x01 || left || right)`;
//!   the distinct prefixes keep a leaf from passing as a node.
//! - The tree of `n > 1` leaves splits at `k`, the largest power of two smaller than `n`.
//! - The root of an empty tree is `SHA-256("")`.
//! - The data of a record leaf is the canonical JSON of the record **as written**, `hash` included
//!   ([`record_leaf_data`]), so the leaf commits to the chain as well as to the content.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::audit::{AuditError, AuditRecord};

/// A SHA-256 digest.
pub type Hash = [u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Why a proof was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MerkleError {
    /// The index is not inside the tree.
    #[error("leaf index {index} is outside a tree of {size} leaves")]
    IndexOutOfRange { index: u64, size: u64 },
    /// The proof has more or fewer hashes than the tree shape needs.
    #[error("the proof has the wrong length")]
    ProofLength,
    /// The proof is well formed but leads to another root.
    #[error("the proof does not lead to the given root")]
    RootMismatch,
    /// The first tree is larger than the second, or empty where a proof is meaningless.
    #[error("invalid tree sizes: first {first}, second {second}")]
    Sizes { first: u64, second: u64 },
}

/// `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The bytes a record contributes as a leaf: its canonical JSON, with `hash`.
pub fn record_leaf_data(record: &AuditRecord) -> Result<Vec<u8>, AuditError> {
    Ok(serde_json::to_vec(record)?)
}

/// The leaf hash of a record.
pub fn record_leaf(record: &AuditRecord) -> Result<Hash, AuditError> {
    Ok(leaf_hash(&record_leaf_data(record)?))
}

/// Lowercase hex of a hash.
pub fn to_hex(hash: &Hash) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex characters into a hash; `None` for any other input.
pub fn from_hex(text: &str) -> Option<Hash> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks(2)) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        *slot = (high * 16 + low) as u8;
    }
    Some(out)
}

fn split(n: u64) -> u64 {
    debug_assert!(n > 1);
    1u64 << (63 - (n - 1).leading_zeros())
}

fn subtree_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n as u64) as usize;
            node_hash(&subtree_root(&leaves[..k]), &subtree_root(&leaves[k..]))
        }
    }
}

/// The Merkle tree hash of a list of leaf hashes.
pub fn root(leaves: &[Hash]) -> Hash {
    subtree_root(leaves)
}

/// The leaf hashes of a stretch of records, in order.
pub fn record_leaves(records: &[AuditRecord]) -> Result<Vec<Hash>, AuditError> {
    records.iter().map(record_leaf).collect()
}

fn path(index: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len() as u64) as usize;
    if index < k {
        path(index, &leaves[..k], out);
        out.push(subtree_root(&leaves[k..]));
    } else {
        path(index - k, &leaves[k..], out);
        out.push(subtree_root(&leaves[..k]));
    }
}

/// The audit path of leaf `index` (RFC 9162 §2.1.3.1): the sibling hashes from the leaf up to the
/// root. `None` when `index` is outside `leaves`.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    path(index, leaves, &mut out);
    Some(out)
}

/// Checks that `leaf` is the leaf `index` of a tree of `size` leaves with root `expected`
/// (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    expected: &Hash,
) -> Result<(), MerkleError> {
    if index >= size {
        return Err(MerkleError::IndexOutOfRange { index, size });
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut hash = *leaf;
    for sibling in proof {
        if snode == 0 {
            return Err(MerkleError::ProofLength);
        }
        if fnode & 1 == 1 || fnode == snode {
            hash = node_hash(sibling, &hash);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err(MerkleError::ProofLength);
    }
    if &hash == expected {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

fn subproof(first: usize, leaves: &[Hash], complete: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if first == n {
        if !complete {
            out.push(subtree_root(leaves));
        }
        return;
    }
    let k = split(n as u64) as usize;
    if first <= k {
        subproof(first, &leaves[..k], complete, out);
        out.push(subtree_root(&leaves[k..]));
    } else {
        subproof(first - k, &leaves[k..], false, out);
        out.push(subtree_root(&leaves[..k]));
    }
}

/// The consistency proof between the tree of the first `first` leaves and the tree of all of
/// `leaves` (RFC 9162 §2.1.4.1). `None` unless `0 < first <= leaves.len()`.
pub fn consistency_proof(leaves: &[Hash], first: usize) -> Option<Vec<Hash>> {
    if first == 0 || first > leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    subproof(first, leaves, true, &mut out);
    Some(out)
}

/// Checks that the tree of `second` leaves with root `second_root` extends the tree of `first`
/// leaves with root `first_root`: nothing before `first` was changed or removed (RFC 9162
/// §2.1.4.2).
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> Result<(), MerkleError> {
    if first == 0 || first > second {
        return Err(MerkleError::Sizes { first, second });
    }
    if first == second {
        return if proof.is_empty() && first_root == second_root {
            Ok(())
        } else if !proof.is_empty() {
            Err(MerkleError::ProofLength)
        } else {
            Err(MerkleError::RootMismatch)
        };
    }
    let mut steps: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        steps.push(*first_root);
    }
    steps.extend_from_slice(proof);
    let (mut fnode, mut snode) = (first - 1, second - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let mut iter = steps.iter();
    let Some(seed) = iter.next() else {
        return Err(MerkleError::ProofLength);
    };
    let (mut fr, mut sr) = (*seed, *seed);
    for step in iter {
        if snode == 0 {
            return Err(MerkleError::ProofLength);
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(step, &fr);
            sr = node_hash(step, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, step);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err(MerkleError::ProofLength);
    }
    if &fr == first_root && &sr == second_root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// A tree kept in memory, for building proofs over a stretch of the trail.
#[derive(Clone, PartialEq, Eq)]
pub struct MerkleTree {
    leaves: Vec<Hash>,
}

impl fmt::Debug for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleTree").field("size", &self.leaves.len()).finish()
    }
}

impl MerkleTree {
    /// A tree over the given leaf hashes.
    pub fn new(leaves: Vec<Hash>) -> Self {
        Self { leaves }
    }

    /// A tree over the records, in the order they were written.
    pub fn from_records(records: &[AuditRecord]) -> Result<Self, AuditError> {
        Ok(Self::new(record_leaves(records)?))
    }

    /// Number of leaves.
    pub fn size(&self) -> usize {
        self.leaves.len()
    }

    /// The root hash.
    pub fn root(&self) -> Hash {
        root(&self.leaves)
    }

    /// The root of the tree of the first `size` leaves, `None` when `size` exceeds the tree.
    pub fn root_at(&self, size: usize) -> Option<Hash> {
        self.leaves.get(..size).map(root)
    }

    /// The inclusion proof of leaf `index`.
    pub fn inclusion_proof(&self, index: usize) -> Option<Vec<Hash>> {
        inclusion_proof(&self.leaves, index)
    }

    /// The consistency proof from the tree of the first `first` leaves to this tree.
    pub fn consistency_proof(&self, first: usize) -> Option<Vec<Hash>> {
        consistency_proof(&self.leaves, first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAVES: [&str; 8] = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];

    fn decode(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn leaves(n: usize) -> Vec<Hash> {
        LEAVES[..n].iter().map(|l| leaf_hash(&decode(l))).collect()
    }

    #[test]
    fn empty_tree_root_is_the_hash_of_the_empty_string() {
        assert_eq!(
            to_hex(&root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rfc_6962_roots() {
        let expected = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (n, want) in expected.iter().enumerate() {
            assert_eq!(&to_hex(&root(&leaves(n + 1))), want, "root of {} leaves", n + 1);
        }
    }

    #[test]
    fn every_inclusion_proof_verifies_and_no_other_does() {
        for size in 1..=17usize {
            let all: Vec<Hash> = (0..size).map(|i| leaf_hash(&[i as u8])).collect();
            let tree = MerkleTree::new(all.clone());
            let top = tree.root();
            for index in 0..size {
                let proof = tree.inclusion_proof(index).unwrap();
                assert_eq!(
                    verify_inclusion(&all[index], index as u64, size as u64, &proof, &top),
                    Ok(())
                );
                let other = (index + 1) % size;
                if other != index {
                    assert!(verify_inclusion(&all[other], index as u64, size as u64, &proof, &top).is_err());
                }
                let mut short = proof.clone();
                if short.pop().is_some() {
                    assert!(verify_inclusion(&all[index], index as u64, size as u64, &short, &top).is_err());
                }
                let mut long = proof.clone();
                long.push([0; 32]);
                assert!(verify_inclusion(&all[index], index as u64, size as u64, &long, &top).is_err());
            }
            assert!(tree.inclusion_proof(size).is_none());
            assert_eq!(
                verify_inclusion(&all[0], size as u64, size as u64, &[], &top),
                Err(MerkleError::IndexOutOfRange {
                    index: size as u64,
                    size: size as u64
                })
            );
        }
    }

    #[test]
    fn every_consistency_proof_verifies_and_a_rewritten_past_does_not() {
        for second in 1..=17usize {
            let all: Vec<Hash> = (0..second).map(|i| leaf_hash(&[i as u8])).collect();
            let tree = MerkleTree::new(all.clone());
            let new_root = tree.root();
            for first in 1..=second {
                let old_root = tree.root_at(first).unwrap();
                let proof = tree.consistency_proof(first).unwrap();
                assert_eq!(
                    verify_consistency(first as u64, second as u64, &old_root, &new_root, &proof),
                    Ok(()),
                    "{first} -> {second}"
                );
                let mut forged = all.clone();
                forged[0] = leaf_hash(b"rewritten");
                let forged_old = root(&forged[..first]);
                assert!(
                    verify_consistency(first as u64, second as u64, &forged_old, &new_root, &proof).is_err(),
                    "{first} -> {second} with a rewritten past"
                );
            }
        }
    }

    const INCLUSION_5_OF_8: [&str; 3] = [
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    ];
    const CONSISTENCY_3_TO_8: [&str; 4] = [
        "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
        "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ];

    fn hashes(texts: &[&str]) -> Vec<Hash> {
        texts.iter().map(|t| from_hex(t).unwrap()).collect()
    }

    /// The vectors printed in `docs/audit-format.md`.
    #[test]
    fn the_documented_proof_vectors() {
        let tree = MerkleTree::new(leaves(8));
        assert_eq!(
            to_hex(&leaves(8)[5]),
            "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658"
        );
        assert_eq!(tree.inclusion_proof(5).unwrap(), hashes(&INCLUSION_5_OF_8));
        assert_eq!(tree.consistency_proof(3).unwrap(), hashes(&CONSISTENCY_3_TO_8));
        let (first, second) = (tree.root_at(3).unwrap(), tree.root());
        assert_eq!(
            to_hex(&first),
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"
        );
        assert_eq!(
            verify_consistency(3, 8, &first, &second, &hashes(&CONSISTENCY_3_TO_8)),
            Ok(())
        );
    }

    #[test]
    fn the_audit_vector_record_has_the_documented_leaf() {
        let line = format!(
            "{},\"hash\":\"087dbffda54667a64ae971f80c70bf6544b205be90c9ca9cc592ef113f4a4cb5\"}}",
            &crate::audit::tests::VECTOR_RECORD[..crate::audit::tests::VECTOR_RECORD.len() - 1]
        );
        let record: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(record_leaf_data(&record).unwrap(), line.as_bytes());
        assert_eq!(
            to_hex(&record_leaf(&record).unwrap()),
            "2ae4dc94737c2493a65e7d7329ed18b0a441951dbe14e3f3b5bef172a6a2e658"
        );
    }

    #[test]
    fn consistency_refuses_bad_sizes() {
        let zero = [0u8; 32];
        assert_eq!(
            verify_consistency(0, 3, &zero, &zero, &[]),
            Err(MerkleError::Sizes { first: 0, second: 3 })
        );
        assert_eq!(
            verify_consistency(4, 3, &zero, &zero, &[]),
            Err(MerkleError::Sizes { first: 4, second: 3 })
        );
        assert!(consistency_proof(&leaves(3), 0).is_none());
        assert!(consistency_proof(&leaves(3), 4).is_none());
    }

    #[test]
    fn hex_round_trips_and_refuses_garbage() {
        let hash = leaf_hash(b"x");
        assert_eq!(from_hex(&to_hex(&hash)), Some(hash));
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(&"g".repeat(64)), None);
    }
}
