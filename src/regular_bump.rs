//! Offline inspection of a restricted regular BUMP Merkle path.
//!
//! This does not prove that the computed root belongs to any real block or
//! validate a transaction, chain, wallet, replay state, or payment. Compound
//! paths, duplicate markers and other valid BUMP shapes are unsupported. The
//! caller must bound input size.
use crate::compact_size::decode_unsigned_compact_size;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegularBump {
    pub block_height: u64,
    pub leaf_txid: String,
    pub root: String,
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let value = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(value)
    }
    fn compact(&mut self) -> Option<u64> {
        let (value, size) = decode_unsigned_compact_size(self.bytes.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(size)?;
        Some(value)
    }
}
#[derive(Clone, Copy)]
struct Leaf {
    offset: u64,
    flagged: bool,
    hash: [u8; 32],
}
fn display_hash(mut hash: [u8; 32]) -> String {
    hash.reverse();
    hex::encode(hash)
}
fn pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    Sha256::digest(Sha256::digest(bytes)).into()
}

/// Parses exactly one BUMP containing either a single offset-zero flagged leaf,
/// or one flagged leaf and its explicit sibling at level zero plus exactly one
/// unflagged explicit sibling per higher level. It rejects all other forms,
/// including valid compound paths. Successful root calculation is not a proof
/// that the root belongs to the claimed block or that payment was made.
pub fn parse_regular_bump(bytes: &[u8]) -> Option<RegularBump> {
    let (bump, consumed) = parse_regular_bump_prefix(bytes)?;
    (consumed == bytes.len()).then_some(bump)
}

// Internal prefix variant allows a regular BUMP inside a framed BEEF object.
pub(crate) fn parse_regular_bump_prefix(bytes: &[u8]) -> Option<(RegularBump, usize)> {
    let inspected = inspect_regular_bump_prefix(bytes)?;
    Some((inspected.bump, inspected.consumed))
}

pub(crate) struct RegularBumpInspection {
    pub bump: RegularBump,
    pub leaf_txids: Vec<String>,
    pub canonical_order: bool,
    pub consumed: usize,
}

pub(crate) fn inspect_regular_bump_prefix(bytes: &[u8]) -> Option<RegularBumpInspection> {
    let mut cursor = Cursor { bytes, pos: 0 };
    let block_height = cursor.compact()?;
    let height = usize::from(*cursor.take(1)?.first()?);
    if !(1..=54).contains(&height) {
        return None;
    }
    let mut levels = Vec::new();
    for level in 0..height {
        let count = cursor.compact()?;
        if (level == 0 && !(1..=2).contains(&count)) || (level > 0 && count != 1) {
            return None;
        }
        let mut leaves = Vec::new();
        for _ in 0..count {
            let offset = cursor.compact()?;
            let flag = *cursor.take(1)?.first()?;
            if flag != 0 && flag != 2 {
                return None;
            }
            let hash: [u8; 32] = cursor.take(32)?.try_into().ok()?;
            leaves.push(Leaf {
                offset,
                flagged: flag == 2,
                hash,
            });
        }
        levels.push(leaves);
    }
    let first = levels.first()?;
    if first.len() == 1 {
        let leaf = first[0];
        if height != 1 || leaf.offset != 0 || !leaf.flagged {
            return None;
        }
        let id = display_hash(leaf.hash);
        return Some(RegularBumpInspection {
            bump: RegularBump {
                block_height,
                leaf_txid: id.clone(),
                root: id.clone(),
            },
            leaf_txids: vec![id],
            canonical_order: true,
            consumed: cursor.pos,
        });
    }
    let anchor = first.iter().find(|leaf| leaf.flagged)?;
    if first.iter().filter(|leaf| leaf.flagged).count() != 1 {
        return None;
    }
    let sibling = first.iter().find(|leaf| !leaf.flagged)?;
    if sibling.offset != (anchor.offset ^ 1) {
        return None;
    }
    let max_offset = anchor.offset.max(sibling.offset);
    if max_offset >= (1u64 << height) {
        return None;
    }
    let mut current = anchor.hash;
    for (level, leaves) in levels.iter().enumerate() {
        let offset = anchor.offset >> level;
        let other = if level == 0 {
            sibling
        } else {
            let leaf = leaves.first()?;
            if leaf.flagged || leaf.offset != (offset ^ 1) {
                return None;
            }
            leaf
        };
        current = if offset & 1 == 0 {
            pair(&current, &other.hash)
        } else {
            pair(&other.hash, &current)
        };
    }
    Some(RegularBumpInspection {
        bump: RegularBump {
            block_height,
            leaf_txid: display_hash(anchor.hash),
            root: display_hash(current),
        },
        leaf_txids: first.iter().map(|leaf| display_hash(leaf.hash)).collect(),
        canonical_order: first[0].offset < first[1].offset,
        consumed: cursor.pos,
    })
}
