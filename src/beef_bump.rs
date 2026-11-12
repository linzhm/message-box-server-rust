//! Offline Atomic BEEF structural inspection with restricted regular BUMPs.
//!
//! Parsing does not validate BUMP indexes, Atomic membership or dependency
//! closure, real block roots, scripts, spendability, wallet state, replay, or
//! payment. Many SDK-supported BUMPs and BEEF forms remain unsupported. The
//! caller must bound input size, and the HTTP adapter does not use this module.
use crate::{
    compact_size::decode_unsigned_compact_size,
    regular_bump::{RegularBump, inspect_regular_bump_prefix},
    transaction_frame::{TransactionFrame, parse_transaction_prefix},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BumpBeefEntry {
    Raw {
        transaction: TransactionFrame,
        bump_index: Option<u64>,
    },
    TxidOnly(String),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BumpBeef {
    pub atomic_txid: String,
    pub version: u32,
    pub bumps: Vec<RegularBump>,
    pub entries: Vec<BumpBeefEntry>,
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
        let (n, size) = decode_unsigned_compact_size(self.bytes.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(size)?;
        Some(n)
    }
    fn txid(&mut self) -> Option<String> {
        let mut hash = self.take(32)?.to_vec();
        hash.reverse();
        Some(hex::encode(hash))
    }
    fn raw(&mut self) -> Option<(TransactionFrame, &'a [u8])> {
        let start = self.pos;
        let (tx, used) = parse_transaction_prefix(self.bytes.get(start..)?)?;
        self.pos = start.checked_add(used)?;
        Some((tx, self.bytes.get(start..self.pos)?))
    }
    fn bump(&mut self) -> Option<(RegularBump, BumpMeta<'a>)> {
        let start = self.pos;
        let info = inspect_regular_bump_prefix(self.bytes.get(start..)?)?;
        self.pos = start.checked_add(info.consumed)?;
        Some((
            info.bump,
            BumpMeta {
                raw: self.bytes.get(start..self.pos)?,
                leaf_txids: info.leaf_txids,
                canonical_order: info.canonical_order,
            },
        ))
    }
}
/// Inspects exactly one Atomic BEEF V1/V2 with only the documented regular BUMP
/// subset. Invalid indexes and unrelated entries can remain in the result.
/// `None` also covers valid but unsupported forms; `Some` is not proof or payment.
pub fn parse_atomic_beef_with_regular_bumps(bytes: &[u8]) -> Option<BumpBeef> {
    parse_with_slices(bytes).map(|parsed| parsed.beef)
}
struct BumpMeta<'a> {
    raw: &'a [u8],
    leaf_txids: Vec<String>,
    canonical_order: bool,
}
struct Parsed<'a> {
    beef: BumpBeef,
    bump_meta: Vec<BumpMeta<'a>>,
    raw_slices: Vec<Option<&'a [u8]>>,
}
fn parse_with_slices(bytes: &[u8]) -> Option<Parsed<'_>> {
    let mut cursor = Cursor { bytes, pos: 0 };
    if cursor.take(4)? != [1, 1, 1, 1] {
        return None;
    }
    let atomic_txid = cursor.txid()?;
    let version = u32::from_le_bytes(cursor.take(4)?.try_into().ok()?);
    if version != 0xefbe_0001 && version != 0xefbe_0002 {
        return None;
    }
    let bump_count = cursor.compact()?;
    let mut bumps = Vec::new();
    let mut bump_meta = Vec::new();
    for _ in 0..bump_count {
        let (bump, meta) = cursor.bump()?;
        bumps.push(bump);
        bump_meta.push(meta);
    }
    let tx_count = cursor.compact()?;
    let mut entries = Vec::new();
    let mut raw_slices = Vec::new();
    for _ in 0..tx_count {
        if version == 0xefbe_0001 {
            let (transaction, raw) = cursor.raw()?;
            let flag = cursor.take(1)?[0];
            let bump_index = if flag == 0 {
                None
            } else {
                Some(cursor.compact()?)
            };
            entries.push(BumpBeefEntry::Raw {
                transaction,
                bump_index,
            });
            raw_slices.push(Some(raw));
        } else {
            match cursor.take(1)?[0] {
                0 => {
                    let (transaction, raw) = cursor.raw()?;
                    entries.push(BumpBeefEntry::Raw {
                        transaction,
                        bump_index: None,
                    });
                    raw_slices.push(Some(raw));
                }
                1 => {
                    let bump_index = Some(cursor.compact()?);
                    let (transaction, raw) = cursor.raw()?;
                    entries.push(BumpBeefEntry::Raw {
                        transaction,
                        bump_index,
                    });
                    raw_slices.push(Some(raw));
                }
                2 => {
                    entries.push(BumpBeefEntry::TxidOnly(cursor.txid()?));
                    raw_slices.push(None);
                }
                _ => return None,
            }
        }
    }
    if cursor.pos != bytes.len() {
        return None;
    }
    Some(Parsed {
        beef: BumpBeef {
            atomic_txid,
            version,
            bumps,
            entries,
        },
        bump_meta,
        raw_slices,
    })
}

/// Normalize a deliberately restricted Atomic BEEF graph with regular BUMPs.
/// Only unique transaction IDs and acyclic subject-reachable dependencies are
/// supported. Each selected BUMP reference must be in range, match a level-zero
/// transaction hash and use the subset's canonical leaf order; other SDK-valid
/// forms may return `None`. A matching BUMP or txid-only parent terminates the
/// dependency walk, without proving a real chain root or complete ancestry.
/// This function does not validate scripts, chain state, funds, wallet receipt,
/// replay or payment, and the caller must bound the input size.
pub fn normalize_regular_bump_atomic_beef(bytes: &[u8]) -> Option<Vec<u8>> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let parsed = parse_with_slices(bytes)?;
    let beef = &parsed.beef;
    let mut index = HashMap::new();
    for (position, entry) in beef.entries.iter().enumerate() {
        let id = match entry {
            BumpBeefEntry::Raw { transaction, .. } => &transaction.txid,
            BumpBeefEntry::TxidOnly(id) => id,
        };
        if index.insert(id.as_str(), position).is_some() {
            return None;
        }
    }
    let subject = *index.get(beef.atomic_txid.as_str())?;
    if !matches!(beef.entries[subject], BumpBeefEntry::Raw { .. }) {
        return None;
    }
    let mut selected = HashSet::new();
    let mut proof_by_position = vec![None; beef.entries.len()];
    let mut stack = vec![subject];
    while let Some(position) = stack.pop() {
        if !selected.insert(position) {
            continue;
        }
        if let BumpBeefEntry::Raw {
            transaction,
            bump_index,
        } = &beef.entries[position]
        {
            if let Some(bump_index) = bump_index {
                let bump_index = usize::try_from(*bump_index).ok()?;
                let meta = parsed.bump_meta.get(bump_index)?;
                if !meta.canonical_order
                    || !meta.leaf_txids.iter().any(|id| id == &transaction.txid)
                {
                    return None;
                }
                proof_by_position[position] = Some(bump_index);
            } else {
                for id in &transaction.input_txids {
                    stack.push(*index.get(id.as_str())?);
                }
            }
        }
    }
    let mut remapped = HashMap::new();
    let mut used_bumps = Vec::new();
    let mut known = Vec::new();
    let mut proofs = Vec::new();
    let mut raw = Vec::new();
    for (position, entry) in beef.entries.iter().enumerate() {
        if !selected.contains(&position) {
            continue;
        }
        match entry {
            BumpBeefEntry::TxidOnly(_) => known.push(position),
            BumpBeefEntry::Raw { .. } => {
                if let Some(old) = proof_by_position[position] {
                    if let std::collections::hash_map::Entry::Vacant(entry) = remapped.entry(old) {
                        entry.insert(used_bumps.len());
                        used_bumps.push(old);
                    }
                    proofs.push(position);
                } else {
                    raw.push(position);
                }
            }
        }
    }
    let mut rank = vec![usize::MAX; beef.entries.len()];
    for (order, &position) in raw.iter().enumerate() {
        rank[position] = order;
    }
    let mut indegree = vec![0usize; beef.entries.len()];
    let mut rounds = vec![0usize; beef.entries.len()];
    let mut dependents = vec![Vec::<usize>::new(); beef.entries.len()];
    for &position in &raw {
        let BumpBeefEntry::Raw { transaction, .. } = &beef.entries[position] else {
            return None;
        };
        let mut distinct = HashSet::new();
        for id in &transaction.input_txids {
            if !distinct.insert(id.as_str()) {
                continue;
            }
            let parent = *index.get(id.as_str())?;
            if matches!(beef.entries[parent], BumpBeefEntry::Raw { .. })
                && proof_by_position[parent].is_none()
            {
                indegree[position] = indegree[position].checked_add(1)?;
                dependents[parent].push(position);
            }
        }
    }
    let mut ready: VecDeque<usize> = raw.iter().copied().filter(|&p| indegree[p] == 0).collect();
    let mut processed = 0usize;
    while let Some(position) = ready.pop_front() {
        processed = processed.checked_add(1)?;
        for &child in &dependents[position] {
            let advance = usize::from(rank[position] > rank[child]);
            rounds[child] = rounds[child].max(rounds[position].checked_add(advance)?);
            indegree[child] = indegree[child].checked_sub(1)?;
            if indegree[child] == 0 {
                ready.push_back(child);
            }
        }
    }
    if processed != raw.len() {
        return None;
    }
    raw.sort_by_key(|&position| (rounds[position], rank[position]));
    known.extend(proofs);
    known.extend(raw);
    let mut result = vec![1, 1, 1, 1];
    let mut subject_bytes = hex::decode(&beef.atomic_txid).ok()?;
    subject_bytes.reverse();
    result.extend_from_slice(&subject_bytes);
    result.extend_from_slice(&beef.version.to_le_bytes());
    result.extend(crate::auth_frame::encode_compact_size(Some(
        u64::try_from(used_bumps.len()).ok()?,
    )));
    for &old in &used_bumps {
        result.extend_from_slice(parsed.bump_meta.get(old)?.raw);
    }
    result.extend(crate::auth_frame::encode_compact_size(Some(
        u64::try_from(known.len()).ok()?,
    )));
    for position in known {
        match &beef.entries[position] {
            BumpBeefEntry::TxidOnly(id) => {
                if beef.version != 0xefbe_0002 {
                    return None;
                }
                result.push(2);
                let mut hash = hex::decode(id).ok()?;
                hash.reverse();
                result.extend_from_slice(&hash);
            }
            BumpBeefEntry::Raw { .. } => {
                let proof = match proof_by_position[position] {
                    Some(old) => Some(*remapped.get(&old)?),
                    None => None,
                };
                if beef.version == 0xefbe_0002 {
                    if let Some(proof) = proof {
                        result.push(1);
                        result.extend(crate::auth_frame::encode_compact_size(Some(
                            u64::try_from(proof).ok()?,
                        )));
                    } else {
                        result.push(0);
                    }
                }
                result.extend_from_slice(parsed.raw_slices.get(position)?.as_ref()?);
                if beef.version == 0xefbe_0001 {
                    if let Some(proof) = proof {
                        result.push(1);
                        result.extend(crate::auth_frame::encode_compact_size(Some(
                            u64::try_from(proof).ok()?,
                        )));
                    } else {
                        result.push(0);
                    }
                }
            }
        }
    }
    Some(result)
}
