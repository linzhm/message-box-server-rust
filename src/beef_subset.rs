//! Offline structural parser for a deliberately narrow Atomic BEEF subset.
//!
//! BUMPs, V2 formats other than raw and txid-only, non-atomic BEEF, and unsafe
//! JavaScript-number amounts are unsupported. Structural parsing does not prove
//! subject membership, dependency closure, script validity, chain state, payment,
//! or authorization. Input size must be bounded by the caller.
use crate::{
    compact_size::decode_unsigned_compact_size,
    transaction_frame::{TransactionFrame, parse_transaction_prefix},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeefEntry {
    Raw(TransactionFrame),
    TxidOnly(String),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicBeefSubset {
    pub atomic_txid: String,
    pub version: u32,
    pub entries: Vec<BeefEntry>,
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
    fn compact(&mut self) -> Option<usize> {
        let (n, size) = decode_unsigned_compact_size(self.bytes.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(size)?;
        usize::try_from(n).ok()
    }
    fn txid(&mut self) -> Option<String> {
        let mut hash = self.take(32)?.to_vec();
        hash.reverse();
        Some(hex::encode(hash))
    }
    fn raw(&mut self) -> Option<(TransactionFrame, &'a [u8])> {
        let start = self.pos;
        let (frame, used) = parse_transaction_prefix(self.bytes.get(start..)?)?;
        self.pos = start.checked_add(used)?;
        Some((frame, self.bytes.get(start..self.pos)?))
    }
}
/// Parses only the documented no-BUMP Atomic BEEF subset, requiring exact
/// framing. An empty or unrelated transaction set can parse; callers must not
/// interpret the result as a valid Atomic BEEF proof or accepted payment.
pub fn parse_atomic_beef_subset(bytes: &[u8]) -> Option<AtomicBeefSubset> {
    parse_atomic_beef_with_raw(bytes).map(|(beef, _)| beef)
}

// Preserve borrowed raw slices internally for normalization without changing
// the public TransactionFrame representation or duplicating transaction bytes.
fn parse_atomic_beef_with_raw(bytes: &[u8]) -> Option<(AtomicBeefSubset, Vec<Option<&[u8]>>)> {
    let mut cursor = Cursor { bytes, pos: 0 };
    if cursor.take(4)? != [1, 1, 1, 1] {
        return None;
    }
    let atomic_txid = cursor.txid()?;
    let version = u32::from_le_bytes(cursor.take(4)?.try_into().ok()?);
    if version != 0xefbe_0001 && version != 0xefbe_0002 {
        return None;
    }
    if cursor.compact()? != 0 {
        return None;
    }
    let count = cursor.compact()?;
    let mut entries = Vec::new();
    let mut raw_slices = Vec::new();
    for _ in 0..count {
        if version == 0xefbe_0001 {
            let (tx, raw) = cursor.raw()?;
            if cursor.take(1)? != [0] {
                return None;
            }
            entries.push(BeefEntry::Raw(tx));
            raw_slices.push(Some(raw));
        } else {
            match cursor.take(1)?[0] {
                0 => {
                    let (tx, raw) = cursor.raw()?;
                    entries.push(BeefEntry::Raw(tx));
                    raw_slices.push(Some(raw));
                }
                2 => {
                    entries.push(BeefEntry::TxidOnly(cursor.txid()?));
                    raw_slices.push(None);
                }
                _ => return None,
            }
        }
    }
    if cursor.pos != bytes.len() {
        return None;
    }
    Some((
        AtomicBeefSubset {
            atomic_txid,
            version,
            entries,
        },
        raw_slices,
    ))
}

/// An unverified observation about the first output of the selected subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubjectOutput<'a> {
    pub txid: &'a str,
    pub satoshis: u64,
}

/// Inspect the first output of the last entry matching the Atomic subject ID.
/// Duplicate IDs follow the pinned SDK's last-entry index behavior. A matching
/// txid-only entry or raw transaction with no outputs returns `None`.
/// This observation does not normalize dependencies, validate scripts or chain
/// state, check a nonce, internalize funds, prevent replay, or authorize payment.
pub fn inspect_subject_output(beef: &AtomicBeefSubset) -> Option<SubjectOutput<'_>> {
    for entry in beef.entries.iter().rev() {
        match entry {
            BeefEntry::TxidOnly(txid) if txid == &beef.atomic_txid => return None,
            BeefEntry::Raw(tx) if tx.txid == beef.atomic_txid => {
                return Some(SubjectOutput {
                    txid: &tx.txid,
                    satoshis: tx.outputs.first()?.satoshis,
                });
            }
            _ => {}
        }
    }
    None
}

/// Normalize a narrow, no-BUMP, single-parent linear path to Atomic BEEF. The
/// path may end at a txid-only placeholder, which does not prove its ancestry.
/// This rejects duplicate IDs, missing referenced entries, branch graphs and a
/// txid-only subject, even when the SDK can normalize them. It does
/// not validate a BUMP, chain state, script, spendability or payment. Input size
/// must be bounded by the caller. `None` means malformed or unsupported, not
/// necessarily invalid under BRC-95 or the pinned SDK.
pub fn normalize_linear_atomic_beef(bytes: &[u8]) -> Option<Vec<u8>> {
    use std::collections::{HashMap, HashSet};
    let (beef, raw_slices) = parse_atomic_beef_with_raw(bytes)?;
    let mut index = HashMap::new();
    for (position, entry) in beef.entries.iter().enumerate() {
        let txid = match entry {
            BeefEntry::Raw(tx) => &tx.txid,
            BeefEntry::TxidOnly(id) => id,
        };
        if index.insert(txid.as_str(), position).is_some() {
            return None;
        }
    }
    let mut current = *index.get(beef.atomic_txid.as_str())?;
    if !matches!(beef.entries[current], BeefEntry::Raw(_)) {
        return None;
    }
    let mut path = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(current) {
            return None;
        }
        path.push(current);
        match &beef.entries[current] {
            BeefEntry::TxidOnly(_) => break,
            BeefEntry::Raw(tx) => {
                let mut deps = tx.input_txids.iter();
                let Some(first) = deps.next() else {
                    break;
                };
                if deps.any(|id| id != first) {
                    return None;
                }
                current = *index.get(first.as_str())?;
            }
        }
    }
    path.reverse();
    serialize_selected(&beef, &raw_slices, &path)
}

fn serialize_selected(
    beef: &AtomicBeefSubset,
    raw_slices: &[Option<&[u8]>],
    path: &[usize],
) -> Option<Vec<u8>> {
    let mut result = vec![1, 1, 1, 1];
    let mut subject = hex::decode(&beef.atomic_txid).ok()?;
    subject.reverse();
    result.extend_from_slice(&subject);
    result.extend_from_slice(&beef.version.to_le_bytes());
    result.push(0); // no BUMPs
    result.extend(crate::auth_frame::encode_compact_size(Some(
        u64::try_from(path.len()).ok()?,
    )));
    for &position in path {
        match &beef.entries[position] {
            BeefEntry::Raw(_) => {
                if beef.version == 0xefbe_0002 {
                    result.push(0);
                }
                result.extend_from_slice(raw_slices.get(position)?.as_ref()?);
                if beef.version == 0xefbe_0001 {
                    result.push(0);
                }
            }
            BeefEntry::TxidOnly(id) => {
                if beef.version != 0xefbe_0002 {
                    return None;
                }
                result.push(2);
                let mut hash = hex::decode(id).ok()?;
                hash.reverse();
                result.extend_from_slice(&hash);
            }
        }
    }
    Some(result)
}

/// Normalize the no-BUMP, unique-ID, acyclic dependency subset of Atomic BEEF.
/// Every subject-reachable referenced parent must be present; a txid-only parent
/// is a placeholder and does not establish its ancestry. A missing reference or
/// cycle in the selected graph, any duplicate ID, or a txid-only subject returns
/// `None`, even where the pinned SDK can serialize some of those inputs.
/// Unrelated entries are removed without checking their dependency graphs. This performs no script, chain, spendability,
/// wallet, replay or payment validation. The caller must bound input size.
pub fn normalize_acyclic_atomic_beef(bytes: &[u8]) -> Option<Vec<u8>> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let (beef, raw_slices) = parse_atomic_beef_with_raw(bytes)?;
    let mut index = HashMap::new();
    for (position, entry) in beef.entries.iter().enumerate() {
        let id = match entry {
            BeefEntry::Raw(tx) => &tx.txid,
            BeefEntry::TxidOnly(id) => id,
        };
        if index.insert(id.as_str(), position).is_some() {
            return None;
        }
    }
    let subject = *index.get(beef.atomic_txid.as_str())?;
    if !matches!(beef.entries[subject], BeefEntry::Raw(_)) {
        return None;
    }
    let mut selected = HashSet::new();
    let mut stack = vec![subject];
    while let Some(position) = stack.pop() {
        if !selected.insert(position) {
            continue;
        }
        if let BeefEntry::Raw(tx) = &beef.entries[position] {
            for id in &tx.input_txids {
                stack.push(*index.get(id.as_str())?);
            }
        }
    }
    let mut known = Vec::new();
    let mut raw = Vec::new();
    for (position, entry) in beef.entries.iter().enumerate() {
        if !selected.contains(&position) {
            continue;
        }
        match entry {
            BeefEntry::TxidOnly(_) => known.push(position),
            BeefEntry::Raw(_) => raw.push(position),
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
        let BeefEntry::Raw(tx) = &beef.entries[position] else {
            return None;
        };
        let mut distinct = HashSet::new();
        for id in &tx.input_txids {
            if !distinct.insert(id.as_str()) {
                continue;
            }
            let parent = *index.get(id.as_str())?;
            if matches!(beef.entries[parent], BeefEntry::Raw(_)) {
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
    known.extend(raw);
    serialize_selected(&beef, &raw_slices, &known)
}
