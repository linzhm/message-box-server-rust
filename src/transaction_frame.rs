//! Offline structural inspection of a standalone legacy transaction.
//!
//! This parser does not execute scripts, establish spendability, verify chain
//! proofs, parse BEEF, or validate or authorize payment. Input size must be
//! bounded by the caller before allocating or invoking it.
use crate::compact_size::decode_unsigned_compact_size;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionOutputFrame {
    pub satoshis: u64,
    pub script: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionFrame {
    /// Conventional display-order transaction ID, derived from the raw bytes.
    pub txid: String,
    /// Display-order source transaction IDs in input order.
    pub input_txids: Vec<String>,
    pub outputs: Vec<TransactionOutputFrame>,
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(count)?;
        let result = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(result)
    }
    fn compact(&mut self) -> Option<usize> {
        let (value, consumed) = decode_unsigned_compact_size(self.bytes.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(consumed)?;
        usize::try_from(value).ok()
    }
}

/// Parses exactly one raw transaction with canonical CompactSize fields and no
/// trailing bytes. Amounts above the SDK's safe-integer limit are rejected.
/// Script bytes are opaque, including syntactically invalid scripts.
pub fn parse_transaction_frame(bytes: &[u8]) -> Option<TransactionFrame> {
    let (frame, consumed) = parse_transaction_prefix(bytes)?;
    (consumed == bytes.len()).then_some(frame)
}

// A bounded prefix scanner for the offline BEEF subset; never exposes an
// incomplete prefix as a complete standalone transaction.
pub(crate) fn parse_transaction_prefix(bytes: &[u8]) -> Option<(TransactionFrame, usize)> {
    let mut cursor = Cursor { bytes, pos: 0 };
    cursor.take(4)?; // version
    let input_count = cursor.compact()?;
    let mut input_txids = Vec::new();
    for _ in 0..input_count {
        let mut source = cursor.take(32)?.to_vec();
        source.reverse();
        input_txids.push(hex::encode(source));
        cursor.take(4)?; // source index
        let script_len = cursor.compact()?;
        cursor.take(script_len)?;
        cursor.take(4)?; // sequence
    }
    let output_count = cursor.compact()?;
    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let satoshis = u64::from_le_bytes(cursor.take(8)?.try_into().ok()?);
        if satoshis > 9_007_199_254_740_991 {
            return None;
        }
        let script_len = cursor.compact()?;
        outputs.push(TransactionOutputFrame {
            satoshis,
            script: cursor.take(script_len)?.to_vec(),
        });
    }
    cursor.take(4)?; // locktime
    let mut hash = Sha256::digest(Sha256::digest(bytes.get(..cursor.pos)?)).to_vec();
    hash.reverse();
    Some((
        TransactionFrame {
            txid: hex::encode(hash),
            input_txids,
            outputs,
        },
        cursor.pos,
    ))
}
