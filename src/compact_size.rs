//! Offline unsigned CompactSize decoding for future BEEF parsing.
//!
//! This primitive alone does not parse or validate a transaction or payment.

/// Reads one canonical unsigned CompactSize value representable exactly by the
/// pinned SDK's JavaScript number reader, and returns the value and byte count.
/// Invalid, noncanonical, oversized and truncated values return `None`.
/// Trailing bytes are not consumed and are the enclosing parser's responsibility.
pub fn decode_unsigned_compact_size(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let (value, size, minimum) = match first {
        0..=252 => return Some((u64::from(first), 1)),
        253 => (
            u64::from(u16::from_le_bytes(input.get(1..3)?.try_into().ok()?)),
            3,
            253,
        ),
        254 => (
            u64::from(u32::from_le_bytes(input.get(1..5)?.try_into().ok()?)),
            5,
            65_536,
        ),
        255 => (
            u64::from_le_bytes(input.get(1..9)?.try_into().ok()?),
            9,
            4_294_967_296,
        ),
    };
    if value < minimum || value > 9_007_199_254_740_991 {
        return None;
    }
    Some((value, size))
}
